#include "io_context.hpp"

#include "../common/logger.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <unistd.h>

namespace af_packet_io {

IoContext::IoContext(const IoConfig& cfg) : cfg_(cfg) {
    LOG(DEBUG_IO, "IoContext init iface=", cfg.interface, " protocol=", cfg.protocol,
        " rx(blocks=", cfg.rx_ring.block_count, " size=", cfg.rx_ring.block_size,
        " frame=", cfg.rx_ring.frame_size, " timeout_ns=", cfg.rx_ring.timeout_ns,
        ") tx(blocks=", cfg.tx_ring.block_count, " size=", cfg.tx_ring.block_size,
        " frame=", cfg.tx_ring.frame_size, ")");
    sock_.open(cfg.protocol);
    sock_.set_tpacket_version(TPACKET_V3);
    sock_.configure_ring(Direction::Rx, cfg.rx_ring);
    applied_rx_ = cfg.rx_ring;
    applied_tx_ = {};

    sock_.bind_interface(cfg.interface, cfg.protocol);
    FanoutConfig fanout_cfg{cfg.fanout.group_id, cfg.fanout.mode, cfg.fanout.flags};
    sock_.configure_fanout(fanout_cfg);
    init_raw_ip_socket();
}

IoContext::~IoContext() {
    if (ip_tx_fd_ >= 0) {
        ::close(ip_tx_fd_);
        LOG(DEBUG_IO, "IoContext raw IP socket closed fd=", ip_tx_fd_);
        ip_tx_fd_ = -1;
    }
}

RingView IoContext::rx_ring() const noexcept {
    auto view = RingView(sock_.mapped_area(Direction::Rx), sock_.mapped_length(Direction::Rx),
                         applied_rx_.block_size, applied_rx_.block_count, applied_rx_.frame_size);
    LOG(DEBUG_IO, "IoContext rx_ring view valid=", view.valid(), " blocks=", view.block_count(),
        " block_size=", view.block_size(), " frame_size=", view.frame_size());
    return view;
}

RingView IoContext::tx_ring() const noexcept {
    auto view = RingView(sock_.mapped_area(Direction::Tx), sock_.mapped_length(Direction::Tx),
                         applied_tx_.block_size, applied_tx_.block_count, applied_tx_.frame_size);
    LOG(DEBUG_IO, "IoContext tx_ring view valid=", view.valid(), " blocks=", view.block_count(),
        " block_size=", view.block_size(), " frame_size=", view.frame_size());
    return view;
}

bool IoContext::send_frame(const uint8_t* data, size_t length, size_t net_offset,
                           const char* reason) {
    const char* tag = reason ? reason : "fallback";

    if (!data) {
        LOG(DEBUG_ERROR, "IoContext", ": TX drop (", tag, ") null data ptr");
        return false;
    }

    // === 1. Если длина позволяет прочитать Ethernet-заголовок, пробуем как Ethernet ===
    if (length >= sizeof(ethhdr)) {
        const auto* eth = reinterpret_cast<const ethhdr*>(data);
        uint16_t eth_proto = ntohs(eth->h_proto);

        // небольшой sanity-check: если тип знакомый, считаем, что это Ethernet frame
        if (eth_proto == ETH_P_IP || eth_proto == ETH_P_ARP || eth_proto == ETH_P_IPV6) {
            sockaddr_ll sa{};
            sa.sll_family   = AF_PACKET;
            sa.sll_protocol = htons(eth_proto);
            sa.sll_ifindex  = sock_.ifindex();
            sa.sll_halen    = ETH_ALEN;
            std::memcpy(sa.sll_addr, eth->h_dest, ETH_ALEN);

            ssize_t sent = ::sendto(sock_.fd(), data, length, 0,
                                    reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
            if (sent == static_cast<ssize_t>(length)) {
                LOG(DEBUG_IO, "IoContext", ": AF_PACKET send ok (", tag,
                    ") bytes=", length, " ifindex=", sock_.ifindex());
                return true;
            }
            int err = errno;
            if (err == EACCES) {
                LOG(DEBUG_IO, "IoContext", ": AF_PACKET send (", tag,
                    ") broadcast ignored length=", length, " errno=", err);
                return true;
            }
            LOG(DEBUG_ERROR, "IoContext", ": AF_PACKET send (", tag,
                ") error length=", length, " errno=", err);
            return false;
        }
        // Если EtherType не распознали, то будем пробовать как IP (fallthrough).
    }

    // === 2. Иначе трактуем как raw IPv4 пакет и отправляем через RAW сокет ===
    if (ip_tx_fd_ >= 0 && net_offset < length && (length - net_offset) >= sizeof(iphdr)) {
        const auto* iph = reinterpret_cast<const iphdr*>(data + net_offset);

        if (iph->version == 4 && iph->ihl >= 5) {
            uint16_t tot_len = ntohs(iph->tot_len);
            size_t ip_len = length - net_offset;

            if (tot_len >= iph->ihl * 4 && tot_len <= ip_len) {
                sockaddr_in dst{};
                dst.sin_family = AF_INET;
                dst.sin_addr.s_addr = 0;//iph->daddr;

                ssize_t sent = ::sendto(ip_tx_fd_, data + net_offset, tot_len, 0,
                                        reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
                if (sent == static_cast<ssize_t>(tot_len)) {
                    LOG(DEBUG_IO, "IoContext", ": RAW IP send ok (", tag,
                        ") bytes=", tot_len, " dst=", inet_ntoa(dst.sin_addr));
                    return true;
                }
                int err = errno;
                if (err == EACCES) {
                    LOG(DEBUG_IO, "IoContext", ": RAW IP send (", tag,
                        ") ignored length=", tot_len, " errno=", err);
                    return true;
                }
                LOG(DEBUG_ERROR, "IoContext", ": RAW IP send (", tag,
                    ") error length=", tot_len, " errno=", err);
            } else {
                LOG(DEBUG_ERROR, "IoContext", ": RAW IP bad tot_len=", tot_len,
                    " ip_len=", ip_len);
            }
        } else {
            LOG(DEBUG_ERROR, "IoContext", ": RAW IP invalid version/ihl ver=",
                (int)iph->version, " ihl=", (int)iph->ihl);
        }
    } else {
        LOG(DEBUG_ERROR, "IoContext", ": RAW IP no valid header, length=", length,
            " net_offset=", net_offset);
    }

    return false;
}

void IoContext::init_raw_ip_socket() {
    ip_tx_fd_ = ::socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (ip_tx_fd_ < 0) {
        LOG(DEBUG_ERROR, "IoContext", ": socket(AF_INET,SOCK_RAW) failed errno=", errno);
        return;
    }

    int hdrincl = 1;
    if (::setsockopt(ip_tx_fd_, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl)) < 0) {
        LOG(DEBUG_ERROR, "IoContext", ": setsockopt(IP_HDRINCL) failed errno=", errno);
        ::close(ip_tx_fd_);
        ip_tx_fd_ = -1;
        return;
    }

    if (!cfg_.interface.empty()) {
        struct ifreq ifr{};
        std::strncpy(ifr.ifr_name, cfg_.interface.c_str(), sizeof(ifr.ifr_name) - 1);
        if (::setsockopt(ip_tx_fd_, SOL_SOCKET, SO_BINDTODEVICE,
                         reinterpret_cast<void*>(&ifr), sizeof(ifr)) < 0) {
            LOG(DEBUG_ERROR, "IoContext", ": SO_BINDTODEVICE failed errno=", errno,
                " iface=", cfg_.interface);
        }
    }

    int sndbuf = 65536 * 8;
    ::setsockopt(ip_tx_fd_, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    LOG(DEBUG_IO, "IoContext", ": raw IP TX socket opened fd=", ip_tx_fd_);
}

} // namespace af_packet_io
