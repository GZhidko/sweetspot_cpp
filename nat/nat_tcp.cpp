#include "nat.h"

#include "checksum.hpp"
#include "../include/tcp.h"
#include "../include/ipv4.h"

#include <arpa/inet.h>
#include <array>
#include <cstring>

namespace {

auto checksum_after_ip_change(uint16_t checksum_net, uint32_t old_ip, uint32_t new_ip) {
    return checksum::adjust_checksum32(checksum_net, old_ip, new_ip);
}

std::string to_string_host(uint32_t host_ip) {
    return IPv4Header::ip_to_string(htonl(host_ip));
}

struct TcpPseudoHeader {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t proto;
    uint16_t length;
};

static_assert(sizeof(TcpPseudoHeader) == 12, "Unexpected TCP pseudo header size");

std::array<uint8_t, sizeof(TcpPseudoHeader)> make_tcp_pseudo(uint32_t saddr_net,
                                                            uint32_t daddr_net,
                                                            uint16_t length_net) {
    TcpPseudoHeader pseudo{.saddr = saddr_net,
                           .daddr = daddr_net,
                           .zero = 0,
                           .proto = IPPROTO_TCP,
                           .length = length_net};
    std::array<uint8_t, sizeof(TcpPseudoHeader)> bytes{};
    std::memcpy(bytes.data(), &pseudo, sizeof(pseudo));
    return bytes;
}

} // namespace

void Nat::process(TCPHeader& tcp) {
    process(tcp, Clock::now());
}

void Nat::process(TCPHeader& tcp, Clock::time_point) {
    if (!ready_ || tcp.ip_header == nullptr) {
        return;
    }

    IPv4Header& ip = *tcp.ip_header;
    const uint32_t src_ip = ntohl(ip.iph.saddr);
    const uint32_t dst_ip = ntohl(ip.iph.daddr);
    const uint16_t src_port = ntohs(tcp.tcph.source);
    const uint16_t dst_port = ntohs(tcp.tcph.dest);
    const uint16_t total_len = ntohs(ip.iph.tot_len);
    const uint16_t header_len = static_cast<uint16_t>(ip.iph.ihl) * 4u;
    const uint16_t tcp_len = total_len > header_len ? static_cast<uint16_t>(total_len - header_len) : 0u;
    const uint16_t tcp_len_net = htons(tcp_len);

    const uint16_t old_check_net = tcp.tcph.check;
    const uint16_t old_src_port_net = tcp.tcph.source;
    const uint16_t old_dst_port_net = tcp.tcph.dest;
    const uint32_t old_src_ip_net = ip.iph.saddr;
    const uint32_t old_dst_ip_net = ip.iph.daddr;

    if (is_private(src_ip) && !is_private(dst_ip)) {
        LOG(DEBUG_NAT, "TCP outbound before NAT src=", to_string_host(src_ip), ":", src_port,
            " dst=", to_string_host(dst_ip), ":", dst_port);
        Translation tr = ensure_tcp_mapping(src_ip, dst_ip, src_port, dst_port);
        const uint32_t new_ip = tr.pub.pub_ip;
        const uint16_t new_port = tr.pub.pub_port;

        if (new_ip != src_ip) {
            LOG(DEBUG_NAT, "TCP outbound IP translate ", to_string_host(src_ip), " -> ",
                to_string_host(new_ip));
            ip.iph.saddr = htonl(new_ip);
            ip.iph.check = checksum_after_ip_change(ip.iph.check, src_ip, new_ip);
        }

        if (new_port != src_port) {
            tcp.tcph.source = htons(new_port);
            LOG(DEBUG_NAT, "TCP outbound port translate ", src_port, " -> ", new_port);
        }
    } else if (is_public(dst_ip)) {
        auto tr = find_tcp_reply(dst_ip, src_ip, dst_port, src_port);
        if (!tr) {
            return;
        }

        const uint32_t new_ip = tr->flow.prv_ip;
        const uint16_t new_port = tr->flow.src_port;
        const uint16_t old_dest_port = dst_port;

        LOG(DEBUG_NAT, "TCP inbound before NAT src=", to_string_host(src_ip), ":", src_port,
            " dst=", to_string_host(dst_ip), ":", dst_port);

        if (new_ip != dst_ip) {
            LOG(DEBUG_NAT, "TCP inbound IP translate ", to_string_host(dst_ip), " -> ",
                to_string_host(new_ip));
            ip.iph.daddr = htonl(new_ip);
            ip.iph.check = checksum_after_ip_change(ip.iph.check, dst_ip, new_ip);
        }

        if (new_port != old_dest_port) {
            tcp.tcph.dest = htons(new_port);
            LOG(DEBUG_NAT, "TCP inbound port translate ", old_dest_port, " -> ", new_port);
        }
    }

    if (old_check_net != 0 && tcp_len >= sizeof(tcphdr)) {
        uint16_t checksum_host = ntohs(old_check_net);
        uint16_t partial = 0;

        std::array<uint8_t, 2 * sizeof(uint16_t)> old_ports{};
        std::memcpy(old_ports.data(), &old_src_port_net, sizeof(uint16_t));
        std::memcpy(old_ports.data() + sizeof(uint16_t), &old_dst_port_net, sizeof(uint16_t));

        if (!checksum::checksum_block_decrement(partial, checksum_host, true,
                                                   old_ports.data(), old_ports.size())) {
            goto recompute_tcp_full;
        }
        checksum_host = partial;

        auto old_pseudo = make_tcp_pseudo(old_src_ip_net, old_dst_ip_net, tcp_len_net);
        if (!checksum::checksum_block_decrement(partial, checksum_host, false,
                                                   old_pseudo.data(), old_pseudo.size())) {
            goto recompute_tcp_full;
        }
        checksum_host = partial;

        auto new_pseudo = make_tcp_pseudo(ip.iph.saddr, ip.iph.daddr, tcp_len_net);
        if (!checksum::checksum_block_increment(checksum_host, checksum_host, false,
                                                   new_pseudo.data(), new_pseudo.size())) {
            goto recompute_tcp_full;
        }

        partial = checksum_host;
        std::array<uint8_t, 2 * sizeof(uint16_t)> new_ports{};
        std::memcpy(new_ports.data(), &tcp.tcph.source, sizeof(uint16_t));
        std::memcpy(new_ports.data() + sizeof(uint16_t), &tcp.tcph.dest, sizeof(uint16_t));
        if (!checksum::checksum_block_increment(checksum_host, partial, true,
                                                   new_ports.data(), new_ports.size())) {
            goto recompute_tcp_full;
        }

        tcp.tcph.check = htons(checksum_host);
        return;
    }

#ifdef NAT_FULL_CHECKSUM
recompute_tcp_full:
    if (tcp_len >= sizeof(tcphdr)) {
        tcp.tcph.check = 0;
        uint16_t full = checksum::l4_checksum(&ip.iph,
                                              reinterpret_cast<const uint8_t*>(&tcp.tcph),
                                              tcp_len,
                                              IPPROTO_TCP);
        tcp.tcph.check = htons(full);
    } else {
        tcp.tcph.check = 0;
    }
#else
recompute_tcp_full:
    tcp.tcph.check = 0;
#endif
}
