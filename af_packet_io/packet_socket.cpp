#include "packet_socket.hpp"

#include "../common/logger.h"

#include <cerrno>
#include <cstring>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

namespace af_packet_io {

namespace {

int to_native_protocol(int protocol) {
    if (protocol == 0) {
        protocol = ETH_P_ALL;
    }
    return htons(protocol);
}

} // namespace

PacketSocket::PacketSocket() = default;

PacketSocket::PacketSocket(PacketSocket&& other) noexcept { *this = std::move(other); }

PacketSocket& PacketSocket::operator=(PacketSocket&& other) noexcept {
    if (this != &other) {
        close();
        fd_ = other.fd_;
        rx_map_ = other.rx_map_;
        rx_map_len_ = other.rx_map_len_;
        tx_map_ = other.tx_map_;
        tx_map_len_ = other.tx_map_len_;

        other.fd_ = -1;
        other.rx_map_ = nullptr;
        other.rx_map_len_ = 0;
        other.tx_map_ = nullptr;
        other.tx_map_len_ = 0;
    }
    return *this;
}

PacketSocket::~PacketSocket() { close(); }

void PacketSocket::open(int protocol) {
    if (is_open()) {
        throw std::runtime_error("PacketSocket already open");
    }

    fd_ = ::socket(AF_PACKET, SOCK_DGRAM, to_native_protocol(protocol));
    if (fd_ < 0) {
        throw make_sys_error("socket(AF_PACKET)");
    }
    int ignore_outgoing = 1;
#ifdef PACKET_IGNORE_OUTGOING
    if (::setsockopt(fd_, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore_outgoing,
                     sizeof(ignore_outgoing)) < 0) {
        LOG(DEBUG_ERROR, "PacketSocket fd=", fd_,
            " PACKET_IGNORE_OUTGOING failed errno=", errno);
    }
#endif
    LOG(DEBUG_IO, "PacketSocket opened fd=", fd_, " protocol=", protocol);
}

void PacketSocket::close() {
    if (fd_ >= 0) {
        munmap_ring(Direction::Rx);
        munmap_ring(Direction::Tx);
        LOG(DEBUG_IO, "PacketSocket closing fd=", fd_);
        ::close(fd_);
        fd_ = -1;
        ifindex_ = -1;
    }
}

void PacketSocket::ensure_open() const {
    if (!is_open()) {
        throw std::runtime_error("PacketSocket not open");
    }
}

void PacketSocket::set_tpacket_version(int version) {
    ensure_open();
    if (::setsockopt(fd_, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
        throw make_sys_error("setsockopt(PACKET_VERSION)");
    }
    LOG(DEBUG_IO, "PacketSocket fd=", fd_, " set TPACKET version=", version);
}

void PacketSocket::bind_interface(const std::string& ifname, uint16_t protocol) {
    ensure_open();
    unsigned ifindex = ::if_nametoindex(ifname.c_str());
    if (ifindex == 0) {
        throw make_sys_error("if_nametoindex(" + ifname + ")");
    }

    sockaddr_ll sll{};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = to_native_protocol(protocol ? protocol : ETH_P_ALL);
    sll.sll_ifindex = static_cast<int>(ifindex);
    sll.sll_pkttype = PACKET_HOST;
    sll.sll_hatype = 0;
    sll.sll_halen = 0;
    if (::bind(fd_, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) < 0) {
        throw make_sys_error("bind(AF_PACKET)");
    }
    ifindex_ = static_cast<int>(ifindex);
    LOG(DEBUG_IO, "PacketSocket fd=", fd_, " bind interface=", ifname, " ifindex=", ifindex,
        " protocol=", protocol);
}

void PacketSocket::enable_qdisc_bypass(bool enable) {
    ensure_open();
    int value = enable ? 1 : 0;
    if (::setsockopt(fd_, SOL_PACKET, PACKET_QDISC_BYPASS, &value, sizeof(value)) < 0) {
        throw make_sys_error("setsockopt(PACKET_QDISC_BYPASS)");
    }
    LOG(DEBUG_IO, "PacketSocket fd=", fd_, " qdisc_bypass=", enable);
}

void PacketSocket::configure_ring(Direction dir, const RingConfig& cfg) {
    ensure_open();
    if (cfg.block_size == 0 || cfg.block_count == 0 || cfg.frame_size == 0) {
        munmap_ring(dir);
        LOG(DEBUG_IO, "PacketSocket fd=", fd_, " configure_ring dir=",
            (dir == Direction::Rx ? "Rx" : "Tx"), " disabled");
        return;
    }

    if (dir != Direction::Rx) {
        munmap_ring(dir);
        LOG(DEBUG_IO, "PacketSocket fd=", fd_, " configure_ring unsupported dir -> noop");
        return;
    }

    munmap_ring(Direction::Rx);
    mmap_ring(Direction::Rx, cfg);
}

void PacketSocket::configure_fanout(const FanoutConfig& cfg) {
    ensure_open();
    uint32_t value = cfg.group_id | (static_cast<uint32_t>(cfg.mode) << 16) |
                     (static_cast<uint32_t>(cfg.flags) << 24);
    if (::setsockopt(fd_, SOL_PACKET, PACKET_FANOUT, &value, sizeof(value)) < 0) {
        throw make_sys_error("setsockopt(PACKET_FANOUT)");
    }
    LOG(DEBUG_IO, "PacketSocket fd=", fd_, " fanout group=", cfg.group_id,
        " mode=", cfg.mode, " flags=", cfg.flags);
}

void* PacketSocket::mapped_area(Direction dir) const noexcept {
    return dir == Direction::Rx ? rx_map_ : tx_map_;
}

size_t PacketSocket::mapped_length(Direction dir) const noexcept {
    return dir == Direction::Rx ? rx_map_len_ : tx_map_len_;
}

void PacketSocket::munmap_ring(Direction dir) {
    void*& map = (dir == Direction::Rx) ? rx_map_ : tx_map_;
    size_t& len = (dir == Direction::Rx) ? rx_map_len_ : tx_map_len_;
    if (map && len) {
        LOG(DEBUG_IO, "PacketSocket fd=", fd_, " munmap dir=",
            (dir == Direction::Rx ? "Rx" : "Tx"), " len=", len);
        ::munmap(map, len);
    }
    map = nullptr;
    len = 0;
}

void PacketSocket::mmap_ring(Direction dir, const RingConfig& cfg) {
    if (dir != Direction::Rx) {
        return;
    }

    constexpr off_t mmap_offset = 0;
    tpacket_req3 req{};
    req.tp_block_size = cfg.block_size;
    req.tp_block_nr = cfg.block_count;
    req.tp_frame_size = cfg.frame_size;
    req.tp_frame_nr = cfg.frame_count ? cfg.frame_count
                                      : (cfg.block_size / cfg.frame_size) * cfg.block_count;
    if (cfg.timeout_ns == 0) {
        req.tp_retire_blk_tov = 60U;
    } else {
        // tp_retire_blk_tov expects milliseconds; convert from nanoseconds with ceiling
        unsigned long long ms = (cfg.timeout_ns + 999999ULL) / 1000000ULL;
        if (ms == 0) {
            ms = 1;
        }
        req.tp_retire_blk_tov = static_cast<unsigned int>(ms);
    }
    req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    if (::setsockopt(fd_, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
        throw make_sys_error("setsockopt(PACKET_RX_RING)");
    }

    size_t map_length = static_cast<size_t>(req.tp_block_size) * req.tp_block_nr;
    void* area = ::mmap(nullptr, map_length, PROT_READ | PROT_WRITE,
                        MAP_SHARED, fd_, mmap_offset);
    if (area == MAP_FAILED) {
        throw make_sys_error("mmap(PACKET_RING)");
    }

    rx_map_ = area;
    rx_map_len_ = map_length;
    LOG(DEBUG_IO, "PacketSocket fd=", fd_, " RX ring configured block_size=", req.tp_block_size,
        " block_nr=", req.tp_block_nr, " frame_size=", req.tp_frame_size,
        " timeout_ms=", req.tp_retire_blk_tov);
}

std::system_error make_sys_error(const std::string& what) {
    return std::system_error(errno, std::generic_category(), what + ": " + std::strerror(errno));
}

} // namespace af_packet_io
