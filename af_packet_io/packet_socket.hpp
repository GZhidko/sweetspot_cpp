#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

namespace af_packet_io {

struct RingConfig {
    uint32_t block_size = 1 << 22;  // 4 MiB
    uint32_t block_count = 8;
    uint32_t frame_size = 2048;
    uint32_t frame_count = 0; // 0 -> auto (block_size / frame_size * block_count)
    uint32_t timeout_ns = 1000000; // 1ms
};

struct FanoutConfig {
    uint16_t group_id = 0;
    uint16_t mode = 0;   // PACKET_FANOUT_* value
    uint16_t flags = 0;  // PACKET_FANOUT_FLAG_*
};

enum class Direction {
    Rx,
    Tx
};

class PacketSocket {
  public:
    PacketSocket();
    PacketSocket(const PacketSocket&) = delete;
    PacketSocket& operator=(const PacketSocket&) = delete;
    PacketSocket(PacketSocket&& other) noexcept;
    PacketSocket& operator=(PacketSocket&& other) noexcept;
    ~PacketSocket();

    void open(int protocol = 0); // default ETH_P_ALL
    void close();
    bool is_open() const noexcept { return fd_ >= 0; }

    void set_tpacket_version(int version);
    void bind_interface(const std::string& ifname, uint16_t protocol = 0);
    void enable_qdisc_bypass(bool enable);

    void configure_ring(Direction dir, const RingConfig& cfg);
    void configure_fanout(const FanoutConfig& cfg);

    int fd() const noexcept { return fd_; }

    void* mapped_area(Direction dir) const noexcept;
    size_t mapped_length(Direction dir) const noexcept;

  private:
    void ensure_open() const;
    void mmap_ring(Direction dir, const RingConfig& cfg);
    void munmap_ring(Direction dir);

    int fd_ = -1;
    void* rx_map_ = nullptr;
    size_t rx_map_len_ = 0;
    void* tx_map_ = nullptr;
    size_t tx_map_len_ = 0;
};

std::system_error make_sys_error(const std::string& what);

} // namespace af_packet_io

