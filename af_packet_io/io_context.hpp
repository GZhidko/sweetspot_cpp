#pragma once

#include "packet_socket.hpp"
#include "ring_buffer.hpp"
#include <cstdint>
#include <memory>
#include <string>

namespace af_packet_io {

struct FanoutParams {
    uint16_t group_id;
    uint16_t mode;  // PACKET_FANOUT_HASH recommended
    uint16_t flags;
};

struct IoConfig {
    std::string interface;
    uint16_t protocol = 0; // ETH_P_ALL
    RingConfig rx_ring{};
    RingConfig tx_ring{};
    FanoutParams fanout{0, PACKET_FANOUT_HASH, 0};
};

class IoContext {
  public:
    explicit IoContext(const IoConfig& cfg);
    ~IoContext() = default;

    PacketSocket& socket() noexcept { return sock_; }
    const PacketSocket& socket() const noexcept { return sock_; }

    RingView rx_ring() const noexcept;
    RingView tx_ring() const noexcept;

  private:
    IoConfig cfg_;
    PacketSocket sock_;
    RingConfig applied_rx_{};
    RingConfig applied_tx_{};
};

} // namespace af_packet_io

