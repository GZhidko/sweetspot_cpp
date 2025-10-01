#pragma once

#include "packet_socket.hpp"
#include "ring_buffer.hpp"
#include <cstdint>
#include <memory>
#include <string>
#include <linux/if_ether.h> // For ETH_P_IP

namespace af_packet_io {

struct FanoutParams {
    uint16_t group_id;
    uint16_t mode;  // PACKET_FANOUT_HASH recommended
    uint16_t flags;
};

struct IoConfig {
    std::string rx_interface;
    std::string tx_interface;
    uint16_t protocol =  ETH_P_ALL;
    RingConfig rx_ring{};
    RingConfig tx_ring{};
    FanoutParams fanout{0, PACKET_FANOUT_HASH, 0};
};

class IoContext {
  public:
    explicit IoContext(const IoConfig& cfg);
    ~IoContext();

    PacketSocket& socket() noexcept { return sock_; }
    const PacketSocket& socket() const noexcept { return sock_; }

    RingView rx_ring() const noexcept;
    RingView tx_ring() const noexcept;

    bool send_frame(const uint8_t* data, size_t length, size_t net_offset,
                    const char* reason = nullptr);

  private:
    IoConfig cfg_;
    PacketSocket sock_;
    RingConfig applied_rx_{};
    RingConfig applied_tx_{};
    int ip_tx_fd_ = -1;

    void init_tx_socket();
};

} // namespace af_packet_io
