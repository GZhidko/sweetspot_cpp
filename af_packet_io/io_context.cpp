#include "io_context.hpp"

#include <linux/if_packet.h>
#include <sys/socket.h>

namespace af_packet_io {

IoContext::IoContext(const IoConfig& cfg) : cfg_(cfg) {
    sock_.open(cfg.protocol);
    sock_.set_tpacket_version(TPACKET_V3);
    sock_.enable_qdisc_bypass(true);
    sock_.configure_ring(Direction::Rx, cfg.rx_ring);
    applied_rx_ = cfg.rx_ring;
    sock_.configure_ring(Direction::Tx, cfg.tx_ring);
    applied_tx_ = cfg.tx_ring;

    FanoutConfig fanout_cfg{cfg.fanout.group_id, cfg.fanout.mode, cfg.fanout.flags};
    sock_.configure_fanout(fanout_cfg);
    sock_.bind_interface(cfg.interface, cfg.protocol);
}

RingView IoContext::rx_ring() const noexcept {
    return RingView(sock_.mapped_area(Direction::Rx), sock_.mapped_length(Direction::Rx),
                    applied_rx_.frame_size);
}

RingView IoContext::tx_ring() const noexcept {
    return RingView(sock_.mapped_area(Direction::Tx), sock_.mapped_length(Direction::Tx),
                    applied_tx_.frame_size);
}

} // namespace af_packet_io

