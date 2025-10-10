#pragma once

#include "../af_packet_io/io_context.hpp"
#include "../af_packet_io/ring_buffer.hpp"
#include "../nat/nat.h"
#include "../parsers/parser.h"
#include "../chain/header_chain.h"
#include "../filters/filter_engine.hpp"
#include <atomic>
#include <cstddef>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "../shape/shape_controller.hpp"
#include "dnat_table.hpp"

struct WorkerPipelineConfig {
    af_packet_io::IoConfig io_priv;
    af_packet_io::IoConfig io_pub;
    NatConfig nat;
    uint32_t thread_index = 0;
    uint32_t thread_count = 1;
    bool enable_io = true;
    std::vector<std::tuple<uint32_t, uint16_t, uint32_t, uint16_t>> static_tcp;
    std::vector<std::tuple<uint32_t, uint16_t, uint32_t, uint16_t>> static_udp;
    std::vector<std::tuple<uint32_t, uint16_t, uint32_t, uint16_t>> static_icmp;
    std::vector<std::pair<uint32_t, uint32_t>> static_ip;
};

class Worker {
  public:
    using Chain = HeaderChainTuple<IPv4Header, TCPHeader, UDPHeader, ICMPHeader>;

    struct FramePayload {
        enum class Origin { Private, Public } origin = Origin::Private;
        std::vector<uint8_t> buffer;
        size_t net_offset = 0;
        std::optional<Chain> parsed_chain;
    };

    struct TxFrame {
        std::vector<uint8_t> buffer;
        size_t net_offset = 0;
        const char* reason = "direct";
    };

    struct InterfaceContext {
        std::unique_ptr<af_packet_io::IoContext> io;
        std::vector<TxFrame> tx_queue;
        size_t tx_ring_index = 0;
        std::mutex tx_mutex;
    };

    enum class InterfaceKind { Private, Public };

    explicit Worker(const WorkerPipelineConfig& cfg);
    ~Worker();

    void start();
    void stop();
    void join();

    void enqueue_shaped_frame(InterfaceKind kind, std::vector<uint8_t>&& frame, size_t net_offset);

  private:
    void run();
    void process_interface(InterfaceContext& src_ctx, af_packet_io::RingView& view,
                           FramePayload::Origin origin);
    void process_rx_block(InterfaceContext& src_ctx, FramePayload::Origin origin,
                          tpacket_block_desc* block_desc);
    void handle_frame(FramePayload::Origin origin, uint8_t* data, size_t len, size_t net_offset);
    void handle_forwarded(FramePayload&& payload);
    void enqueue_tx(InterfaceContext& ctx, std::vector<uint8_t>&& frame, size_t net_offset,
                    const char* reason);
    void transmit_pending(InterfaceContext& ctx);
    void process_remote_frames();
    void process_chain(FramePayload::Origin origin, uint8_t* data, size_t len, size_t net_offset,
                       Chain& chain);
    bool apply_inbound_dnat(FramePayload::Origin origin, Chain& chain,
                            IPv4Header& ipv4, uint8_t* l3_data, size_t l3_len,
                            const filters::Decision& decision);
    bool apply_outbound_dnat(FramePayload::Origin origin, Chain& chain, IPv4Header& ipv4,
                             uint8_t* l3_data, size_t l3_len);
    void finish_frame(Chain& chain, const filters::Decision& decision,
                      FramePayload::Origin origin, uint8_t* data, size_t len, size_t net_offset,
                      uint32_t session_ip);

    WorkerPipelineConfig cfg_;
    InterfaceContext priv_ctx_;
    InterfaceContext pub_ctx_;
    bool io_enabled_ = true;
    Nat nat_;
    std::thread thread_;
    std::atomic<bool> running_{false};

    std::function<void(uint32_t, FramePayload&&)> forward_fn_;

    std::mutex remote_mutex_;
    std::deque<FramePayload> remote_queue_;

    std::unique_ptr<shape::ShapeController> shape_controller_;

  public:
    void set_forward_callback(std::function<void(uint32_t, FramePayload&&)> fn) {
        forward_fn_ = std::move(fn);
    }

    void submit_remote_frame(FramePayload&& frame);
    void process_remote_frames_for_tests() { process_remote_frames(); }
    std::vector<std::vector<uint8_t>> collect_tx_frames();
    void process_frame_for_tests(std::vector<uint8_t>& frame,
                                 FramePayload::Origin origin = FramePayload::Origin::Private,
                                 size_t net_offset = 0) {
        handle_frame(origin, frame.data(), frame.size(), net_offset);
    }
    Nat& nat_for_tests() { return nat_; }
};
