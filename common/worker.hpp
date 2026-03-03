#pragma once

#include "../af_packet_io/io_context.hpp"
#include "../af_packet_io/ring_buffer.hpp"
#include "../nat/nat.h"
#include "../parsers/parser.h"
#include "../chain/header_chain.h"
#include "../filters/filter_engine.hpp"
#include <atomic>
#include <chrono>
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
    bool forward_pool_enabled = false;
    bool profile_enabled = false;
    uint32_t profile_interval_ms = 2000;
    std::vector<std::tuple<uint32_t, uint16_t, uint32_t, uint16_t>> static_tcp;
    std::vector<std::tuple<uint32_t, uint16_t, uint32_t, uint16_t>> static_udp;
    std::vector<std::tuple<uint32_t, uint16_t, uint32_t, uint16_t>> static_icmp;
    std::vector<std::pair<uint32_t, uint32_t>> static_ip;
};

class Worker {
  public:
    using Chain = HeaderChainTuple<IPv4Header, TCPHeader, UDPHeader, ICMPHeader>;
    struct ForwardBlockHold;

    struct FramePayload {
        enum class Origin { Private, Public } origin = Origin::Private;
        std::vector<uint8_t> buffer;
        uint8_t* borrowed_data = nullptr;
        size_t borrowed_len = 0;
        size_t net_offset = 0;
        std::optional<Chain> parsed_chain;
        std::shared_ptr<ForwardBlockHold> block_hold;
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
        std::unique_ptr<std::atomic<uint8_t>[]> rx_block_inflight;
        size_t rx_block_inflight_count = 0;
    };

    struct ForwardBlockHold {
        tpacket_block_desc* block = nullptr;
        std::atomic<uint32_t> remaining{0};
        std::atomic<uint8_t>* inflight_flag = nullptr;
    };

    enum class InterfaceKind { Private, Public };

    explicit Worker(const WorkerPipelineConfig& cfg);
    ~Worker();

    void start();
    void stop();
    void join();

    void enqueue_shaped_frame(InterfaceKind kind, std::vector<uint8_t>&& frame, size_t net_offset);

  private:
    std::vector<uint8_t> acquire_forward_buffer(size_t len);
    void recycle_forward_buffer(std::vector<uint8_t>&& buffer);

    struct RemoteNode {
        FramePayload payload;
        RemoteNode* next = nullptr;
    };

    RemoteNode* acquire_remote_node();
    void recycle_remote_node(RemoteNode* node);
    RemoteNode* pop_all_remote_nodes();

    void run();
    void process_interface(InterfaceContext& src_ctx, af_packet_io::RingView& view,
                           FramePayload::Origin origin);
    bool process_rx_block(InterfaceContext& src_ctx, FramePayload::Origin origin,
                          tpacket_block_desc* block_desc, size_t block_index);
    bool handle_frame(FramePayload::Origin origin, uint8_t* data, size_t len, size_t net_offset,
                      const std::shared_ptr<ForwardBlockHold>& block_hold = nullptr);
    void handle_forwarded(FramePayload&& payload);
    void enqueue_tx(InterfaceContext& ctx, std::vector<uint8_t>&& frame, size_t net_offset,
                    const char* reason);
    void transmit_pending(InterfaceContext& ctx);
    void process_remote_frames();
    void maybe_dump_profile(bool force);
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
    bool forward_pool_enabled_ = false;
    bool profile_enabled_ = false;
    uint32_t profile_interval_ms_ = 2000;
    Nat nat_;
    std::thread thread_;
    std::atomic<bool> running_{false};

    std::function<void(uint32_t, FramePayload&&)> forward_fn_;

    std::atomic<RemoteNode*> remote_head_{nullptr};
    std::atomic<RemoteNode*> remote_free_{nullptr};
    std::atomic<uint32_t> remote_size_{0};
    int remote_event_fd_ = -1;
    std::mutex forward_pool_mutex_;
    std::deque<std::vector<uint8_t>> forward_pool_;

    std::chrono::steady_clock::time_point profile_started_at_{};
    std::chrono::steady_clock::time_point profile_last_dump_at_{};
    uint64_t profile_loops_ = 0;
    uint64_t profile_epoll_wait_calls_ = 0;
    uint64_t profile_epoll_ready_events_ = 0;
    uint64_t profile_epoll_timeouts_ = 0;
    uint64_t profile_rx_packets_ = 0;
    uint64_t profile_rx_bytes_ = 0;
    uint64_t profile_parse_calls_ = 0;
    uint64_t profile_parse_fail_ = 0;
    uint64_t profile_parse_ns_ = 0;
    uint64_t profile_chain_calls_ = 0;
    uint64_t profile_chain_ns_ = 0;
    uint64_t profile_forward_remote_ = 0;
    uint64_t profile_forward_local_ = 0;
    uint64_t profile_remote_batches_ = 0;
    uint64_t profile_remote_frames_ = 0;
    uint64_t profile_tx_frames_ = 0;
    uint64_t profile_tx_bytes_ = 0;
    uint64_t profile_tx_fallback_frames_ = 0;

    std::unique_ptr<shape::ShapeController> shape_controller_;
    DnatTable dnat_table_;

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
        (void)handle_frame(origin, frame.data(), frame.size(), net_offset);
    }
    Nat& nat_for_tests() { return nat_; }
};
