#pragma once

#include "../af_packet_io/io_context.hpp"
#include "../af_packet_io/ring_buffer.hpp"
#include "../nat/nat.h"
#include "../parsers/parser.h"
#include "../chain/header_chain.h"
#include <atomic>
#include <cstddef>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

struct WorkerPipelineConfig {
    af_packet_io::IoConfig io;
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
    struct FramePayload {
        std::vector<uint8_t> buffer;
        size_t net_offset = 0;
    };

    explicit Worker(const WorkerPipelineConfig& cfg);
    ~Worker();

    void start();
    void stop();
    void join();

  private:
    void run();
    void process_rx_block(tpacket_block_desc* block_desc);
    void handle_frame(uint8_t* data, size_t len, size_t net_offset);
    void enqueue_tx(std::vector<uint8_t>&& frame, size_t net_offset);
    void transmit_pending();
    void process_remote_frames();

    WorkerPipelineConfig cfg_;
    std::unique_ptr<af_packet_io::IoContext> io_;
    bool io_enabled_ = true;
    Nat nat_;
    std::thread thread_;
    std::atomic<bool> running_{false};

    std::function<void(uint32_t, FramePayload&&)> forward_fn_;

    using Chain = HeaderChainTuple<IPv4Header, TCPHeader, UDPHeader, ICMPHeader>;
    Chain chain_;

    struct TxFrame {
        std::vector<uint8_t> buffer;
        size_t net_offset = 0;
    };
    std::vector<TxFrame> tx_queue_;
    size_t tx_ring_index_ = 0;

    std::mutex remote_mutex_;
    std::deque<FramePayload> remote_queue_;

  public:
    void set_forward_callback(std::function<void(uint32_t, FramePayload&&)> fn) {
        forward_fn_ = std::move(fn);
    }

    void submit_remote_frame(FramePayload&& frame);
    void process_remote_frames_for_tests() { process_remote_frames(); }
    std::vector<std::vector<uint8_t>> collect_tx_frames();
    void process_frame_for_tests(std::vector<uint8_t>& frame, size_t net_offset = 0) {
        handle_frame(frame.data(), frame.size(), net_offset);
    }
    Nat& nat_for_tests() { return nat_; }
};
