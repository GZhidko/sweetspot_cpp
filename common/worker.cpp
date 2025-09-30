#include "worker.hpp"

#include "../common/logger.h"
#include "../filters/filter.h"
#include "jenkins_hash.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <vector>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef TP_STATUS_OUTGOING
#define TP_STATUS_OUTGOING 0x20000000
#endif

Worker::Worker(const WorkerPipelineConfig& cfg)
    : cfg_(cfg), nat_(cfg.nat, cfg.thread_index, cfg.thread_count) {
    io_enabled_ = cfg.enable_io;
    if (io_enabled_) {
        io_ = std::make_unique<af_packet_io::IoContext>(cfg.io);
    }
    for (const auto& [priv_ip, priv_port, pub_ip, pub_port] : cfg_.static_tcp) {
        nat_.add_static_tcp_mapping(priv_ip, priv_port, pub_ip, pub_port);
    }
    for (const auto& [priv_ip, priv_port, pub_ip, pub_port] : cfg_.static_udp) {
        nat_.add_static_udp_mapping(priv_ip, priv_port, pub_ip, pub_port);
    }
    for (const auto& [priv_ip, priv_id, pub_ip, pub_id] : cfg_.static_icmp) {
        nat_.add_static_icmp_mapping(priv_ip, priv_id, pub_ip, pub_id);
    }
    for (const auto& [priv_ip, pub_ip] : cfg_.static_ip) {
        nat_.add_static_ip_mapping(priv_ip, pub_ip);
    }
    tx_queue_.reserve(1024);
}

Worker::~Worker() { stop(); }

void Worker::start() {
    if (running_.exchange(true)) {
        return;
    }
    thread_ = std::thread(&Worker::run, this);
}

void Worker::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    if (thread_.joinable()) {
        thread_.join();
    }
}

void Worker::join() {
    if (thread_.joinable()) {
        thread_.join();
    }
}

void Worker::run() {
    if (!io_) {
        while (running_) {
            process_remote_frames();
            transmit_pending();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return;
    }

    af_packet_io::RingView rx = io_->rx_ring();
    while (running_) {
        process_remote_frames();
        for (size_t i = 0; i < rx.block_count(); ++i) {
            auto* block = rx.block_at(i);
            if (!block) {
                continue;
            }
            if (block->hdr.bh1.block_status & TP_STATUS_USER) {
                process_rx_block(block);
                block->hdr.bh1.block_status = TP_STATUS_KERNEL;
            }
        }
        transmit_pending();
    }
}

void Worker::process_rx_block(tpacket_block_desc* block_desc) {
    auto* hdr = reinterpret_cast<tpacket3_hdr*>(reinterpret_cast<char*>(block_desc) + block_desc->hdr.bh1.offset_to_first_pkt);
    for (uint32_t i = 0; i < block_desc->hdr.bh1.num_pkts; ++i) {
        uint8_t* data = reinterpret_cast<uint8_t*>(hdr) + hdr->tp_mac;
        size_t len = hdr->tp_snaplen;
        size_t net_offset = 0;
        if (hdr->tp_net >= hdr->tp_mac && hdr->tp_net != 0) {
            net_offset = static_cast<size_t>(hdr->tp_net - hdr->tp_mac);
            if (net_offset > len) {
                net_offset = 0;
            }
        }
        handle_frame(data, len, net_offset);
        hdr = reinterpret_cast<tpacket3_hdr*>(reinterpret_cast<uint8_t*>(hdr) + hdr->tp_next_offset);
    }
}

void Worker::handle_frame(uint8_t* data, size_t len, size_t net_offset) {
    if (net_offset > len) {
        net_offset = 0;
    }
    uint8_t* l3_data = data + net_offset;
    size_t l3_len = len - net_offset;
    if (l3_len == 0) {
        return;
    }

    LOG(DEBUG_NAT, "Worker", cfg_.thread_index, ": received frame len=", len,
        " net_offset=", net_offset);

    if (!chain_.parse(l3_data, l3_len)) {
        LOG(DEBUG_NAT, "Worker", cfg_.thread_index, ": parse failed");
        return;
    }

    bool ok = true;
    chain_.for_each([&](auto& hdr) {
        if (!Filter<std::decay_t<decltype(hdr)>>{}(hdr)) {
            ok = false;
        }
    });
    if (!ok) {
        LOG(DEBUG_NAT, "Worker", cfg_.thread_index, ": filtered");
        return;
    }

    auto* ip = chain_.template get<IPv4Header>();
    if (!ip) {
        return;
    }

    LOG(DEBUG_NAT, "Worker", cfg_.thread_index,
        ": frame before NAT src=", IPv4Header::ip_to_string(ip->iph.saddr),
        " dst=", IPv4Header::ip_to_string(ip->iph.daddr),
        " proto=", static_cast<int>(ip->iph.protocol));

    uint32_t src_ip = ntohl(ip->iph.saddr);
    uint32_t dst_ip = ntohl(ip->iph.daddr);
    bool source_private = cfg_.nat.private_netset && cfg_.nat.private_netset->contains(src_ip);
    bool dest_public = cfg_.nat.public_netset && cfg_.nat.public_netset->contains(dst_ip);

    auto* tcp = chain_.template get<TCPHeader>();
    auto* udp = chain_.template get<UDPHeader>();
    auto* icmp = chain_.template get<ICMPHeader>();

    if (!source_private && dest_public && forward_fn_) {
        uint16_t src_port = 0;
        uint16_t dst_port = 0;
        uint8_t proto = ip->iph.protocol;
        if (tcp) {
            proto = IPPROTO_TCP;
            src_port = ntohs(tcp->tcph.source);
            dst_port = ntohs(tcp->tcph.dest);
        } else if (udp) {
            proto = IPPROTO_UDP;
            src_port = ntohs(udp->udph.source);
            dst_port = ntohs(udp->udph.dest);
        } else if (icmp) {
            proto = IPPROTO_ICMP;
            src_port = ntohs(icmp->icmph.un.echo.id);
            dst_port = ntohs(icmp->icmph.un.echo.id);
        }
        auto tuple = std::make_tuple(htonl(src_ip), htonl(dst_ip), htons(src_port), htons(dst_port),
                                     static_cast<uint8_t>(proto));
        uint32_t target = CPUFanoutHash::select_cpu(CPUFanoutHash::hash_tuple(tuple),
                                                    cfg_.thread_count);
        if (target != cfg_.thread_index) {
            FramePayload payload;
            payload.buffer.assign(data, data + len);
            payload.net_offset = net_offset;
            forward_fn_(target, std::move(payload));
            return;
        }
    }

    chain_.for_each([&](auto& hdr) { nat_.process(hdr); });

    LOG(DEBUG_NAT, "Worker", cfg_.thread_index,
        ": frame after NAT src=", IPv4Header::ip_to_string(ip->iph.saddr),
        " dst=", IPv4Header::ip_to_string(ip->iph.daddr));

    enqueue_tx(std::vector<uint8_t>(data, data + len), net_offset);
}

void Worker::enqueue_tx(std::vector<uint8_t>&& frame, size_t net_offset) {
    tx_queue_.push_back({});
    tx_queue_.back().buffer = std::move(frame);
    tx_queue_.back().net_offset = net_offset;
    LOG(DEBUG_NAT, "Worker", cfg_.thread_index, ": enqueue TX frame bytes=",
        tx_queue_.back().buffer.size(), " net_offset=", net_offset,
        " queue_size=", tx_queue_.size());
}

void Worker::transmit_pending() {
    if (tx_queue_.empty()) {
        return;
    }

    if (!io_) {
        tx_queue_.clear();
        return;
    }

    auto tx_view = io_->tx_ring();
    int fd = io_->socket().fd();

    auto send_frame = [&](const TxFrame& frame, const char* reason) {
        if (!io_->send_frame(frame.buffer.data(), frame.buffer.size(), frame.net_offset, reason)) {
            LOG(DEBUG_ERROR, "Worker", cfg_.thread_index,
                ": TX fallback failed reason=", reason,
                " frame_len=", frame.buffer.size());
        }
    };

    if (!tx_view.valid()) {
        LOG(DEBUG_NAT, "Worker", cfg_.thread_index,
            ": TX ring not mapped, using send() fallback for ", tx_queue_.size(), " frames");
        for (auto& frame : tx_queue_) {
            send_frame(frame, "no_tx_ring_mapping");
        }
        tx_queue_.clear();
        return;
    }

    size_t frame_count = tx_view.frame_count();
        if (frame_count == 0) {
            LOG(DEBUG_NAT, "Worker", cfg_.thread_index,
                ": TX ring unavailable, using send() fallback for ", tx_queue_.size(), " frames");
            for (auto& frame : tx_queue_) {
                send_frame(frame, "zero_frame_count");
            }
            tx_queue_.clear();
            return;
        }

    auto* base = static_cast<uint8_t*>(io_->socket().mapped_area(af_packet_io::Direction::Tx));
    size_t frame_size = tx_view.frame_size();
    constexpr size_t hdr_size = TPACKET_ALIGN(sizeof(tpacket3_hdr));

    for (auto& frame : tx_queue_) {
        bool written = false;
        for (size_t attempt = 0; attempt < frame_count; ++attempt) {
            size_t idx = tx_ring_index_ % frame_count;
            auto* hdr = reinterpret_cast<tpacket3_hdr*>(base + idx * frame_size);
            if ((hdr->tp_status & TP_STATUS_AVAILABLE) == TP_STATUS_AVAILABLE) {
                size_t copy_len = std::min(frame.buffer.size(), frame_size - hdr_size);
                std::memcpy(reinterpret_cast<uint8_t*>(hdr) + hdr_size, frame.buffer.data(), copy_len);
                hdr->tp_len = copy_len;
                hdr->tp_snaplen = copy_len;
                hdr->tp_status = TP_STATUS_SEND_REQUEST;
                tx_ring_index_ = idx + 1;
                written = true;
                LOG(DEBUG_NAT, "Worker", cfg_.thread_index,
                    ": TX via ring idx=", idx, " bytes=", copy_len);
                break;
            } else {
                ::sendto(fd, nullptr, 0, 0, nullptr, 0);
                tx_ring_index_ = idx + 1;
            }
        }
        if (!written) {
            send_frame(frame, "ring_full");
        }
    }
    ::sendto(fd, nullptr, 0, 0, nullptr, 0);
    LOG(DEBUG_NAT, "Worker", cfg_.thread_index, ": TX batch complete");
    tx_queue_.clear();
}

void Worker::process_remote_frames() {
    std::deque<FramePayload> local;
    {
        std::lock_guard<std::mutex> lock(remote_mutex_);
        local.swap(remote_queue_);
    }
    for (auto& frame : local) {
        LOG(DEBUG_NAT, "Worker", cfg_.thread_index,
            ": processing forwarded frame bytes=", frame.buffer.size(),
            " net_offset=", frame.net_offset);
        handle_frame(frame.buffer.data(), frame.buffer.size(), frame.net_offset);
    }
}

void Worker::submit_remote_frame(FramePayload&& frame) {
    std::lock_guard<std::mutex> lock(remote_mutex_);
    remote_queue_.emplace_back(std::move(frame));
}

std::vector<std::vector<uint8_t>> Worker::collect_tx_frames() {
    std::vector<std::vector<uint8_t>> out;
    out.reserve(tx_queue_.size());
    for (auto& frame : tx_queue_) {
        out.push_back(std::move(frame.buffer));
    }
    tx_queue_.clear();
    return out;
}
