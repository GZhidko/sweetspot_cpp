#include "worker.hpp"

#include "../common/logger.h"
#include "../filters/filter.h"
#include "../committer/committer.h"
#include "checksum.hpp"
#include "jenkins_hash.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <optional>
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

#ifndef TP_STATUS_AVAILABLE
#define TP_STATUS_AVAILABLE 0
#endif

#ifndef TPACKET_ALIGN
#define TPACKET_ALIGN(x) (((x) + TPACKET_ALIGNMENT - 1) & ~(TPACKET_ALIGNMENT - 1))
#endif

Worker::Worker(const WorkerPipelineConfig& cfg)
    : cfg_(cfg), nat_(cfg.nat, cfg.thread_index, cfg.thread_count) {
    io_enabled_ = cfg.enable_io;
    if (io_enabled_) {
        if (!cfg.io_priv.rx_interface.empty()) {
            priv_ctx_.io = std::make_unique<af_packet_io::IoContext>(cfg.io_priv);
        }
        if (!cfg.io_pub.rx_interface.empty()) {
            pub_ctx_.io = std::make_unique<af_packet_io::IoContext>(cfg.io_pub);
        }
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
    af_packet_io::RingView priv_view;
    af_packet_io::RingView pub_view;
    if (priv_ctx_.io) {
        priv_view = priv_ctx_.io->rx_ring();
    }
    if (pub_ctx_.io) {
        pub_view = pub_ctx_.io->rx_ring();
    }

    while (running_) {
        process_remote_frames();
        if (priv_ctx_.io) {
            process_interface(priv_ctx_, priv_view, FramePayload::Origin::Private);
        }
        if (pub_ctx_.io) {
            process_interface(pub_ctx_, pub_view, FramePayload::Origin::Public);
        }
        transmit_pending(priv_ctx_);
        transmit_pending(pub_ctx_);
        if (!priv_ctx_.io && !pub_ctx_.io) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
}

void Worker::process_interface(InterfaceContext& src_ctx, af_packet_io::RingView& view,
                               FramePayload::Origin origin) {
    for (size_t i = 0; i < view.block_count(); ++i) {
        auto* block = view.block_at(i);
        if (!block) {
            continue;
        }
        if (block->hdr.bh1.block_status & TP_STATUS_USER) {
            process_rx_block(src_ctx, origin, block);
            block->hdr.bh1.block_status = TP_STATUS_KERNEL;
        }
    }
}

void Worker::process_rx_block(InterfaceContext& src_ctx, FramePayload::Origin origin,
                              tpacket_block_desc* block_desc) {
    auto* hdr = reinterpret_cast<tpacket3_hdr*>(reinterpret_cast<char*>(block_desc) +
                                                 block_desc->hdr.bh1.offset_to_first_pkt);
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
        handle_frame(origin, data, len, net_offset);
        hdr = reinterpret_cast<tpacket3_hdr*>(reinterpret_cast<uint8_t*>(hdr) +
                                              hdr->tp_next_offset);
    }
}

void Worker::handle_frame(FramePayload::Origin origin, uint8_t* data, size_t len,
                          size_t net_offset) {
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

    
    Chain chain_;
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

    if (forward_fn_) {
        uint32_t local_ip = source_private ? src_ip : dst_ip;
        uint32_t remote_ip = source_private ? dst_ip : src_ip;
        uint16_t local_port = 0;
        uint16_t remote_port = 0;
        uint8_t tuple_proto = ip->iph.protocol;

        if (tcp) {
            tuple_proto = IPPROTO_TCP;
            if (source_private) {
                local_port = ntohs(tcp->tcph.source);
                remote_port = ntohs(tcp->tcph.dest);
            } else {
                local_port = ntohs(tcp->tcph.dest);
                remote_port = ntohs(tcp->tcph.source);
            }
        } else if (udp) {
            tuple_proto = IPPROTO_UDP;
            if (source_private) {
                local_port = ntohs(udp->udph.source);
                remote_port = ntohs(udp->udph.dest);
            } else {
                local_port = ntohs(udp->udph.dest);
                remote_port = ntohs(udp->udph.source);
            }
        } else if (icmp) {
            tuple_proto = IPPROTO_ICMP;
            uint16_t id = ntohs(icmp->icmph.un.echo.id);
            uint16_t seq = ntohs(icmp->icmph.un.echo.sequence);
            local_port = id;
            remote_port = seq;
        }

        bool should_forward = false;

        if (!source_private && dest_public) {
            should_forward = true;
        } else if (source_private) {
            std::optional<Nat::Translation> static_outbound;
            if (tcp) {
                static_outbound = nat_.find_static_outbound(src_ip, dst_ip, local_port,
                                                            remote_port, IPPROTO_TCP);
            } else if (udp) {
                static_outbound = nat_.find_static_outbound(src_ip, dst_ip, local_port,
                                                            remote_port, IPPROTO_UDP);
            } else if (icmp) {
                static_outbound = nat_.find_static_outbound(src_ip, dst_ip, local_port,
                                                            remote_port, IPPROTO_ICMP);
            } else {
                static_outbound = nat_.find_static_outbound(src_ip, dst_ip, 0, 0, tuple_proto);
            }

            if (static_outbound.has_value()) {
                should_forward = true;
                local_ip = static_outbound->pub.pub_ip;
                local_port = static_outbound->pub.pub_port;
            }
        }

        if (should_forward) {
            auto tuple = std::make_tuple(htonl(local_ip), htonl(remote_ip), htons(local_port),
                                         htons(remote_port), static_cast<uint8_t>(tuple_proto));
            uint32_t target = CPUFanoutHash::select_cpu(CPUFanoutHash::hash_tuple(tuple),
                                                        cfg_.thread_count);
            if (target != cfg_.thread_index) {
                FramePayload payload;
                payload.origin = origin;
                payload.buffer.assign(data, data + len);
                payload.net_offset = net_offset;
                forward_fn_(target, std::move(payload));
                return;
            }
        }
    }

    chain_.for_each([&](auto& hdr) { nat_.process(hdr); });

    size_t offset = 0;
    auto* ipv4 = chain_.template get<IPv4Header>();
    if (!ipv4 || !Committer<IPv4Header>{}(ipv4, l3_data, l3_len, offset)) {
        return;
    }

    chain_.for_each([&](auto& hdr) {
        using Header = std::decay_t<decltype(hdr)>;
        if constexpr (!std::is_same_v<Header, IPv4Header>) {
            Committer<Header>{}(&hdr, l3_data, l3_len, offset, ipv4);
        }
    });

    LOG(DEBUG_NAT, "Worker", cfg_.thread_index,
        ": frame after NAT src=", IPv4Header::ip_to_string(ip->iph.saddr),
        " dst=", IPv4Header::ip_to_string(ip->iph.daddr));

    uint16_t log_src_port = 0;
    uint16_t log_dst_port = 0;
    uint16_t log_icmp_id = 0;

    switch (ip->iph.protocol) {
    case IPPROTO_TCP: {
        if (auto* tcp_hdr = chain_.template get<TCPHeader>()) {
            log_src_port = ntohs(tcp_hdr->tcph.source);
            log_dst_port = ntohs(tcp_hdr->tcph.dest);
        }
        break;
    }
    case IPPROTO_UDP: {
        if (auto* udp_hdr = chain_.template get<UDPHeader>()) {
            log_src_port = ntohs(udp_hdr->udph.source);
            log_dst_port = ntohs(udp_hdr->udph.dest);
        }
        break;
    }
    case IPPROTO_ICMP: {
        if (auto* icmp_hdr = chain_.template get<ICMPHeader>()) {
            log_icmp_id = ntohs(icmp_hdr->icmph.un.echo.id);
        }
        break;
    }
    default:
        break;
    }

    InterfaceContext* dest_ctx = (origin == FramePayload::Origin::Private) ? &pub_ctx_ : &priv_ctx_;
    if (!dest_ctx->io) {
        LOG(DEBUG_IO, "Worker", cfg_.thread_index,
            ": destination interface missing, queuing only origin=",
            origin == FramePayload::Origin::Private ? "private" : "public");
    }

    LOG(DEBUG_NAT, "Worker", cfg_.thread_index,
        ": TX schedule proto=", static_cast<int>(ipv4->iph.protocol),
        " src=", IPv4Header::ip_to_string(ipv4->iph.saddr), ":", log_src_port,
        " dst=", IPv4Header::ip_to_string(ipv4->iph.daddr), ":", log_dst_port,
        " icmp_id=", log_icmp_id,
        " via=", (dest_ctx == &pub_ctx_ ? "pub" : "priv"));

    enqueue_tx(*dest_ctx, std::vector<uint8_t>(data, data + len), net_offset, "direct");
}

void Worker::enqueue_tx(InterfaceContext& ctx, std::vector<uint8_t>&& frame, size_t net_offset,
                        const char* reason) {
    ctx.tx_queue.push_back({});
    ctx.tx_queue.back().buffer = std::move(frame);
    ctx.tx_queue.back().net_offset = net_offset;
    ctx.tx_queue.back().reason = reason;
    LOG(DEBUG_NAT, "Worker", cfg_.thread_index, ": enqueue TX frame bytes=",
        ctx.tx_queue.back().buffer.size(), " net_offset=", net_offset,
        " reason=", reason, " queue_size=", ctx.tx_queue.size());
}

void Worker::transmit_pending(InterfaceContext& ctx) {
    if (ctx.tx_queue.empty()) {
        return;
    }

    if (!ctx.io) {
        ctx.tx_queue.clear();
        return;
    }

    auto tx_view = ctx.io->tx_ring();
    int fd = ctx.io->socket().fd();

    auto send_frame = [&](const TxFrame& frame, const char* reason) {
        if (!ctx.io->send_frame(frame.buffer.data(), frame.buffer.size(), frame.net_offset, reason)) {
            LOG(DEBUG_ERROR, "Worker", cfg_.thread_index,
                ": TX fallback failed reason=", reason,
                " frame_len=", frame.buffer.size());
        }
    };

    if (!tx_view.valid()) {
        LOG(DEBUG_IO, "Worker", cfg_.thread_index,
            ": TX ring not mapped origin=",
            (&ctx == &priv_ctx_) ? "priv" : "pub",
            " fallback for ", ctx.tx_queue.size(), " frames");
        for (auto& frame : ctx.tx_queue) {
            send_frame(frame, frame.reason);
        }
        ctx.tx_queue.clear();
        return;
    }

    size_t frame_count = tx_view.frame_count();
    if (frame_count == 0) {
        LOG(DEBUG_IO, "Worker", cfg_.thread_index,
            ": TX ring empty origin=",
            (&ctx == &priv_ctx_) ? "priv" : "pub",
            " fallback for ", ctx.tx_queue.size(), " frames");
        for (auto& frame : ctx.tx_queue) {
            send_frame(frame, frame.reason);
        }
        ctx.tx_queue.clear();
        return;
    }

    auto* base = static_cast<uint8_t*>(ctx.io->socket().mapped_area(af_packet_io::Direction::Tx));
    size_t frame_size = tx_view.frame_size();
    constexpr size_t hdr_size = TPACKET_ALIGN(sizeof(tpacket3_hdr));

    for (auto& frame : ctx.tx_queue) {
        bool written = false;
        for (size_t attempt = 0; attempt < frame_count; ++attempt) {
            size_t idx = ctx.tx_ring_index % frame_count;
            auto* hdr = reinterpret_cast<tpacket3_hdr*>(base + idx * frame_size);
            if ((hdr->tp_status & TP_STATUS_AVAILABLE) == TP_STATUS_AVAILABLE) {
                size_t copy_len = std::min(frame.buffer.size(), frame_size - hdr_size);
                std::memcpy(reinterpret_cast<uint8_t*>(hdr) + hdr_size, frame.buffer.data(), copy_len);
                hdr->tp_len = copy_len;
                hdr->tp_snaplen = copy_len;
                hdr->tp_status = TP_STATUS_SEND_REQUEST;
                ctx.tx_ring_index = idx + 1;
                written = true;
                LOG(DEBUG_NAT, "Worker", cfg_.thread_index,
                    ": TX via ring idx=", idx, " bytes=", copy_len);
                break;
            } else {
                ::sendto(fd, nullptr, 0, 0, nullptr, 0);
                ctx.tx_ring_index = idx + 1;
            }
        }
        if (!written) {
            send_frame(frame, frame.reason);
        }
    }
    ::sendto(fd, nullptr, 0, 0, nullptr, 0);
    LOG(DEBUG_NAT, "Worker", cfg_.thread_index, ": TX batch complete");
    ctx.tx_queue.clear();
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
            " net_offset=", frame.net_offset,
            " origin=", frame.origin == FramePayload::Origin::Private ? "private" : "public");
        handle_frame(frame.origin, frame.buffer.data(), frame.buffer.size(), frame.net_offset);
    }
}

void Worker::submit_remote_frame(FramePayload&& frame) {
    std::lock_guard<std::mutex> lock(remote_mutex_);
    remote_queue_.emplace_back(std::move(frame));
}

std::vector<std::vector<uint8_t>> Worker::collect_tx_frames() {
    std::vector<std::vector<uint8_t>> out;
    auto collect = [&](InterfaceContext& ctx) {
        for (auto& frame : ctx.tx_queue) {
            out.push_back(std::move(frame.buffer));
        }
        ctx.tx_queue.clear();
    };
    collect(priv_ctx_);
    collect(pub_ctx_);
    return out;
}
