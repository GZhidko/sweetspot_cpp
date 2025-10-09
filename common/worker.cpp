#include "worker.hpp"

#include "../common/logger.h"
#include "../filters/filter.h"
#include "../filters/filter_engine.hpp"
#include "../sessions/session_manager.hpp"
#include "../acct/gauge_tracker.hpp"
#include "../committer/committer.h"
#include "../shape/shape_controller.hpp"
#include "checksum.hpp"
#include "jenkins_hash.hpp"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <tuple>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
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

namespace {

const char* origin_to_string(Worker::FramePayload::Origin origin) {
    return origin == Worker::FramePayload::Origin::Private ? "private" : "public";
}

const char* interface_kind_to_string(Worker::InterfaceKind kind) {
    return kind == Worker::InterfaceKind::Private ? "private" : "public";
}

}

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

    try {
        sessions::SessionManager::instance().initialize_from_netset(
            cfg.nat.private_netset,
            filters::Engine::instance().default_filter_name());
    } catch (const std::exception& ex) {
        LOG(DEBUG_ERROR, "Session init failed: ", ex.what());
    }

    shape_controller_ = std::make_unique<shape::ShapeController>(*this);

    LOG(DEBUG_RELAY, "relay init thread=", cfg_.thread_index,
        " io_enabled=", io_enabled_,
        " priv_rx=", cfg_.io_priv.rx_interface,
        " pub_rx=", cfg_.io_pub.rx_interface,
        " static_tcp=", cfg_.static_tcp.size(),
        " static_udp=", cfg_.static_udp.size(),
        " static_icmp=", cfg_.static_icmp.size(),
        " static_ip=", cfg_.static_ip.size(),
        " nat_configured=", nat_.configured());
}

Worker::~Worker() { stop(); }

void Worker::start() {
    if (running_.exchange(true)) {
        return;
    }
    LOG(DEBUG_RELAY, "relay start requested thread=", cfg_.thread_index);
    thread_ = std::thread(&Worker::run, this);
}

void Worker::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    LOG(DEBUG_RELAY, "relay stop requested thread=", cfg_.thread_index);
    if (thread_.joinable()) {
        thread_.join();
    }
    if (shape_controller_) {
        shape_controller_->shutdown();
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

    LOG(DEBUG_RELAY, "relay loop enter thread=", cfg_.thread_index,
        " priv_blocks=", priv_view.block_count(),
        " pub_blocks=", pub_view.block_count());

    size_t iteration = 0;
    while (running_) {
        ++iteration;
        size_t remote_pending = 0;
        {
            std::lock_guard<std::mutex> lock(remote_mutex_);
            remote_pending = remote_queue_.size();
        }
        size_t priv_tx = 0;
        size_t pub_tx = 0;
        {
            std::lock_guard<std::mutex> lock(priv_ctx_.tx_mutex);
            priv_tx = priv_ctx_.tx_queue.size();
        }
        {
            std::lock_guard<std::mutex> lock(pub_ctx_.tx_mutex);
            pub_tx = pub_ctx_.tx_queue.size();
        }
        LOG(DEBUG_RELAY, "relay cycle thread=", cfg_.thread_index,
            " iteration=", iteration,
            " remote_pending=", remote_pending,
            " priv_tx_queue=", priv_tx,
            " pub_tx_queue=", pub_tx);
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
    LOG(DEBUG_RELAY, "relay loop exit thread=", cfg_.thread_index,
        " iterations=", iteration);
}

void Worker::process_interface(InterfaceContext& src_ctx, af_packet_io::RingView& view,
                               FramePayload::Origin origin) {
    LOG(DEBUG_RELAY, "relay process_interface thread=", cfg_.thread_index,
        " origin=", origin_to_string(origin),
        " blocks=", view.block_count());
    for (size_t i = 0; i < view.block_count(); ++i) {
        auto* block = view.block_at(i);
        if (!block) {
            continue;
        }
        if (block->hdr.bh1.block_status & TP_STATUS_USER) {
            LOG(DEBUG_RELAY, "relay block ready thread=", cfg_.thread_index,
                " origin=", origin_to_string(origin),
                " block_index=", i,
                " packets=", block->hdr.bh1.num_pkts);
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
        LOG(DEBUG_RELAY, "relay packet thread=", cfg_.thread_index,
            " origin=", origin_to_string(origin),
            " block_packet_index=", i,
            " len=", len,
            " net_offset=", net_offset);
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
    if (l3_len < sizeof(iphdr)) {
        return;
    }

    LOG(DEBUG_RELAY, "relay handle_frame thread=", cfg_.thread_index,
        " origin=", origin_to_string(origin),
        " len=", len,
        " net_offset=", net_offset);
    LOG(DEBUG_NAT, "Worker", cfg_.thread_index, ": received frame len=", len,
        " net_offset=", net_offset);

    // Parse full packet once
    filters::Direction dir = (origin == FramePayload::Origin::Public)
                                 ? filters::Direction::Inbound
                                 : filters::Direction::Outbound;
    Chain chain;
    if (!chain.parse(l3_data, l3_len)) {
        LOG(DEBUG_NAT, "Worker", cfg_.thread_index, ": parse failed");
        return;
    }

    auto* ipv4 = chain.get<IPv4Header>();
    if (!ipv4) {
        return;
    }

    const uint32_t src_ip_host = ntohl(ipv4->iph.saddr);
    const uint32_t dst_ip_host = ntohl(ipv4->iph.daddr);

    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    if (auto* tcp = chain.get<TCPHeader>()) {
        src_port = ntohs(tcp->tcph.source);
        dst_port = ntohs(tcp->tcph.dest);
    } else if (auto* udp = chain.get<UDPHeader>()) {
        src_port = ntohs(udp->udph.source);
        dst_port = ntohs(udp->udph.dest);
    } else if (auto* icmp = chain.get<ICMPHeader>()) {
        src_port = ntohs(icmp->icmph.un.echo.id);
        dst_port = ntohs(icmp->icmph.un.echo.sequence);
    }

    if (cfg_.thread_count > 1 && forward_fn_) {
        auto tuple = std::make_tuple(htonl(src_ip_host), htonl(dst_ip_host), htons(src_port),
                                     htons(dst_port), static_cast<uint8_t>(ipv4->iph.protocol));
        uint32_t target = CPUFanoutHash::select_cpu(CPUFanoutHash::hash_tuple(tuple),
                                                    cfg_.thread_count);
        if (target != cfg_.thread_index) {
            LOG(DEBUG_RELAY, "relay forward thread=", cfg_.thread_index,
                " target=", target,
                " origin=", origin_to_string(origin),
                " len=", len);
            FramePayload payload;
            payload.origin = origin;
            payload.buffer.assign(data, data + len);
            payload.net_offset = net_offset;
            payload.parsed_chain.emplace(std::move(chain));
            forward_fn_(target, std::move(payload));
            return;
        }
    }

    LOG(DEBUG_RELAY, "relay local process thread=", cfg_.thread_index,
        " origin=", origin_to_string(origin),
        " len=", len);
    process_chain(origin, data, len, net_offset, chain);
}

void Worker::handle_forwarded(FramePayload&& payload) {
    if (!payload.parsed_chain) {
        LOG(DEBUG_NAT, "Worker", cfg_.thread_index, ": forwarded frame missing parsed chain");
        return;
    }

    Chain chain = std::move(*payload.parsed_chain);
    LOG(DEBUG_RELAY, "relay handle_forwarded thread=", cfg_.thread_index,
        " origin=", origin_to_string(payload.origin),
        " len=", payload.buffer.size(),
        " net_offset=", payload.net_offset);
    process_chain(payload.origin, payload.buffer.data(), payload.buffer.size(),
                  payload.net_offset, chain);
}

void Worker::process_chain(FramePayload::Origin origin, uint8_t* data, size_t len,
                           size_t net_offset, Chain& chain) {
    filters::Direction dir = (origin == FramePayload::Origin::Public)
                                 ? filters::Direction::Inbound
                                 : filters::Direction::Outbound;

    filters::ScopedPacket packet_scope(dir);

    auto* ipv4 = chain.get<IPv4Header>();
    if (!ipv4) {
        return;
    }

    uint32_t session_ip = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    if (auto* tcp = chain.get<TCPHeader>()) {
        src_port = ntohs(tcp->tcph.source);
        dst_port = ntohs(tcp->tcph.dest);
    } else if (auto* udp = chain.get<UDPHeader>()) {
        src_port = ntohs(udp->udph.source);
        dst_port = ntohs(udp->udph.dest);
    } else if (auto* icmp = chain.get<ICMPHeader>()) {
        src_port = ntohs(icmp->icmph.un.echo.id);
        dst_port = ntohs(icmp->icmph.un.echo.sequence);
    }

    if (dir == filters::Direction::Outbound) {
        session_ip = ntohl(ipv4->iph.saddr);
    } else {
        uint32_t pub_ip = ntohl(ipv4->iph.daddr);
        uint32_t remote_ip = ntohl(ipv4->iph.saddr);
        if (auto resolved =
                nat_.resolve_private(pub_ip, remote_ip, dst_port, src_port, ipv4->iph.protocol)) {
            session_ip = *resolved;
        }
    }

    std::string selected_filter = filters::Engine::instance().default_filter_name();
    bool drop_for_status = false;
    if (session_ip != 0) {
        if (auto session = sessions::SessionManager::instance().find_session(session_ip)) {
            if (!session->filter_name.empty()) {
                selected_filter = session->filter_name;
            }
            if (session->status == sessions::SessionStatus::Captured) {
                drop_for_status = true;
            }
        }
    }

    filters::set_current_filter(selected_filter);
    LOG(DEBUG_RELAY, "relay process_chain thread=", cfg_.thread_index,
        " origin=", origin_to_string(origin),
        " filter=", selected_filter,
        " session_ip=", session_ip,
        " drop_for_status=", drop_for_status);

    bool ok = true;
    chain.for_each([&](auto& hdr) {
        if (!Filter<std::decay_t<decltype(hdr)>>{}(hdr)) {
            ok = false;
        }
    });
    if (!ok) {
        LOG(DEBUG_NAT, "Worker", cfg_.thread_index, ": filtered");
        LOG(DEBUG_RELAY, "relay filter drop thread=", cfg_.thread_index,
            " origin=", origin_to_string(origin));
        return;
    }

    auto decision = filters::current_decision();
    LOG(DEBUG_RELAY, "relay decision thread=", cfg_.thread_index,
        " allow=", decision.allow,
        " matched=", decision.matched,
        " rule=", decision.rule_index,
        " actions=", static_cast<int>(decision.actions),
        " shape_rate=", decision.shape_rate);
    if (!decision.allow) {
        return;
    }

    if (drop_for_status) {
        LOG(DEBUG_NAT, "Worker", cfg_.thread_index, ": frame dropped due to session status");
        LOG(DEBUG_RELAY, "relay drop status thread=", cfg_.thread_index,
            " session_ip=", session_ip);
        return;
    }

    finish_frame(chain, decision, origin, data, len, net_offset, session_ip);
}

void Worker::enqueue_tx(InterfaceContext& ctx, std::vector<uint8_t>&& frame, size_t net_offset,
                        const char* reason) {
    std::lock_guard<std::mutex> lock(ctx.tx_mutex);
    ctx.tx_queue.push_back({});
    ctx.tx_queue.back().buffer = std::move(frame);
    ctx.tx_queue.back().net_offset = net_offset;
    ctx.tx_queue.back().reason = reason;
    LOG(DEBUG_RELAY, "relay enqueue_tx thread=", cfg_.thread_index,
        " origin_ctx=", (&ctx == &priv_ctx_) ? "priv" : "pub",
        " reason=", reason,
        " bytes=", ctx.tx_queue.back().buffer.size(),
        " queue_size=", ctx.tx_queue.size());
    LOG(DEBUG_NAT, "Worker", cfg_.thread_index, ": enqueue TX frame bytes=",
        ctx.tx_queue.back().buffer.size(), " net_offset=", net_offset,
        " reason=", reason, " queue_size=", ctx.tx_queue.size());
}

void Worker::transmit_pending(InterfaceContext& ctx) {
    std::vector<TxFrame> frames;
    {
        std::lock_guard<std::mutex> lock(ctx.tx_mutex);
        if (ctx.tx_queue.empty()) {
            return;
        }
        frames.swap(ctx.tx_queue);
    }

    LOG(DEBUG_RELAY, "relay transmit_pending thread=", cfg_.thread_index,
        " origin_ctx=", (&ctx == &priv_ctx_) ? "priv" : "pub",
        " frames=", frames.size());

    if (!ctx.io) {
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
            " fallback for ", frames.size(), " frames");
        for (auto& frame : frames) {
            send_frame(frame, frame.reason);
        }
        return;
    }

    size_t frame_count = tx_view.frame_count();
    if (frame_count == 0) {
        LOG(DEBUG_IO, "Worker", cfg_.thread_index,
            ": TX ring empty origin=",
            (&ctx == &priv_ctx_) ? "priv" : "pub",
            " fallback for ", frames.size(), " frames");
        for (auto& frame : frames) {
            send_frame(frame, frame.reason);
        }
        return;
    }

    auto* base = static_cast<uint8_t*>(ctx.io->socket().mapped_area(af_packet_io::Direction::Tx));
    size_t frame_size = tx_view.frame_size();
    constexpr size_t hdr_size = TPACKET_ALIGN(sizeof(tpacket3_hdr));

    for (auto& frame : frames) {
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
}

void Worker::process_remote_frames() {
    std::deque<FramePayload> local;
    {
        std::lock_guard<std::mutex> lock(remote_mutex_);
        local.swap(remote_queue_);
    }
    LOG(DEBUG_RELAY, "relay process_remote thread=", cfg_.thread_index,
        " count=", local.size());
    for (auto& frame : local) {
        LOG(DEBUG_NAT, "Worker", cfg_.thread_index,
            ": processing forwarded frame bytes=", frame.buffer.size(),
            " net_offset=", frame.net_offset,
            " origin=", frame.origin == FramePayload::Origin::Private ? "private" : "public");
        LOG(DEBUG_RELAY, "relay remote frame thread=", cfg_.thread_index,
            " origin=", origin_to_string(frame.origin),
            " len=", frame.buffer.size());
        handle_forwarded(std::move(frame));
    }
}

void Worker::submit_remote_frame(FramePayload&& frame) {
    std::lock_guard<std::mutex> lock(remote_mutex_);
    remote_queue_.emplace_back(std::move(frame));
    LOG(DEBUG_RELAY, "relay submit_remote thread=", cfg_.thread_index,
        " queue_size=", remote_queue_.size());
}

std::vector<std::vector<uint8_t>> Worker::collect_tx_frames() {
    std::vector<std::vector<uint8_t>> out;
    auto collect = [&](InterfaceContext& ctx) {
        std::lock_guard<std::mutex> lock(ctx.tx_mutex);
        for (auto& frame : ctx.tx_queue) {
            out.push_back(std::move(frame.buffer));
        }
        ctx.tx_queue.clear();
    };
    collect(priv_ctx_);
    collect(pub_ctx_);
    LOG(DEBUG_RELAY, "relay collect_tx_frames thread=", cfg_.thread_index,
        " collected=", out.size());
    return out;
}

void Worker::enqueue_shaped_frame(InterfaceKind kind, std::vector<uint8_t>&& frame,
                                  size_t net_offset) {
    LOG(DEBUG_RELAY, "relay enqueue_shaped thread=", cfg_.thread_index,
        " target=", interface_kind_to_string(kind),
        " bytes=", frame.size(),
        " net_offset=", net_offset);
    if (kind == InterfaceKind::Private) {
        enqueue_tx(priv_ctx_, std::move(frame), net_offset, "shape");
    } else {
        enqueue_tx(pub_ctx_, std::move(frame), net_offset, "shape");
    }
}

void Worker::finish_frame(Chain& chain, const filters::Decision& decision,
                          FramePayload::Origin origin, uint8_t* data, size_t len, size_t net_offset,
                          uint32_t session_ip) {
    auto* ipv4 = chain.template get<IPv4Header>();
    if (!ipv4) {
        return;
    }

    uint8_t* l3_data = data + net_offset;
    size_t l3_len = len - net_offset;

    chain.for_each([&](auto& hdr) { nat_.process(hdr); });

    size_t offset = 0;
    if (!Committer<IPv4Header>{}(ipv4, l3_data, l3_len, offset)) {
        return;
    }

    chain.for_each([&](auto& hdr) {
        using Header = std::decay_t<decltype(hdr)>;
        if constexpr (!std::is_same_v<Header, IPv4Header>) {
            Committer<Header>{}(&hdr, l3_data, l3_len, offset, ipv4);
        }
    });

    uint32_t gauge_ip = session_ip;
    if (gauge_ip == 0) {
        gauge_ip = (origin == FramePayload::Origin::Private) ? ntohl(ipv4->iph.saddr)
                                                            : ntohl(ipv4->iph.daddr);
        if (cfg_.nat.private_netset && !cfg_.nat.private_netset->contains(gauge_ip)) {
            gauge_ip = 0;
        }
    }
    if (gauge_ip != 0) {
        auto direction = (origin == FramePayload::Origin::Private)
                             ? accounting::GaugeTracker::Direction::Outbound
                             : accounting::GaugeTracker::Direction::Inbound;
        accounting::GaugeTracker::instance().record(gauge_ip, l3_len, direction);
    }

    LOG(DEBUG_NAT, "Worker", cfg_.thread_index,
        ": frame after NAT src=", IPv4Header::ip_to_string(ipv4->iph.saddr),
        " dst=", IPv4Header::ip_to_string(ipv4->iph.daddr));

    uint16_t log_src_port = 0;
    uint16_t log_dst_port = 0;
    uint16_t log_icmp_id = 0;

    switch (ipv4->iph.protocol) {
    case IPPROTO_TCP:
        if (auto* tcp_hdr = chain.template get<TCPHeader>()) {
            log_src_port = ntohs(tcp_hdr->tcph.source);
            log_dst_port = ntohs(tcp_hdr->tcph.dest);
        }
        break;
    case IPPROTO_UDP:
        if (auto* udp_hdr = chain.template get<UDPHeader>()) {
            log_src_port = ntohs(udp_hdr->udph.source);
            log_dst_port = ntohs(udp_hdr->udph.dest);
        }
        break;
    case IPPROTO_ICMP:
        if (auto* icmp_hdr = chain.template get<ICMPHeader>()) {
            log_icmp_id = ntohs(icmp_hdr->icmph.un.echo.id);
        }
        break;
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

    std::vector<uint8_t> tx_buffer(data, data + len);
    bool shaped = has_flag(decision.actions, filters::ActionFlag::Shape) && decision.shape_rate > 0;
    if (shaped && shape_controller_) {
        auto target = (dest_ctx == &pub_ctx_) ? shape::ShapeController::Target::Public
                                              : shape::ShapeController::Target::Private;
        LOG(DEBUG_RELAY, "relay shape enqueue thread=", cfg_.thread_index,
            " target=", (dest_ctx == &pub_ctx_ ? "pub" : "priv"),
            " rate=", decision.shape_rate,
            " bytes=", tx_buffer.size());
        shape_controller_->enqueue(target, std::move(tx_buffer), net_offset, decision.shape_rate);
    } else {
        LOG(DEBUG_RELAY, "relay direct enqueue thread=", cfg_.thread_index,
            " target=", (dest_ctx == &pub_ctx_ ? "pub" : "priv"),
            " bytes=", tx_buffer.size());
        enqueue_tx(*dest_ctx, std::move(tx_buffer), net_offset, "direct");
    }
}
