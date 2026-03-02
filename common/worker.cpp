#include "worker.hpp"

#include "../acct/gauge_tracker.hpp"
#include "../committer/committer.h"
#include "../common/logger.h"
#include "../filters/filter.h"
#include "../filters/filter_engine.hpp"
#include "../sessions/session_manager.hpp"
#include "../shape/shape_controller.hpp"
#include "checksum.hpp"
#include "jenkins_hash.hpp"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <tuple>
#include <unistd.h>
#include <vector>

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

struct ScopedProfileTimer {
    std::chrono::steady_clock::time_point started_at;
    uint64_t* total_ns = nullptr;
    uint64_t* calls = nullptr;

    ScopedProfileTimer(uint64_t* total, uint64_t* calls_counter)
        : started_at(std::chrono::steady_clock::now()), total_ns(total), calls(calls_counter) {}

    ~ScopedProfileTimer() {
        if (!total_ns) {
            return;
        }
        const auto now = std::chrono::steady_clock::now();
        *total_ns += static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(now - started_at).count());
        if (calls) {
            ++(*calls);
        }
    }
};

const char* origin_to_string(Worker::FramePayload::Origin origin) {
    return origin == Worker::FramePayload::Origin::Private ? "private" : "public";
}

const char* interface_kind_to_string(Worker::InterfaceKind kind) {
    return kind == Worker::InterfaceKind::Private ? "private" : "public";
}

} // namespace

Worker::Worker(const WorkerPipelineConfig& cfg)
    : cfg_(cfg), nat_(cfg.nat, cfg.thread_index, cfg.thread_count) {
    forward_pool_enabled_ = cfg.forward_pool_enabled;
    profile_enabled_ = cfg.profile_enabled;
    profile_interval_ms_ = cfg.profile_interval_ms == 0 ? 2000 : cfg.profile_interval_ms;
    if (profile_enabled_) {
        profile_started_at_ = std::chrono::steady_clock::now();
        profile_last_dump_at_ = profile_started_at_;
    }
    remote_event_fd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (remote_event_fd_ < 0) {
        LOG(DEBUG_ERROR, "Worker", cfg_.thread_index, ": eventfd create failed errno=", errno);
    }

    io_enabled_ = cfg.enable_io;
    if (io_enabled_) {
        if (!cfg.io_priv.rx_interface.empty()) {
            priv_ctx_.io = std::make_unique<af_packet_io::IoContext>(cfg.io_priv);
        }
        if (!cfg.io_pub.rx_interface.empty()) {
            pub_ctx_.io = std::make_unique<af_packet_io::IoContext>(cfg.io_pub);
        }
    }
    if (!cfg_.static_tcp.empty() || !cfg_.static_udp.empty() || !cfg_.static_icmp.empty() ||
        !cfg_.static_ip.empty()) {
        LOG(DEBUG_NAT,
            "Static NAT mappings via WorkerPipelineConfig are no longer supported and will be "
            "ignored "
            "tcp=",
            cfg_.static_tcp.size(), " udp=", cfg_.static_udp.size(),
            " icmp=", cfg_.static_icmp.size(), " ip=", cfg_.static_ip.size());
    }

    try {
        sessions::SessionManager::instance().initialize_from_netset(
            cfg.nat.private_netset, filters::Engine::instance().default_filter_name());
    } catch (const std::exception& ex) {
        LOG(DEBUG_ERROR, "Session init failed: ", ex.what());
    }

    shape_controller_ = std::make_unique<shape::ShapeController>(*this);

    LOG(DEBUG_RELAY, "relay init thread=", cfg_.thread_index, " io_enabled=", io_enabled_,
        " priv_rx=", cfg_.io_priv.rx_interface, " pub_rx=", cfg_.io_pub.rx_interface,
        " static_tcp=", cfg_.static_tcp.size(), " static_udp=", cfg_.static_udp.size(),
        " static_icmp=", cfg_.static_icmp.size(), " static_ip=", cfg_.static_ip.size(),
        " nat_configured=", nat_.configured(), " profile_enabled=", profile_enabled_,
        " profile_interval_ms=", profile_interval_ms_);
}

Worker::~Worker() {
    stop();

    RemoteNode* pending = pop_all_remote_nodes();
    while (pending) {
        RemoteNode* next = pending->next;
        delete pending;
        pending = next;
    }
    RemoteNode* free_head = remote_free_.exchange(nullptr, std::memory_order_acquire);
    while (free_head) {
        RemoteNode* next = free_head->next;
        delete free_head;
        free_head = next;
    }

    if (remote_event_fd_ >= 0) {
        ::close(remote_event_fd_);
        remote_event_fd_ = -1;
    }
}

std::vector<uint8_t> Worker::acquire_forward_buffer(size_t len) {
    std::lock_guard<std::mutex> lock(forward_pool_mutex_);
    if (!forward_pool_.empty()) {
        std::vector<uint8_t> buffer = std::move(forward_pool_.back());
        forward_pool_.pop_back();
        if (buffer.capacity() < len) {
            buffer.reserve(len);
        }
        buffer.resize(len);
        return buffer;
    }
    return std::vector<uint8_t>(len);
}

void Worker::recycle_forward_buffer(std::vector<uint8_t>&& buffer) {
    if (!forward_pool_enabled_ || buffer.capacity() == 0) {
        return;
    }
    buffer.clear();
    std::lock_guard<std::mutex> lock(forward_pool_mutex_);
    if (forward_pool_.size() < 4096) {
        forward_pool_.push_back(std::move(buffer));
    }
}

Worker::RemoteNode* Worker::acquire_remote_node() {
    RemoteNode* head = remote_free_.load(std::memory_order_acquire);
    while (head &&
           !remote_free_.compare_exchange_weak(head, head->next, std::memory_order_acq_rel,
                                               std::memory_order_acquire)) {
    }
    if (!head) {
        return new RemoteNode();
    }
    head->next = nullptr;
    return head;
}

void Worker::recycle_remote_node(RemoteNode* node) {
    if (!node) {
        return;
    }
    if (forward_pool_enabled_) {
        recycle_forward_buffer(std::move(node->payload.buffer));
    } else {
        node->payload.buffer.clear();
    }
    node->payload.parsed_chain.reset();
    node->payload.net_offset = 0;
    node->payload.origin = FramePayload::Origin::Private;

    RemoteNode* head = remote_free_.load(std::memory_order_relaxed);
    do {
        node->next = head;
    } while (!remote_free_.compare_exchange_weak(head, node, std::memory_order_release,
                                                 std::memory_order_relaxed));
}

Worker::RemoteNode* Worker::pop_all_remote_nodes() {
    return remote_head_.exchange(nullptr, std::memory_order_acquire);
}

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
        " priv_blocks=", priv_view.block_count(), " pub_blocks=", pub_view.block_count());

    int epfd = -1;
    int priv_fd = priv_ctx_.io ? priv_ctx_.io->socket().fd() : -1;
    int pub_fd = pub_ctx_.io ? pub_ctx_.io->socket().fd() : -1;

    if (priv_fd >= 0 || pub_fd >= 0) {
        epfd = ::epoll_create1(EPOLL_CLOEXEC);
        if (epfd < 0) {
            LOG(DEBUG_ERROR, "Worker", cfg_.thread_index,
                ": epoll_create1 failed errno=", errno, " fallback to polling");
        } else {
            auto register_fd = [&](int fd, uint32_t token) {
                if (fd < 0) {
                    return;
                }
                epoll_event ev{};
                ev.events = EPOLLIN;
                ev.data.u32 = token;
                if (::epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
                    LOG(DEBUG_ERROR, "Worker", cfg_.thread_index,
                        ": epoll_ctl add failed fd=", fd, " errno=", errno);
                }
            };
            register_fd(priv_fd, 1);
            if (pub_fd != priv_fd) {
                register_fd(pub_fd, 2);
            }
            register_fd(remote_event_fd_, 3);
        }
    }

    size_t iteration = 0;
    while (running_) {
        ++iteration;
        if (profile_enabled_) {
            ++profile_loops_;
        }
        bool has_priv_tx = false;
        bool has_pub_tx = false;
        {
            std::lock_guard<std::mutex> lock(priv_ctx_.tx_mutex);
            has_priv_tx = !priv_ctx_.tx_queue.empty();
        }
        {
            std::lock_guard<std::mutex> lock(pub_ctx_.tx_mutex);
            has_pub_tx = !pub_ctx_.tx_queue.empty();
        }

        bool priv_ready = false;
        bool pub_ready = false;
        bool remote_ready = false;

        if (epfd >= 0) {
            // Block when fully idle; run immediately when local work is queued.
            int timeout_ms = (has_priv_tx || has_pub_tx) ? 0 : 5;
            if (profile_enabled_) {
                ++profile_epoll_wait_calls_;
            }
            epoll_event events[4]{};
            int ready = ::epoll_wait(epfd, events, 4, timeout_ms);
            if (ready < 0) {
                if (errno != EINTR) {
                    LOG(DEBUG_ERROR, "Worker", cfg_.thread_index,
                        ": epoll_wait failed errno=", errno);
                }
            } else {
                if (profile_enabled_) {
                    if (ready == 0) {
                        ++profile_epoll_timeouts_;
                    } else {
                        profile_epoll_ready_events_ += static_cast<uint64_t>(ready);
                    }
                }
                for (int i = 0; i < ready; ++i) {
                    const uint32_t token = events[i].data.u32;
                    if (token == 1) {
                        priv_ready = true;
                    } else if (token == 2) {
                        pub_ready = true;
                    } else if (token == 3) {
                        remote_ready = true;
                    }
                }
            }
        } else {
            // Fallback behavior on systems where epoll init failed.
            priv_ready = priv_ctx_.io != nullptr;
            pub_ready = pub_ctx_.io != nullptr;
            remote_ready = (remote_head_.load(std::memory_order_acquire) != nullptr);
        }

        if (remote_ready && remote_event_fd_ >= 0) {
            uint64_t counter = 0;
            while (::read(remote_event_fd_, &counter, sizeof(counter)) == sizeof(counter)) {
            }
        }

        if (remote_ready) {
            process_remote_frames();
        }
        if (priv_ctx_.io && priv_ready) {
            process_interface(priv_ctx_, priv_view, FramePayload::Origin::Private);
        }
        if (pub_ctx_.io && pub_ready) {
            process_interface(pub_ctx_, pub_view, FramePayload::Origin::Public);
        }
        transmit_pending(priv_ctx_);
        transmit_pending(pub_ctx_);
        if (!priv_ctx_.io && !pub_ctx_.io) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        maybe_dump_profile(false);
    }
    maybe_dump_profile(true);
    if (epfd >= 0) {
        ::close(epfd);
    }
    LOG(DEBUG_RELAY, "relay loop exit thread=", cfg_.thread_index, " iterations=", iteration);
}

void Worker::process_interface(InterfaceContext& src_ctx, af_packet_io::RingView& view,
                               FramePayload::Origin origin) {
    for (size_t i = 0; i < view.block_count(); ++i) {
        auto* block = view.block_at(i);
        if (!block) {
            continue;
        }
        if (block->hdr.bh1.block_status & TP_STATUS_USER) {
            LOG(DEBUG_RELAY, "relay block ready thread=", cfg_.thread_index,
                " origin=", origin_to_string(origin), " block_index=", i,
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
            " origin=", origin_to_string(origin), " block_packet_index=", i, " len=", len,
            " net_offset=", net_offset);
        if (profile_enabled_) {
            ++profile_rx_packets_;
            profile_rx_bytes_ += static_cast<uint64_t>(len);
        }
        handle_frame(origin, data, len, net_offset);
        hdr =
            reinterpret_cast<tpacket3_hdr*>(reinterpret_cast<uint8_t*>(hdr) + hdr->tp_next_offset);
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
        " origin=", origin_to_string(origin), " len=", len, " net_offset=", net_offset);
    LOG(DEBUG_NAT, "Worker", cfg_.thread_index, ": received frame len=", len,
        " net_offset=", net_offset);

    // Parse full packet once
    filters::Direction dir = (origin == FramePayload::Origin::Private)
                                 ? filters::Direction::Inbound
                                 : filters::Direction::Outbound;
    Chain chain;
    bool parsed = false;
    if (profile_enabled_) {
        const auto parse_started = std::chrono::steady_clock::now();
        parsed = chain.parse(l3_data, l3_len);
        const auto parse_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                  std::chrono::steady_clock::now() - parse_started)
                                  .count();
        ++profile_parse_calls_;
        profile_parse_ns_ += static_cast<uint64_t>(parse_ns);
    } else {
        parsed = chain.parse(l3_data, l3_len);
    }
    if (!parsed) {
        if (profile_enabled_) {
            ++profile_parse_fail_;
        }
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
        uint32_t target =
            CPUFanoutHash::select_cpu(CPUFanoutHash::hash_tuple(tuple), cfg_.thread_count);
        if (target != cfg_.thread_index) {
            LOG(DEBUG_RELAY, "relay forward thread=", cfg_.thread_index, " target=", target,
                " origin=", origin_to_string(origin), " len=", len);
            FramePayload payload;
            payload.origin = origin;
            if (forward_pool_enabled_) {
                payload.buffer = acquire_forward_buffer(len);
                std::memcpy(payload.buffer.data(), data, len);
            } else {
                payload.buffer.assign(data, data + len);
            }
            payload.net_offset = net_offset;
            payload.parsed_chain.emplace(std::move(chain));
            forward_fn_(target, std::move(payload));
            if (profile_enabled_) {
                ++profile_forward_remote_;
            }
            return;
        }
    }

    LOG(DEBUG_RELAY, "relay local process thread=", cfg_.thread_index,
        " origin=", origin_to_string(origin), " len=", len);
    if (profile_enabled_) {
        ++profile_forward_local_;
    }
    process_chain(origin, data, len, net_offset, chain);
}

void Worker::handle_forwarded(FramePayload&& payload) {
    if (!payload.parsed_chain) {
        LOG(DEBUG_NAT, "Worker", cfg_.thread_index, ": forwarded frame missing parsed chain");
        return;
    }

    Chain chain = std::move(*payload.parsed_chain);
    LOG(DEBUG_RELAY, "relay handle_forwarded thread=", cfg_.thread_index,
        " origin=", origin_to_string(payload.origin), " len=", payload.buffer.size(),
        " net_offset=", payload.net_offset);
    process_chain(payload.origin, payload.buffer.data(), payload.buffer.size(), payload.net_offset,
                  chain);
}

void Worker::process_chain(FramePayload::Origin origin, uint8_t* data, size_t len,
                           size_t net_offset, Chain& chain) {
    ScopedProfileTimer chain_timer(profile_enabled_ ? &profile_chain_ns_ : nullptr,
                                   profile_enabled_ ? &profile_chain_calls_ : nullptr);
    filters::Direction dir = (origin == FramePayload::Origin::Private)
                                 ? filters::Direction::Inbound
                                 : filters::Direction::Outbound;

    filters::ScopedPacket packet_scope(dir);

    auto* ipv4 = chain.get<IPv4Header>();
    if (!ipv4) {
        return;
    }

    uint8_t* l3_data = data + net_offset;
    size_t l3_len = len > net_offset ? len - net_offset : 0;

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
        dst_port = ntohs(icmp->icmph.un.echo.id);
        src_port = ntohs(icmp->icmph.un.echo.sequence);
    }

    if (origin == FramePayload::Origin::Private) {
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
        " origin=", origin_to_string(origin), " filter=", selected_filter,
        " session_ip=", session_ip, " drop_for_status=", drop_for_status);

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
    LOG(DEBUG_RELAY, "relay decision thread=", cfg_.thread_index, " allow=", decision.allow,
        " matched=", decision.matched, " rule=", decision.rule_index,
        " actions=", static_cast<int>(decision.actions), " shape_rate=", decision.shape_rate ,
        " dnat_valid=", decision.dnat.valid, " dnat_ip=", IPv4Header::ip_to_string(decision.dnat.ip));
    if (!decision.allow) {
        return;
    }

    if (has_flag(decision.actions, filters::ActionFlag::Dnat) ) {
        if (dir == filters::Direction::Inbound) {
            apply_inbound_dnat(origin, chain, *ipv4, l3_data, l3_len, decision);
        }
    }

    if (drop_for_status) {
        LOG(DEBUG_NAT, "Worker", cfg_.thread_index, ": frame dropped due to session status");
        LOG(DEBUG_RELAY, "relay drop status thread=", cfg_.thread_index,
            " session_ip=", session_ip);
        return;
    }

    finish_frame(chain, decision, origin, data, len, net_offset, session_ip);
}

namespace {

uint16_t compute_tcp_checksum(const iphdr& ip, uint8_t* l4_data, uint16_t tcp_len) {
    auto checksum = checksum::l4_checksum(&ip, l4_data, tcp_len, IPPROTO_TCP);
    return htons(checksum);
}

uint16_t compute_udp_checksum(const iphdr& ip, uint8_t* l4_data, uint16_t udp_len) {
    auto checksum = checksum::l4_checksum(&ip, l4_data, udp_len, IPPROTO_UDP);
    return htons(checksum);
}

uint16_t compute_icmp_checksum(uint8_t* icmp_bytes, uint16_t icmp_len) {
    auto checksum = checksum::ip_checksum(icmp_bytes, icmp_len);
    return htons(checksum);
}

} // namespace

bool Worker::apply_inbound_dnat(FramePayload::Origin origin, Chain& chain, IPv4Header& ipv4,
                                uint8_t* l3_data, size_t l3_len,
                                const filters::Decision& decision) {
    if (origin != FramePayload::Origin::Private) {
        return false;
    }
    if (!has_flag(decision.actions, filters::ActionFlag::Dnat) || !decision.dnat.valid) {
        return false;
    }

    const uint8_t protocol = ipv4.iph.protocol;
    const uint32_t target_ip = decision.dnat.ip;
    const uint16_t requested_target_port = decision.dnat.port;
    const uint32_t original_ip = ntohl(ipv4.iph.daddr);
    const uint32_t remote_ip = ntohl(ipv4.iph.saddr);

    uint16_t original_port = 0;
    uint16_t remote_port = 0;
    uint16_t effective_target_port = requested_target_port;

    auto* tcp = chain.get<TCPHeader>();
    auto* udp = chain.get<UDPHeader>();
    auto* icmp = chain.get<ICMPHeader>();

    uint16_t ip_header_len = static_cast<uint16_t>(ipv4.iph.ihl) * 4u;
    uint16_t total_len = ntohs(ipv4.iph.tot_len);
    if (l3_len < total_len || total_len < ip_header_len) {
        LOG(DEBUG_ERROR, "Worker", cfg_.thread_index,
            ": DNAT inbound invalid lengths total=", total_len, " header=", ip_header_len,
            " l3_len=", l3_len);
        return false;
    }

    if (tcp) {
        original_port = ntohs(tcp->tcph.dest);
        remote_port = ntohs(tcp->tcph.source);
        if (requested_target_port != 0) {
            tcp->tcph.dest = htons(requested_target_port);
            effective_target_port = requested_target_port;
        } else {
            effective_target_port = original_port;
        }
    } else if (udp) {
        original_port = ntohs(udp->udph.dest);
        remote_port = ntohs(udp->udph.source);
        if (requested_target_port != 0) {
            udp->udph.dest = htons(requested_target_port);
            effective_target_port = requested_target_port;
        } else {
            effective_target_port = original_port;
        }
    } else if (icmp) {
        original_port = ntohs(icmp->icmph.un.echo.id);
        remote_port = ntohs(icmp->icmph.un.echo.sequence);
        if (requested_target_port != 0) {
            icmp->icmph.un.echo.id = htons(requested_target_port);
            effective_target_port = requested_target_port;
        } else {
            effective_target_port = original_port;
        }
    } else {
        effective_target_port = requested_target_port;
    }

    LOG(DEBUG_RELAY, "relay DNAT inbound thread=", cfg_.thread_index,
        " original_ip=", IPv4Header::ip_to_string(original_ip), " original_port=", original_port,
        " target_ip=", IPv4Header::ip_to_string(target_ip), " target_port=", effective_target_port,
        " remote_ip=", IPv4Header::ip_to_string(remote_ip), " remote_port=", remote_port,
        " protocol=", static_cast<int>(protocol));

    dnat_table_.upsert(target_ip, effective_target_port, remote_ip, remote_port,
                       original_ip, original_port, protocol, protocol == IPPROTO_TCP);

    ipv4.iph.daddr = htonl(target_ip);
    ipv4.iph.check = checksum::recompute_ipv4_checksum(ipv4.iph);
    std::memcpy(l3_data, &ipv4.iph, ip_header_len);

    uint8_t* l4_data = l3_data + ip_header_len;
    uint16_t payload_len = static_cast<uint16_t>(total_len - ip_header_len);

    if (tcp && payload_len >= sizeof(tcphdr)) {
        std::memcpy(l4_data, &tcp->tcph, sizeof(tcphdr));
        auto* raw_tcp = reinterpret_cast<tcphdr*>(l4_data);
        raw_tcp->check = 0;
        raw_tcp->check = compute_tcp_checksum(ipv4.iph, l4_data, payload_len);
        tcp->tcph.check = raw_tcp->check;
    } else if (udp && payload_len >= sizeof(udphdr)) {
        std::memcpy(l4_data, &udp->udph, sizeof(udphdr));
        auto* raw_udp = reinterpret_cast<udphdr*>(l4_data);
        if (raw_udp->check != 0) {
            raw_udp->check = 0;
            raw_udp->check = compute_udp_checksum(ipv4.iph, l4_data, payload_len);
        }
        udp->udph.check = raw_udp->check;
    } else if (icmp && payload_len >= sizeof(icmphdr)) {
        std::memcpy(l4_data, &icmp->icmph, sizeof(icmphdr));
        auto* raw_icmp = reinterpret_cast<icmphdr*>(l4_data);
        raw_icmp->checksum = 0;
        raw_icmp->checksum = compute_icmp_checksum(l4_data, payload_len);
        icmp->icmph.checksum = raw_icmp->checksum;
    }

    return true;
}

bool Worker::apply_outbound_dnat(FramePayload::Origin origin, Chain& chain, IPv4Header& ipv4,
                                 uint8_t* l3_data, size_t l3_len) {
    if (origin != FramePayload::Origin::Public) {
        return false;
    }

    const uint8_t protocol = ipv4.iph.protocol;
    uint32_t source_ip = ntohl(ipv4.iph.saddr);
    uint32_t dest_ip = ntohl(ipv4.iph.daddr);
    uint16_t source_port = 0;
    uint16_t dest_port = 0;

    auto* tcp = chain.get<TCPHeader>();
    auto* udp = chain.get<UDPHeader>();
    auto* icmp = chain.get<ICMPHeader>();

    if (tcp) {
        source_port = ntohs(tcp->tcph.source);
        dest_port = ntohs(tcp->tcph.dest);
    } else if (udp) {
        source_port = ntohs(udp->udph.source);
        dest_port = ntohs(udp->udph.dest);
    } else if (icmp) {
        source_port = ntohs(icmp->icmph.un.echo.id);
        dest_port = ntohs(icmp->icmph.un.echo.sequence);
    }

    auto lookup =
        dnat_table_.consume(source_ip, source_port, dest_ip, dest_port, protocol);
    if (!lookup) {
      LOG(DEBUG_NAT, "Worker", cfg_.thread_index,
          ": DNAT outbound no mapping for src=", IPv4Header::ip_to_string(source_ip), ":",
          source_port, " dst=", IPv4Header::ip_to_string(dest_ip), ":", dest_port,
          " protocol=", static_cast<int>(protocol));
       return false;
    }

    uint16_t ip_header_len = static_cast<uint16_t>(ipv4.iph.ihl) * 4u;
    uint16_t total_len = ntohs(ipv4.iph.tot_len);
    if (l3_len < total_len || total_len < ip_header_len) {
        LOG(DEBUG_ERROR, "Worker", cfg_.thread_index,
            ": DNAT outbound invalid lengths total=", total_len, " header=", ip_header_len,
            " l3_len=", l3_len);
        return false;
    }

    LOG(DEBUG_RELAY, "relay DNAT outbound thread=", cfg_.thread_index,
        " src_ip=", IPv4Header::ip_to_string(source_ip), ":", source_port,
        " restored_ip=", IPv4Header::ip_to_string(lookup->original_ip), ":", lookup->original_port,
        " remote_ip=", IPv4Header::ip_to_string(dest_ip), ":", dest_port,
        " protocol=", static_cast<int>(protocol));

    ipv4.iph.saddr = htonl(lookup->original_ip);
    ipv4.iph.check = checksum::recompute_ipv4_checksum(ipv4.iph);
    std::memcpy(l3_data, &ipv4.iph, ip_header_len);

    uint8_t* l4_data = l3_data + ip_header_len;
    uint16_t payload_len = static_cast<uint16_t>(total_len - ip_header_len);

    if (tcp && payload_len >= sizeof(tcphdr)) {
        tcp->tcph.source = htons(lookup->original_port);
        std::memcpy(l4_data, &tcp->tcph, sizeof(tcphdr));
        auto* raw_tcp = reinterpret_cast<tcphdr*>(l4_data);
        raw_tcp->check = 0;
        raw_tcp->check = compute_tcp_checksum(ipv4.iph, l4_data, payload_len);
        tcp->tcph.check = raw_tcp->check;
    } else if (udp && payload_len >= sizeof(udphdr)) {
        if (lookup->original_port != 0) {
            udp->udph.source = htons(lookup->original_port);
        }
        std::memcpy(l4_data, &udp->udph, sizeof(udphdr));
        auto* raw_udp = reinterpret_cast<udphdr*>(l4_data);
        if (raw_udp->check != 0) {
            raw_udp->check = 0;
            raw_udp->check = compute_udp_checksum(ipv4.iph, l4_data, payload_len);
        }
        udp->udph.check = raw_udp->check;
    } else if (icmp && payload_len >= sizeof(icmphdr)) {
        if (lookup->original_port != 0) {
            icmp->icmph.un.echo.id = htons(lookup->original_port);
        }
        std::memcpy(l4_data, &icmp->icmph, sizeof(icmphdr));
        auto* raw_icmp = reinterpret_cast<icmphdr*>(l4_data);
        raw_icmp->checksum = 0;
        raw_icmp->checksum = compute_icmp_checksum(l4_data, payload_len);
        icmp->icmph.checksum = raw_icmp->checksum;
    }

    return true;
}

void Worker::enqueue_tx(InterfaceContext& ctx, std::vector<uint8_t>&& frame, size_t net_offset,
                        const char* reason) {
    std::lock_guard<std::mutex> lock(ctx.tx_mutex);
    ctx.tx_queue.push_back({});
    ctx.tx_queue.back().buffer = std::move(frame);
    ctx.tx_queue.back().net_offset = net_offset;
    ctx.tx_queue.back().reason = reason;
    LOG(DEBUG_RELAY, "relay enqueue_tx thread=", cfg_.thread_index,
        " origin_ctx=", (&ctx == &priv_ctx_) ? "priv" : "pub", " reason=", reason,
        " bytes=", ctx.tx_queue.back().buffer.size(), " queue_size=", ctx.tx_queue.size());
    LOG(DEBUG_NAT, "Worker", cfg_.thread_index,
        ": enqueue TX frame bytes=", ctx.tx_queue.back().buffer.size(), " net_offset=", net_offset,
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
        " origin_ctx=", (&ctx == &priv_ctx_) ? "priv" : "pub", " frames=", frames.size());
    if (profile_enabled_) {
        profile_tx_frames_ += static_cast<uint64_t>(frames.size());
        for (const auto& frame : frames) {
            profile_tx_bytes_ += static_cast<uint64_t>(frame.buffer.size());
        }
    }

    if (!ctx.io) {
        return;
    }

    auto tx_view = ctx.io->tx_ring();
    int fd = ctx.io->socket().fd();

    auto send_frame = [&](const TxFrame& frame, const char* reason) {
        if (!ctx.io->send_frame(frame.buffer.data(), frame.buffer.size(), frame.net_offset,
                                reason)) {
            LOG(DEBUG_ERROR, "Worker", cfg_.thread_index, ": TX fallback failed reason=", reason,
                " frame_len=", frame.buffer.size());
        }
    };

    if (!tx_view.valid()) {
        LOG(DEBUG_IO, "Worker", cfg_.thread_index,
            ": TX ring not mapped origin=", (&ctx == &priv_ctx_) ? "priv" : "pub", " fallback for ",
            frames.size(), " frames");
        for (auto& frame : frames) {
            send_frame(frame, frame.reason);
        }
        if (profile_enabled_) {
            profile_tx_fallback_frames_ += static_cast<uint64_t>(frames.size());
        }
        return;
    }

    size_t frame_count = tx_view.frame_count();
    if (frame_count == 0) {
        LOG(DEBUG_IO, "Worker", cfg_.thread_index,
            ": TX ring empty origin=", (&ctx == &priv_ctx_) ? "priv" : "pub", " fallback for ",
            frames.size(), " frames");
        for (auto& frame : frames) {
            send_frame(frame, frame.reason);
        }
        if (profile_enabled_) {
            profile_tx_fallback_frames_ += static_cast<uint64_t>(frames.size());
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
                std::memcpy(reinterpret_cast<uint8_t*>(hdr) + hdr_size, frame.buffer.data(),
                            copy_len);
                hdr->tp_len = copy_len;
                hdr->tp_snaplen = copy_len;
                hdr->tp_status = TP_STATUS_SEND_REQUEST;
                ctx.tx_ring_index = idx + 1;
                written = true;
                LOG(DEBUG_NAT, "Worker", cfg_.thread_index, ": TX via ring idx=", idx,
                    " bytes=", copy_len);
                break;
            } else {
                ::sendto(fd, nullptr, 0, 0, nullptr, 0);
                ctx.tx_ring_index = idx + 1;
            }
        }
        if (!written) {
            send_frame(frame, frame.reason);
            if (profile_enabled_) {
                ++profile_tx_fallback_frames_;
            }
        }
    }
    ::sendto(fd, nullptr, 0, 0, nullptr, 0);
    LOG(DEBUG_NAT, "Worker", cfg_.thread_index, ": TX batch complete");
}

void Worker::process_remote_frames() {
    RemoteNode* list = pop_all_remote_nodes();
    if (!list) {
        return;
    }

    // Producers push to stack; reverse once to preserve FIFO-ish processing order.
    RemoteNode* rev = nullptr;
    uint32_t count = 0;
    while (list) {
        RemoteNode* next = list->next;
        list->next = rev;
        rev = list;
        list = next;
        ++count;
    }
    remote_size_.fetch_sub(count, std::memory_order_relaxed);
    if (profile_enabled_) {
        ++profile_remote_batches_;
        profile_remote_frames_ += static_cast<uint64_t>(count);
    }

    while (rev) {
        RemoteNode* next = rev->next;
        handle_forwarded(std::move(rev->payload));
        recycle_remote_node(rev);
        rev = next;
    }
}

void Worker::maybe_dump_profile(bool force) {
    if (!profile_enabled_) {
        return;
    }
    const auto now = std::chrono::steady_clock::now();
    const auto elapsed_since_last = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - profile_last_dump_at_);
    if (!force && elapsed_since_last.count() < static_cast<long long>(profile_interval_ms_)) {
        return;
    }
    const auto elapsed_total_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(now - profile_started_at_).count();
    if (elapsed_total_ns <= 0) {
        return;
    }

    const double elapsed_s = static_cast<double>(elapsed_total_ns) / 1e9;
    const double rx_mpps = static_cast<double>(profile_rx_packets_) / elapsed_s / 1e6;
    const double tx_mbps = (static_cast<double>(profile_tx_bytes_) * 8.0) / elapsed_s / 1e6;
    const double parse_avg_us = profile_parse_calls_ == 0
                                    ? 0.0
                                    : (static_cast<double>(profile_parse_ns_) /
                                       static_cast<double>(profile_parse_calls_)) /
                                          1000.0;
    const double chain_avg_us = profile_chain_calls_ == 0
                                    ? 0.0
                                    : (static_cast<double>(profile_chain_ns_) /
                                       static_cast<double>(profile_chain_calls_)) /
                                          1000.0;

    LOG(DEBUG_RELAY, "profile thread=", cfg_.thread_index, " uptime_s=", elapsed_s,
        " loops=", profile_loops_, " epoll_wait=", profile_epoll_wait_calls_,
        " epoll_ready=", profile_epoll_ready_events_, " epoll_timeouts=", profile_epoll_timeouts_,
        " rx_packets=", profile_rx_packets_, " rx_mpps=", rx_mpps, " tx_frames=", profile_tx_frames_,
        " tx_mbps=", tx_mbps, " tx_fallback=", profile_tx_fallback_frames_,
        " parse_calls=", profile_parse_calls_, " parse_fail=", profile_parse_fail_,
        " parse_avg_us=", parse_avg_us, " chain_calls=", profile_chain_calls_,
        " chain_avg_us=", chain_avg_us, " fwd_local=", profile_forward_local_,
        " fwd_remote=", profile_forward_remote_, " remote_batches=", profile_remote_batches_,
        " remote_frames=", profile_remote_frames_, " remote_q=", remote_size_.load());

    profile_last_dump_at_ = now;
}

void Worker::submit_remote_frame(FramePayload&& frame) {
    RemoteNode* node = acquire_remote_node();
    node->payload = std::move(frame);
    RemoteNode* head = remote_head_.load(std::memory_order_relaxed);
    do {
        node->next = head;
    } while (!remote_head_.compare_exchange_weak(head, node, std::memory_order_release,
                                                 std::memory_order_relaxed));
    uint32_t q = remote_size_.fetch_add(1, std::memory_order_relaxed) + 1;
    if (remote_event_fd_ >= 0) {
        const uint64_t one = 1;
        if (::write(remote_event_fd_, &one, sizeof(one)) < 0 && errno != EAGAIN) {
            LOG(DEBUG_ERROR, "Worker", cfg_.thread_index,
                ": eventfd write failed errno=", errno);
        }
    }
    LOG(DEBUG_RELAY, "relay submit_remote thread=", cfg_.thread_index,
        " queue_size=", q);
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
        " target=", interface_kind_to_string(kind), " bytes=", frame.size(),
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
    size_t l3_len = len > net_offset ? len - net_offset : 0;

    chain.for_each([&](auto& hdr) { nat_.process(hdr); });

    if (has_flag(decision.actions, filters::ActionFlag::Dnat) &&
        origin == FramePayload::Origin::Public) {
        if (auto* ipv4_after_nat = chain.get<IPv4Header>()) {
            apply_outbound_dnat(origin, chain, *ipv4_after_nat, l3_data, l3_len);
        }
    }
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
        " icmp_id=", log_icmp_id, " via=", (dest_ctx == &pub_ctx_ ? "pub" : "priv"));

    std::vector<uint8_t> tx_buffer(data, data + len);
    bool shaped = has_flag(decision.actions, filters::ActionFlag::Shape) && decision.shape_rate > 0;
    if (shaped && shape_controller_) {
        auto target = (dest_ctx == &pub_ctx_) ? shape::ShapeController::Target::Public
                                              : shape::ShapeController::Target::Private;
        LOG(DEBUG_RELAY, "relay shape enqueue thread=", cfg_.thread_index,
            " target=", (dest_ctx == &pub_ctx_ ? "pub" : "priv"), " rate=", decision.shape_rate,
            " bytes=", tx_buffer.size());
        shape_controller_->enqueue(target, std::move(tx_buffer), net_offset, decision.shape_rate);
    } else {
        LOG(DEBUG_RELAY, "relay direct enqueue thread=", cfg_.thread_index,
            " target=", (dest_ctx == &pub_ctx_ ? "pub" : "priv"), " bytes=", tx_buffer.size());
        enqueue_tx(*dest_ctx, std::move(tx_buffer), net_offset, "direct");
    }
}
