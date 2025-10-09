#include "nat.h"

#include "logger.h"
#include "../acct/snat_tracker.hpp"
#include "../include/ipv4.h"
#include <arpa/inet.h>
#include <netinet/in.h>

namespace {

constexpr uint64_t pack32(uint32_t hi, uint32_t lo) noexcept {
    return (static_cast<uint64_t>(hi) << 32) | lo;
}

size_t hash_mix(uint64_t value, uint64_t salt) noexcept {
    value ^= salt + 0x9e3779b97f4a7c15ULL + (value << 6) + (value >> 2);
    return static_cast<size_t>(value);
}

constexpr uint8_t proto_ip_only = 0; // используется для IP NAT без портов

std::string ip_to_string(uint32_t ip_host_order) {
    return IPv4Header::ip_to_string(htonl(ip_host_order));
}

} // namespace

bool Nat::FlowKey::operator==(const FlowKey& other) const noexcept {
    return prv_ip == other.prv_ip && dst_ip == other.dst_ip && src_port == other.src_port &&
           dst_port == other.dst_port && protocol == other.protocol;
}

bool Nat::PubKey::operator==(const PubKey& other) const noexcept {
    return pub_ip == other.pub_ip && dst_ip == other.dst_ip && pub_port == other.pub_port &&
           dst_port == other.dst_port && protocol == other.protocol;
}

size_t Nat::FlowKeyHash::operator()(const FlowKey& key) const noexcept {
    uint64_t part1 = pack32(key.prv_ip, key.dst_ip);
    uint64_t part2 = (static_cast<uint64_t>(key.src_port) << 16) | key.dst_port;
    return hash_mix(part1, part2 ^ key.protocol);
}

size_t Nat::PubKeyHash::operator()(const PubKey& key) const noexcept {
    uint64_t part1 = pack32(key.pub_ip, key.dst_ip);
    uint64_t part2 = (static_cast<uint64_t>(key.pub_port) << 16) | key.dst_port;
    return hash_mix(part1, part2 ^ key.protocol);
}

bool Nat::PrivateKey::operator==(const PrivateKey& other) const noexcept {
    return prv_ip == other.prv_ip && src_port == other.src_port && protocol == other.protocol;
}

bool Nat::PubOnlyKey::operator==(const PubOnlyKey& other) const noexcept {
    return pub_ip == other.pub_ip && pub_port == other.pub_port && protocol == other.protocol;
}

size_t Nat::PrivateKeyHash::operator()(const PrivateKey& key) const noexcept {
    uint64_t packed = pack32(key.prv_ip, static_cast<uint32_t>(key.src_port));
    return hash_mix(packed, key.protocol);
}

size_t Nat::PubOnlyKeyHash::operator()(const PubOnlyKey& key) const noexcept {
    uint64_t packed = pack32(key.pub_ip, static_cast<uint32_t>(key.pub_port));
    return hash_mix(packed, key.protocol);
}

Nat::Nat(const NatConfig& cfg, uint32_t thread_index, uint32_t thread_count)
    : EndpointBase(std::make_shared<NatConfig>(cfg), thread_count), ready_(config_->is_valid()),
      thread_index_(thread_index) {
    ip_table_.capacity = config_->ip_thread_capacity;
    tcp_table_.capacity = config_->tcp_thread_capacity;
    udp_table_.capacity = config_->udp_thread_capacity;
    icmp_table_.capacity = config_->icmp_thread_capacity;

    LOG(DEBUG_NAT, "Nat init thread=", static_cast<int>(thread_index_),
        " cfg_valid=", ready_, " cap(ip/tcp/udp/icmp)=",
        ip_table_.capacity, "/", tcp_table_.capacity, "/", udp_table_.capacity, "/",
        icmp_table_.capacity);
}

void Nat::maintenance() {
    LOG(DEBUG_NAT, "Nat maintenance thread=", static_cast<int>(thread_index_),
        " entries(ip/tcp/udp/icmp)=", ip_table_.forward.size(), "/",
        tcp_table_.forward.size(), "/", udp_table_.forward.size(), "/",
        icmp_table_.forward.size());
}

void Nat::maintenance(Clock::time_point) { maintenance(); }

bool Nat::is_private(uint32_t ip) const {
    return config_->private_netset && config_->private_netset->contains(ip);
}

bool Nat::is_public(uint32_t ip) const {
    return config_->public_netset && config_->public_netset->contains(ip);
}

Nat::Translation Nat::ensure_ip_mapping(uint32_t prv_ip, uint32_t dst_ip, uint8_t protocol) {
    auto static_trans = maybe_static_translation(prv_ip, dst_ip, 0, 0, protocol);
    if (static_trans.has_value()) {
        return static_trans.value();
    }

    FlowKey flow{prv_ip, dst_ip, 0, 0, protocol};
    auto it = ip_table_.forward.find(flow);
    if (it != ip_table_.forward.end()) {
        touch_entry(ip_table_, it->second);
        LOG(DEBUG_NAT, "Nat reuse IP mapping thread=", static_cast<int>(thread_index_),
            " prv=", ip_to_string(prv_ip), " -> pub=",
            ip_to_string(it->second.pub.pub_ip));
        return make_translation(it->second);
    }

    uint32_t pub_ip = map_ip(prv_ip, dst_ip, protocol, thread_index_);
    PubKey pub{pub_ip, dst_ip, 0, 0, protocol};
    MappingEntry& entry = insert_entry(ip_table_, flow, pub);
    LOG(DEBUG_NAT, "Nat new IP mapping thread=", static_cast<int>(thread_index_),
        " prv=", ip_to_string(prv_ip), " -> pub=", ip_to_string(pub_ip));
    return make_translation(entry);
}

uint32_t Nat::map_ip(uint32_t prv_ip, uint32_t dst_ip, uint8_t protocol,
                     uint32_t thread_index) const {
    (void)thread_index;
    auto tuple = std::make_tuple(htonl(prv_ip), htonl(dst_ip), static_cast<uint16_t>(0),
                                 static_cast<uint16_t>(0), protocol);
    uint32_t hash = CPUFanoutHash::hash_tuple(tuple);
    return select_public_ip(hash);
}

Nat::Translation Nat::ensure_tcp_mapping(uint32_t prv_ip, uint32_t dst_ip, uint16_t src_port,
                                         uint16_t dst_port) {
    if (auto stat = maybe_static_translation(prv_ip, dst_ip, src_port, dst_port, IPPROTO_TCP)) {
        return *stat;
    }

    FlowKey flow{prv_ip, dst_ip, src_port, dst_port, static_cast<uint8_t>(IPPROTO_TCP)};
    auto it = tcp_table_.forward.find(flow);
    if (it != tcp_table_.forward.end()) {
        touch_entry(tcp_table_, it->second);
        LOG(DEBUG_NAT, "Nat reuse TCP mapping thread=", static_cast<int>(thread_index_),
            " prv=", ip_to_string(prv_ip), ":", src_port, " -> pub=",
            ip_to_string(it->second.pub.pub_ip), ":", it->second.pub.pub_port);
        return make_translation(it->second);
    }

    auto [pub_ip, pub_port] =
        map_tcp_udp(prv_ip, dst_ip, src_port, dst_port, IPPROTO_TCP, config_->tcp_port_min,
                    config_->tcp_port_max);
    PubKey pub{pub_ip, dst_ip, pub_port, dst_port, static_cast<uint8_t>(IPPROTO_TCP)};
    MappingEntry& entry = insert_entry(tcp_table_, flow, pub);
    accounting::SnatTracker::instance().observe_tcp(prv_ip, pub_ip, pub_port);
    LOG(DEBUG_NAT, "Nat new TCP mapping thread=", static_cast<int>(thread_index_),
        " prv=", ip_to_string(prv_ip), ":", src_port, " -> pub=",
        ip_to_string(pub_ip), ":", pub_port);
    return make_translation(entry);
}

Nat::Translation Nat::ensure_udp_mapping(uint32_t prv_ip, uint32_t dst_ip, uint16_t src_port,
                                         uint16_t dst_port) {
    if (auto stat = maybe_static_translation(prv_ip, dst_ip, src_port, dst_port, IPPROTO_UDP)) {
        return *stat;
    }

    FlowKey flow{prv_ip, dst_ip, src_port, dst_port, static_cast<uint8_t>(IPPROTO_UDP)};
    auto it = udp_table_.forward.find(flow);
    if (it != udp_table_.forward.end()) {
        touch_entry(udp_table_, it->second);
        LOG(DEBUG_NAT, "Nat reuse UDP mapping thread=", static_cast<int>(thread_index_),
            " prv=", ip_to_string(prv_ip), ":", src_port, " -> pub=",
            ip_to_string(it->second.pub.pub_ip), ":", it->second.pub.pub_port);
        return make_translation(it->second);
    }

    auto [pub_ip, pub_port] =
        map_tcp_udp(prv_ip, dst_ip, src_port, dst_port, IPPROTO_UDP, config_->udp_port_min,
                    config_->udp_port_max);
    PubKey pub{pub_ip, dst_ip, pub_port, dst_port, static_cast<uint8_t>(IPPROTO_UDP)};
    MappingEntry& entry = insert_entry(udp_table_, flow, pub);
    accounting::SnatTracker::instance().observe_udp(prv_ip, pub_ip, pub_port);
    LOG(DEBUG_NAT, "Nat new UDP mapping thread=", static_cast<int>(thread_index_),
        " prv=", ip_to_string(prv_ip), ":", src_port, " -> pub=",
        ip_to_string(pub_ip), ":", pub_port);
    return make_translation(entry);
}

Nat::Translation Nat::ensure_icmp_mapping(uint32_t prv_ip, uint32_t dst_ip, uint16_t ident,
                                          uint16_t seq) {
    if (auto stat = maybe_static_translation(prv_ip, dst_ip, ident, seq, IPPROTO_ICMP)) {
        return *stat;
    }

    FlowKey flow{prv_ip, dst_ip, ident, seq, static_cast<uint8_t>(IPPROTO_ICMP)};
    auto it = icmp_table_.forward.find(flow);
    if (it != icmp_table_.forward.end()) {
        touch_entry(icmp_table_, it->second);
        LOG(DEBUG_NAT, "Nat reuse ICMP mapping thread=", static_cast<int>(thread_index_),
            " prv=", ip_to_string(prv_ip), " id=", ident, " -> pub=",
            ip_to_string(it->second.pub.pub_ip),
            " new_id=", it->second.pub.pub_port);
        return make_translation(it->second);
    }

    auto [pub_ip, new_id] = map_icmp(prv_ip, dst_ip, ident, seq);
    PubKey pub{pub_ip, dst_ip, new_id, seq, static_cast<uint8_t>(IPPROTO_ICMP)};
    MappingEntry& entry = insert_entry(icmp_table_, flow, pub);
    accounting::SnatTracker::instance().observe_icmp(prv_ip, pub_ip, new_id);
    LOG(DEBUG_NAT, "Nat new ICMP mapping thread=", static_cast<int>(thread_index_),
        " prv=", ip_to_string(prv_ip), " id=", ident, " -> pub=",
        ip_to_string(pub_ip), " new_id=", new_id);
    return make_translation(entry);
}

std::optional<Nat::Translation> Nat::find_ip_reply(uint32_t pub_ip, uint32_t remote_ip,
                                                   uint8_t protocol) {
    if (auto stat = maybe_static_inbound(pub_ip, remote_ip, 0, 0, proto_ip_only)) {
        return stat;
    }

    PubKey key{pub_ip, remote_ip, 0, 0, protocol};
    return find_inbound(ip_table_, key);
}

std::optional<Nat::Translation> Nat::find_tcp_reply(uint32_t pub_ip, uint32_t remote_ip,
                                                    uint16_t pub_port, uint16_t remote_port) {
    if (auto stat = maybe_static_inbound(pub_ip, remote_ip, pub_port, remote_port,
                                         IPPROTO_TCP)) {
        return stat;
    }

    PubKey key{pub_ip, remote_ip, pub_port, remote_port, static_cast<uint8_t>(IPPROTO_TCP)};
    return find_inbound(tcp_table_, key);
}

std::optional<Nat::Translation> Nat::find_udp_reply(uint32_t pub_ip, uint32_t remote_ip,
                                                    uint16_t pub_port, uint16_t remote_port) {
    if (auto stat = maybe_static_inbound(pub_ip, remote_ip, pub_port, remote_port,
                                         IPPROTO_UDP)) {
        return stat;
    }

    PubKey key{pub_ip, remote_ip, pub_port, remote_port, static_cast<uint8_t>(IPPROTO_UDP)};
    return find_inbound(udp_table_, key);
}

std::optional<Nat::Translation> Nat::find_icmp_reply(uint32_t pub_ip, uint32_t remote_ip,
                                                     uint16_t pub_id, uint16_t remote_seq) {
    if (auto stat = maybe_static_inbound(pub_ip, remote_ip, pub_id, remote_seq,
                                         IPPROTO_ICMP)) {
        return stat;
    }

    PubKey key{pub_ip, remote_ip, pub_id, remote_seq, static_cast<uint8_t>(IPPROTO_ICMP)};
    return find_inbound(icmp_table_, key);
}

std::optional<uint32_t> Nat::resolve_private(uint32_t pub_ip, uint32_t remote_ip,
                                             uint16_t pub_port, uint16_t remote_port,
                                             uint8_t protocol) {
    std::optional<Translation> translation;
    switch (protocol) {
    case IPPROTO_TCP:
        translation = find_tcp_reply(pub_ip, remote_ip, pub_port, remote_port);
        break;
    case IPPROTO_UDP:
        translation = find_udp_reply(pub_ip, remote_ip, pub_port, remote_port);
        break;
    case IPPROTO_ICMP:
        translation = find_icmp_reply(pub_ip, remote_ip, pub_port, remote_port);
        break;
    default:
        translation = find_ip_reply(pub_ip, remote_ip, protocol);
        break;
    }
    if (translation) {
        return translation->flow.prv_ip;
    }
    return std::nullopt;
}

std::optional<Nat::Translation> Nat::lookup_tcp_outbound(uint32_t prv_ip, uint32_t dst_ip,
                                                         uint16_t src_port, uint16_t dst_port) {
    FlowKey flow{prv_ip, dst_ip, src_port, dst_port, static_cast<uint8_t>(IPPROTO_TCP)};
    auto it = tcp_table_.forward.find(flow);
    if (it == tcp_table_.forward.end()) {
        return std::nullopt;
    }
    touch_entry(tcp_table_, it->second);
    return make_translation(it->second);
}

std::optional<Nat::Translation> Nat::lookup_udp_outbound(uint32_t prv_ip, uint32_t dst_ip,
                                                         uint16_t src_port, uint16_t dst_port) {
    FlowKey flow{prv_ip, dst_ip, src_port, dst_port, static_cast<uint8_t>(IPPROTO_UDP)};
    auto it = udp_table_.forward.find(flow);
    if (it == udp_table_.forward.end()) {
        return std::nullopt;
    }
    touch_entry(udp_table_, it->second);
    return make_translation(it->second);
}

std::optional<Nat::Translation> Nat::lookup_icmp_outbound(uint32_t prv_ip, uint32_t dst_ip,
                                                          uint16_t ident, uint16_t seq) {
    FlowKey flow{prv_ip, dst_ip, ident, seq, static_cast<uint8_t>(IPPROTO_ICMP)};
    auto it = icmp_table_.forward.find(flow);
    if (it == icmp_table_.forward.end()) {
        return std::nullopt;
    }
    touch_entry(icmp_table_, it->second);
    return make_translation(it->second);
}

std::optional<Nat::Translation> Nat::find_static_outbound(uint32_t prv_ip, uint32_t dst_ip,
                                                          uint16_t src_port, uint16_t dst_port,
                                                          uint8_t protocol) const {
    return maybe_static_translation(prv_ip, dst_ip, src_port, dst_port, protocol);
}

std::optional<Nat::Translation> Nat::maybe_static_translation(uint32_t prv_ip, uint32_t dst_ip,
                                                              uint16_t src_port, uint16_t dst_port,
                                                              uint8_t protocol) const {
    PrivateKey key{prv_ip, src_port, protocol};
    auto it = static_forward_.find(key);
    if (it == static_forward_.end() && protocol != proto_ip_only) {
        key.protocol = proto_ip_only;
        it = static_forward_.find(key);
    }
    if (it == static_forward_.end()) {
        return std::nullopt;
    }

    const PubOnlyKey& pub_key = it->second;
    PubKey pub{pub_key.pub_ip, dst_ip, pub_key.pub_port, dst_port, protocol};
    FlowKey flow{prv_ip, dst_ip, src_port, dst_port, protocol};
    LOG(DEBUG_NAT, "Nat static mapping outbound thread=", static_cast<int>(thread_index_),
        " prv=", ip_to_string(prv_ip), ":", src_port, " -> pub=",
        ip_to_string(pub_key.pub_ip), ":", pub_key.pub_port);
    return Translation{flow, pub, thread_index_};
}

std::optional<Nat::Translation> Nat::maybe_static_inbound(uint32_t pub_ip, uint32_t remote_ip,
                                                          uint16_t pub_port, uint16_t remote_port,
                                                          uint8_t protocol) const {
    PubOnlyKey key{pub_ip, pub_port, protocol};
    auto it = static_reverse_.find(key);
    if (it == static_reverse_.end() && protocol != proto_ip_only) {
        key.protocol = proto_ip_only;
        it = static_reverse_.find(key);
    }
    if (it == static_reverse_.end()) {
        return std::nullopt;
    }

    const PrivateKey& priv = it->second;
    FlowKey flow{priv.prv_ip, remote_ip, priv.src_port, remote_port, protocol};
    PubKey pub{pub_ip, remote_ip, pub_port, remote_port, protocol};
    LOG(DEBUG_NAT, "Nat static mapping inbound thread=", static_cast<int>(thread_index_),
        " pub=", ip_to_string(pub_ip), ":", pub_port, " -> prv=",
        ip_to_string(priv.prv_ip), ":", priv.src_port);
    return Translation{flow, pub, thread_index_};
}

Nat::Translation Nat::make_translation(const MappingEntry& entry) const {
    return Translation{entry.flow, entry.pub, entry.owner_thread};
}

std::optional<Nat::Translation> Nat::find_inbound(MappingTable& table, const PubKey& key) {
    auto rev_it = table.reverse.find(key);
    if (rev_it == table.reverse.end()) {
        LOG(DEBUG_NAT, "Nat inbound miss thread=", static_cast<int>(thread_index_),
            " pub=", ip_to_string(key.pub_ip), ":", key.pub_port);
        return std::nullopt;
    }

    auto fwd_it = table.forward.find(rev_it->second);
    if (fwd_it == table.forward.end()) {
        table.reverse.erase(rev_it);
        LOG(DEBUG_NAT, "Nat stale inbound mapping thread=", static_cast<int>(thread_index_),
            " pub=", ip_to_string(key.pub_ip), ":", key.pub_port);
        return std::nullopt;
    }

    touch_entry(table, fwd_it->second);
    LOG(DEBUG_NAT, "Nat inbound hit thread=", static_cast<int>(thread_index_),
        " pub=", ip_to_string(key.pub_ip), ":", key.pub_port, " -> prv=",
        ip_to_string(fwd_it->second.flow.prv_ip), ":", fwd_it->second.flow.src_port);
    return make_translation(fwd_it->second);
}

void Nat::touch_entry(MappingTable& table, MappingEntry& entry) {
    table.order.splice(table.order.end(), table.order, entry.order_it);
    entry.order_it = std::prev(table.order.end());
}

void Nat::evict_if_needed(MappingTable& table) {
    if (table.capacity == 0 || table.forward.size() < table.capacity) {
        return;
    }
    if (table.order.empty()) {
        return;
    }

    const FlowKey victim_key = table.order.front();
    table.order.pop_front();
    auto it = table.forward.find(victim_key);
    if (it != table.forward.end()) {
        LOG(DEBUG_NAT, "Nat evict mapping thread=", static_cast<int>(thread_index_),
            " prv=", ip_to_string(it->second.flow.prv_ip), ":", it->second.flow.src_port,
            " pub=", ip_to_string(it->second.pub.pub_ip), ":", it->second.pub.pub_port);
        table.reverse.erase(it->second.pub);
        table.forward.erase(it);
    }
}

Nat::MappingEntry& Nat::insert_entry(MappingTable& table, FlowKey flow, PubKey pub) {
    evict_if_needed(table);

    auto [fwd_it, inserted] = table.forward.emplace(flow, MappingEntry{});
    if (!inserted) {
        table.order.erase(fwd_it->second.order_it);
    }

    table.order.push_back(flow);
    fwd_it->second.flow = flow;
    fwd_it->second.pub = pub;
    fwd_it->second.owner_thread = thread_index_;
    fwd_it->second.order_it = std::prev(table.order.end());

    table.reverse[pub] = flow;
    return fwd_it->second;
}

void Nat::add_static_mapping(uint32_t prv_ip, uint16_t private_port, uint8_t protocol,
                             uint32_t pub_ip, uint16_t public_port) {
    PrivateKey priv{prv_ip, private_port, protocol};
    PubOnlyKey pub{pub_ip, public_port, protocol};
    // Если уже существовала привязка к этому публичному адресу, очищаем её.
    for (auto it = static_forward_.begin(); it != static_forward_.end();) {
        if (it->second.pub_ip == pub.pub_ip && it->second.pub_port == pub.pub_port &&
            it->second.protocol == pub.protocol && it->first.prv_ip != priv.prv_ip) {
            it = static_forward_.erase(it);
        } else {
            ++it;
        }
    }

    for (auto it = static_reverse_.begin(); it != static_reverse_.end();) {
        if (it->first.pub_ip == pub.pub_ip && it->first.pub_port == pub.pub_port &&
            it->first.protocol == pub.protocol) {
            it = static_reverse_.erase(it);
        } else {
            ++it;
        }
    }

    static_forward_[priv] = pub;
    static_reverse_[pub] = priv;
    LOG(DEBUG_NAT, "Nat add static mapping thread=", static_cast<int>(thread_index_),
        " prv=", ip_to_string(prv_ip), ":", private_port, " -> pub=",
        ip_to_string(pub_ip), ":", public_port,
        " proto=", static_cast<int>(protocol));
}

void Nat::add_static_tcp_mapping(uint32_t prv_ip, uint16_t private_port, uint32_t pub_ip,
                                 uint16_t public_port) {
    add_static_mapping(prv_ip, private_port, IPPROTO_TCP, pub_ip, public_port);
}

void Nat::add_static_udp_mapping(uint32_t prv_ip, uint16_t private_port, uint32_t pub_ip,
                                 uint16_t public_port) {
    add_static_mapping(prv_ip, private_port, IPPROTO_UDP, pub_ip, public_port);
}

void Nat::add_static_icmp_mapping(uint32_t prv_ip, uint16_t private_id, uint32_t pub_ip,
                                  uint16_t public_id) {
    add_static_mapping(prv_ip, private_id, IPPROTO_ICMP, pub_ip, public_id);
}

void Nat::add_static_ip_mapping(uint32_t prv_ip, uint32_t pub_ip) {
    add_static_mapping(prv_ip, 0, proto_ip_only, pub_ip, 0);
}

void Nat::clear_static_mappings() {
    static_forward_.clear();
    static_reverse_.clear();
    LOG(DEBUG_NAT, "Nat cleared static mappings thread=", static_cast<int>(thread_index_));
}
