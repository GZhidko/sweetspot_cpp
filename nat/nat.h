#pragma once

#include "endpoint_base.hpp"
#include "nat_config.hpp"
#include "../include/forward_dec.h"

#include <chrono>
#include <cstdint>
#include <list>
#include <optional>
#include <unordered_map>

class Nat : public EndpointBase {
  public:
    using Clock = std::chrono::steady_clock;

    struct FlowKey {
        uint32_t prv_ip = 0;
        uint32_t dst_ip = 0;
        uint16_t src_port = 0;
        uint16_t dst_port = 0;
        uint8_t protocol = 0;

        bool operator==(const FlowKey& other) const noexcept;
    };

    struct PubKey {
        uint32_t pub_ip = 0;
        uint32_t dst_ip = 0;
        uint16_t pub_port = 0;
        uint16_t dst_port = 0;
        uint8_t protocol = 0;

        bool operator==(const PubKey& other) const noexcept;
    };

    struct FlowKeyHash {
        size_t operator()(const FlowKey& key) const noexcept;
    };

    struct PubKeyHash {
        size_t operator()(const PubKey& key) const noexcept;
    };

    struct Translation {
        FlowKey flow;
        PubKey pub;
        uint32_t owner_thread = 0;
    };

    Nat(const NatConfig& cfg, uint32_t thread_index = 0, uint32_t thread_count = 1);

    bool configured() const noexcept { return ready_; }
    uint32_t thread_index() const noexcept { return thread_index_; }

    void process(IPv4Header& ip);
    void process(IPv4Header& ip, Clock::time_point now);

    void process(TCPHeader& tcp);
    void process(TCPHeader& tcp, Clock::time_point now);

    void process(UDPHeader& udp);
    void process(UDPHeader& udp, Clock::time_point now);

    void process(ICMPHeader& icmp);
    void process(ICMPHeader& icmp, Clock::time_point now);

    std::optional<Translation> find_ip_reply(uint32_t pub_ip, uint32_t remote_ip,
                                             uint8_t protocol);
    std::optional<Translation> find_tcp_reply(uint32_t pub_ip, uint32_t remote_ip,
                                              uint16_t pub_port, uint16_t remote_port);
    std::optional<Translation> find_udp_reply(uint32_t pub_ip, uint32_t remote_ip,
                                              uint16_t pub_port, uint16_t remote_port);
    std::optional<Translation> find_icmp_reply(uint32_t pub_ip, uint32_t remote_ip,
                                               uint16_t pub_id, uint16_t remote_seq);
    std::optional<Translation> lookup_tcp_outbound(uint32_t prv_ip, uint32_t dst_ip,
                                                   uint16_t src_port, uint16_t dst_port);
    std::optional<Translation> lookup_udp_outbound(uint32_t prv_ip, uint32_t dst_ip,
                                                   uint16_t src_port, uint16_t dst_port);
    std::optional<Translation> lookup_icmp_outbound(uint32_t prv_ip, uint32_t dst_ip,
                                                    uint16_t ident, uint16_t seq);

    std::optional<uint32_t> resolve_private(uint32_t pub_ip, uint32_t remote_ip,
                                            uint16_t pub_port, uint16_t remote_port,
                                            uint8_t protocol);

    void maintenance();
    void maintenance(Clock::time_point now);

  private:
    struct MappingEntry {
        FlowKey flow;
        PubKey pub;
        uint32_t owner_thread = 0;
        std::list<FlowKey>::iterator order_it;
    };

    struct MappingTable {
        std::unordered_map<FlowKey, MappingEntry, FlowKeyHash> forward;
        std::unordered_map<PubKey, FlowKey, PubKeyHash> reverse;
        std::list<FlowKey> order;
        uint32_t capacity = 0;
    };

    bool is_private(uint32_t ip) const;
    bool is_public(uint32_t ip) const;

    Translation ensure_ip_mapping(uint32_t prv_ip, uint32_t dst_ip, uint8_t protocol);
    Translation ensure_tcp_mapping(uint32_t prv_ip, uint32_t dst_ip, uint16_t src_port,
                                   uint16_t dst_port);
    Translation ensure_udp_mapping(uint32_t prv_ip, uint32_t dst_ip, uint16_t src_port,
                                   uint16_t dst_port);
    Translation ensure_icmp_mapping(uint32_t prv_ip, uint32_t dst_ip, uint16_t ident,
                                    uint16_t seq);

    uint32_t map_ip(uint32_t prv_ip, uint32_t dst_ip, uint8_t protocol,
                    uint32_t thread_index) const;

    Translation make_translation(const MappingEntry& entry) const;
    std::optional<Translation> find_inbound(MappingTable& table, const PubKey& key);
    void touch_entry(MappingTable& table, MappingEntry& entry);
    void evict_if_needed(MappingTable& table);
    MappingEntry& insert_entry(MappingTable& table, FlowKey flow, PubKey pub);

    bool ready_ = false;
    uint32_t thread_index_ = 0;
    MappingTable ip_table_{};
    MappingTable tcp_table_{};
    MappingTable udp_table_{};
    MappingTable icmp_table_{};
};

namespace std {

template <> struct hash<Nat::FlowKey> {
    size_t operator()(const Nat::FlowKey& key) const noexcept {
        return Nat::FlowKeyHash{}(key);
    }
};

template <> struct hash<Nat::PubKey> {
    size_t operator()(const Nat::PubKey& key) const noexcept {
        return Nat::PubKeyHash{}(key);
    }
};

} // namespace std
