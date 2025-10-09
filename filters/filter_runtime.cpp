#include "filter_runtime.hpp"

#include "filter_engine.hpp"
#include "../common/logger.h"
#include "../include/icmp.h"
#include "../include/ipv4.h"
#include "../include/tcp.h"
#include "../include/udp.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>

namespace filters {
namespace {
struct ThreadState {
    PacketState state;
    bool active = false;
    Decision decision;
    std::string filter_name;
};

thread_local ThreadState g_state;

const char* direction_to_string(Direction dir) {
    return dir == Direction::Inbound ? "in" : "out";
}

bool evaluate_now() {
    if (g_state.filter_name.empty()) {
        g_state.filter_name = Engine::instance().default_filter_name();
    }
    g_state.decision = Engine::instance().evaluate(g_state.state, g_state.filter_name);
    return g_state.decision.allow;
}

bool ensure_active() {
    if (!g_state.active) {
        begin_packet(Direction::Outbound);
    }
    return true;
}

} // namespace

ScopedPacket::ScopedPacket(Direction dir) { begin_packet(dir); }
ScopedPacket::~ScopedPacket() { end_packet(); }

void begin_packet(Direction dir) {
    g_state.active = true;
    g_state.decision = Decision{};
    g_state.state = PacketState{};
    g_state.state.direction = dir;
    if (g_state.filter_name.empty()) {
        g_state.filter_name = Engine::instance().default_filter_name();
    }
    LOG(DEBUG_FILTER, "filter runtime begin dir=", direction_to_string(dir),
        " current_filter=", g_state.filter_name);
}

void end_packet() {
    LOG(DEBUG_FILTER, "filter runtime end dir=", direction_to_string(g_state.state.direction),
        " allow=", g_state.decision.allow, " matched=", g_state.decision.matched,
        " rule=", g_state.decision.rule_index, " actions=",
        static_cast<int>(g_state.decision.actions));
    g_state.active = false;
}

bool apply_ipv4(const IPv4Header& ip) {
    ensure_active();
    g_state.state.has_ipv4 = true;
    g_state.state.src_ip = ntohl(ip.iph.saddr);
    g_state.state.dst_ip = ntohl(ip.iph.daddr);
    g_state.state.protocol = ip.iph.protocol;
    g_state.state.has_l4 = false;
    g_state.state.tcp_flags_valid = false;
    LOG(DEBUG_FILTER, "filter runtime ipv4 src=", IPv4Header::ip_to_string(g_state.state.src_ip),
        " dst=", IPv4Header::ip_to_string(g_state.state.dst_ip),
        " proto=", static_cast<int>(g_state.state.protocol));
    return evaluate_now();
}

bool apply_tcp(const TCPHeader& tcp) {
    ensure_active();
    g_state.state.has_l4 = true;
    g_state.state.src_port = ntohs(tcp.tcph.source);
    g_state.state.dst_port = ntohs(tcp.tcph.dest);
    g_state.state.protocol = IPPROTO_TCP;
    g_state.state.tcp_flags_valid = true;
    uint8_t flags = 0;
    flags |= tcp.tcph.fin ? 0x01 : 0;
    flags |= tcp.tcph.syn ? 0x02 : 0;
    flags |= tcp.tcph.rst ? 0x04 : 0;
    flags |= tcp.tcph.psh ? 0x08 : 0;
    flags |= tcp.tcph.ack ? 0x10 : 0;
    flags |= tcp.tcph.urg ? 0x20 : 0;
    g_state.state.tcp_flags = flags;
    g_state.state.src_ip = ntohl(tcp.ip_header->iph.saddr);
    g_state.state.dst_ip = ntohl(tcp.ip_header->iph.daddr);
    g_state.state.has_ipv4 = true;
    LOG(DEBUG_FILTER, "filter runtime tcp src=", IPv4Header::ip_to_string(g_state.state.src_ip),
        ":", g_state.state.src_port, " dst=",
        IPv4Header::ip_to_string(g_state.state.dst_ip), ":", g_state.state.dst_port,
        " flags=0x", std::hex, static_cast<int>(g_state.state.tcp_flags), std::dec);
    return evaluate_now();
}

bool apply_udp(const UDPHeader& udp) {
    ensure_active();
    g_state.state.has_l4 = true;
    g_state.state.src_port = ntohs(udp.udph.source);
    g_state.state.dst_port = ntohs(udp.udph.dest);
    g_state.state.protocol = IPPROTO_UDP;
    g_state.state.src_ip = ntohl(udp.ip_header->iph.saddr);
    g_state.state.dst_ip = ntohl(udp.ip_header->iph.daddr);
    g_state.state.has_ipv4 = true;
    g_state.state.tcp_flags_valid = false;
    LOG(DEBUG_FILTER, "filter runtime udp src=", IPv4Header::ip_to_string(g_state.state.src_ip),
        ":", g_state.state.src_port, " dst=",
        IPv4Header::ip_to_string(g_state.state.dst_ip), ":", g_state.state.dst_port);
    return evaluate_now();
}

bool apply_icmp(const ICMPHeader& icmp) {
    ensure_active();
    g_state.state.protocol = IPPROTO_ICMP;
    g_state.state.src_ip = ntohl(icmp.ip_header->iph.saddr);
    g_state.state.dst_ip = ntohl(icmp.ip_header->iph.daddr);
    g_state.state.has_ipv4 = true;
    g_state.state.has_l4 = false;
    g_state.state.tcp_flags_valid = false;
    LOG(DEBUG_FILTER, "filter runtime icmp src=", IPv4Header::ip_to_string(g_state.state.src_ip),
        " dst=", IPv4Header::ip_to_string(g_state.state.dst_ip),
        " type=", static_cast<int>(icmp.icmph.type),
        " code=", static_cast<int>(icmp.icmph.code));
    return evaluate_now();
}

void set_filter_path(const std::string& path) {
    LOG(DEBUG_FILTER, "filter runtime set_path path=", path);
    Engine::instance().set_config_path(path);
}

void reload_filters() {
    LOG(DEBUG_FILTER, "filter runtime reload request");
    Engine::instance().reload();
}

const Decision& current_decision() {
    LOG(DEBUG_FILTER, "filter runtime decision allow=", g_state.decision.allow,
        " matched=", g_state.decision.matched, " rule=", g_state.decision.rule_index);
    return g_state.decision;
}

void set_current_filter(const std::string& name) {
    LOG(DEBUG_FILTER, "filter runtime set_current_filter old=", g_state.filter_name,
        " new=", name);
    g_state.filter_name = name;
}

const std::string& current_filter_name() {
    LOG(DEBUG_FILTER, "filter runtime current_filter=", g_state.filter_name);
    return g_state.filter_name;
}

} // namespace filters
