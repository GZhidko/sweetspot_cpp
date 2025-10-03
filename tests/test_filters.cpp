#include "filters/filter.h"
#include "filters/filter_engine.hpp"
#include "filters/filter_runtime.hpp"
#include "include/icmp.h"
#include "include/ipv4.h"
#include "include/tcp.h"
#include "include/udp.h"

#include <arpa/inet.h>
#include <cassert>
#include <cstdlib>
#include <filesystem>

namespace {

IPv4Header make_ip(uint32_t src_host, uint32_t dst_host, uint8_t proto) {
    IPv4Header ip{};
    ip.iph.version = 4;
    ip.iph.ihl = 5;
    ip.iph.protocol = proto;
    ip.iph.saddr = htonl(src_host);
    ip.iph.daddr = htonl(dst_host);
    return ip;
}

TCPHeader make_tcp(IPv4Header& ip, uint16_t src_port, uint16_t dst_port, uint8_t flags = 0) {
    TCPHeader tcp{};
    tcp.ip_header = &ip;
    tcp.tcph.source = htons(src_port);
    tcp.tcph.dest = htons(dst_port);
    tcp.tcph.doff = sizeof(tcphdr) / 4;
    tcp.tcph.fin = (flags & TH_FIN) ? 1 : 0;
    tcp.tcph.syn = (flags & TH_SYN) ? 1 : 0;
    tcp.tcph.rst = (flags & TH_RST) ? 1 : 0;
    tcp.tcph.psh = (flags & TH_PUSH) ? 1 : 0;
    tcp.tcph.ack = (flags & TH_ACK) ? 1 : 0;
    tcp.tcph.urg = (flags & TH_URG) ? 1 : 0;
    return tcp;
}

UDPHeader make_udp(IPv4Header& ip, uint16_t src_port, uint16_t dst_port) {
    UDPHeader udp{};
    udp.ip_header = &ip;
    udp.udph.source = htons(src_port);
    udp.udph.dest = htons(dst_port);
    udp.udph.len = htons(sizeof(udphdr));
    return udp;
}

ICMPHeader make_icmp(IPv4Header& ip) {
    ICMPHeader icmp{};
    icmp.ip_header = &ip;
    icmp.icmph.type = ICMP_ECHO;
    icmp.icmph.code = 0;
    icmp.icmph.un.echo.id = htons(1234);
    icmp.icmph.un.echo.sequence = htons(1);
    return icmp;
}

bool run_chain(filters::Direction dir, IPv4Header& ip, TCPHeader* tcp = nullptr,
               UDPHeader* udp = nullptr, ICMPHeader* icmp = nullptr) {
    filters::ScopedPacket scoped(dir);
    if (!Filter<IPv4Header>{}(ip)) {
        return false;
    }
    if (tcp) {
        if (!Filter<TCPHeader>{}(*tcp)) {
            return false;
        }
    }
    if (udp) {
        if (!Filter<UDPHeader>{}(*udp)) {
            return false;
        }
    }
    if (icmp) {
        if (!Filter<ICMPHeader>{}(*icmp)) {
            return false;
        }
    }
    return true;
}

} // namespace

int main() {
    const auto config_path = std::filesystem::path(__FILE__).parent_path() / "data" /
                             "test_filters.conf";
    assert(std::filesystem::exists(config_path));
    filters::set_filter_path(config_path.string());
    filters::reload_filters();
    filters::set_current_filter(filters::Engine::instance().default_filter_name());

    constexpr uint32_t src_host = 0xCB007201; // 203.0.114.1
    constexpr uint32_t dst_http = 0xCB007101; // 203.0.113.1
    constexpr uint32_t dst_icmp = 0xCB007137; // 203.0.113.55
    constexpr uint32_t dst_dnat = 0xCB0071C8; // 203.0.113.200

    {
        auto ip = make_ip(src_host, dst_http, IPPROTO_TCP);
        auto tcp = make_tcp(ip, 12345, 80, TH_SYN);
        filters::ScopedPacket scoped(filters::Direction::Inbound);
        bool ip_allowed = Filter<IPv4Header>{}(ip);
        assert(ip_allowed);
        bool tcp_allowed = Filter<TCPHeader>{}(tcp);
        assert(!tcp_allowed);
        const auto& decision = filters::current_decision();
        assert(!decision.allow);
        assert(has_flag(decision.actions, filters::ActionFlag::Block));
    }

    {
        auto ip = make_ip(src_host, dst_http, IPPROTO_TCP);
        auto tcp = make_tcp(ip, 12345, 81, TH_SYN);
        bool allowed = run_chain(filters::Direction::Inbound, ip, &tcp, nullptr, nullptr);
        assert(allowed);
        const auto& decision = filters::current_decision();
        assert(decision.allow);
        assert(has_flag(decision.actions, filters::ActionFlag::Pass));
    }

    {
        auto ip = make_ip(src_host, dst_http, IPPROTO_TCP);
        auto tcp = make_tcp(ip, 12345, 80, TH_SYN);
        bool allowed = run_chain(filters::Direction::Outbound, ip, &tcp, nullptr, nullptr);
        assert(allowed);
        const auto& decision = filters::current_decision();
        assert(decision.allow);
    }

    {
        auto ip = make_ip(src_host, dst_icmp, IPPROTO_ICMP);
        auto icmp = make_icmp(ip);
        bool allowed = run_chain(filters::Direction::Inbound, ip, nullptr, nullptr, &icmp);
        assert(!allowed);
        const auto& decision = filters::current_decision();
        assert(!decision.allow);
        assert(has_flag(decision.actions, filters::ActionFlag::Block));
    }

    {
        auto ip = make_ip(src_host, dst_http, IPPROTO_UDP);
        auto udp = make_udp(ip, 10000, 80);
        bool allowed = run_chain(filters::Direction::Inbound, ip, nullptr, &udp, nullptr);
        assert(allowed);
        const auto& decision = filters::current_decision();
        assert(decision.allow);
    }

    {
        auto ip = make_ip(src_host, dst_dnat, IPPROTO_TCP);
        auto tcp = make_tcp(ip, 34567, 8080, TH_SYN);
        bool allowed = run_chain(filters::Direction::Inbound, ip, &tcp, nullptr, nullptr);
        assert(allowed);
        const auto& decision = filters::current_decision();
        assert(decision.allow);
        assert(has_flag(decision.actions, filters::ActionFlag::Dnat));
        assert(has_flag(decision.actions, filters::ActionFlag::Shape));
        assert(decision.dnat.valid);
        assert(decision.dnat.ip == ntohl(inet_addr("198.51.100.10")));
        assert(decision.dnat.port == 80);
        assert(decision.shape_rate == 512);
    }

    {
        auto ip = make_ip(src_host, dst_dnat, IPPROTO_TCP);
        auto tcp = make_tcp(ip, 34567, 9090, TH_SYN);
        bool allowed = run_chain(filters::Direction::Inbound, ip, &tcp, nullptr, nullptr);
        assert(allowed);
        const auto& decision = filters::current_decision();
        assert(decision.allow);
        assert(!has_flag(decision.actions, filters::ActionFlag::Dnat));
    }

    {
        auto ip = make_ip(src_host, dst_http, IPPROTO_TCP);
        auto tcp = make_tcp(ip, 22, 443, TH_SYN);
        bool allowed = run_chain(filters::Direction::Outbound, ip, &tcp, nullptr, nullptr);
        assert(!allowed);
        const auto& decision = filters::current_decision();
        assert(!decision.allow);
        assert(has_flag(decision.actions, filters::ActionFlag::Block));
    }

    {
        auto ip = make_ip(src_host, dst_http, IPPROTO_TCP);
        auto tcp = make_tcp(ip, 2000, 443, TH_SYN | TH_ACK);
        bool allowed = run_chain(filters::Direction::Outbound, ip, &tcp, nullptr, nullptr);
        assert(allowed);
        const auto& decision = filters::current_decision();
        assert(decision.allow);
    }

    {
        auto repo_root = std::filesystem::path(__FILE__).parent_path().parent_path();
        auto filters_dir = repo_root / "filters" / "filters";
        assert(std::filesystem::exists(filters_dir));
        for (const auto& entry : std::filesystem::recursive_directory_iterator(filters_dir)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            std::string name = entry.path().stem().string();
            filters::Engine::instance().load_filter(name, entry.path());
            auto count = filters::Engine::instance().rule_count(name);
            assert(count > 0);
            filters::PacketState state;
            state.direction = filters::Direction::Inbound;
            (void)filters::Engine::instance().evaluate(state, name);
        }
    }

    return 0;
}
