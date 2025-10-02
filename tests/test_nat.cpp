#include <arpa/inet.h>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include "netset.hpp"
#include "icmp.h"
#include "ipv4.h"
#include "tcp.h"
#include "udp.h"
#include "checksum.hpp"
#include "nat.h"
#include "nat_config.hpp"

namespace {

uint32_t ip_from_string(const char* str) {
    in_addr addr{};
    if (inet_pton(AF_INET, str, &addr) != 1) {
        std::cerr << "Failed to parse IP: " << str << "\n";
        std::exit(1);
    }
    return ntohl(addr.s_addr);
}

void setup_ipv4(IPv4Header& ip, uint32_t src_host, uint32_t dst_host, uint8_t proto,
                uint16_t payload_len) {
    std::memset(&ip.iph, 0, sizeof(ip.iph));
    ip.iph.version = 4;
    ip.iph.ihl = 5;
    ip.iph.protocol = proto;
    ip.iph.ttl = 64;
    ip.iph.tot_len = htons(static_cast<uint16_t>(sizeof(iphdr) + payload_len));
    ip.iph.saddr = htonl(src_host);
    ip.iph.daddr = htonl(dst_host);
    ip.iph.check = checksum::recompute_ipv4_checksum(ip.iph);
}

void setup_tcp(TCPHeader& tcp, IPv4Header& ip, uint16_t src_port, uint16_t dst_port,
               uint16_t checksum_host) {
    std::memset(&tcp.tcph, 0, sizeof(tcp.tcph));
    tcp.ip_header = &ip;
    tcp.tcph.source = htons(src_port);
    tcp.tcph.dest = htons(dst_port);
    tcp.tcph.doff = sizeof(tcphdr) / 4;
    tcp.tcph.check = htons(checksum_host);
}

void setup_udp(UDPHeader& udp, IPv4Header& ip, uint16_t src_port, uint16_t dst_port,
               uint16_t checksum_host) {
    std::memset(&udp.udph, 0, sizeof(udp.udph));
    udp.ip_header = &ip;
    udp.udph.source = htons(src_port);
    udp.udph.dest = htons(dst_port);
    udp.udph.len = htons(sizeof(udphdr));
    udp.udph.check = htons(checksum_host);
}

void setup_icmp(ICMPHeader& icmp, IPv4Header& ip, uint16_t ident, uint16_t seq, uint16_t checksum) {
    std::memset(&icmp.icmph, 0, sizeof(icmp.icmph));
    icmp.ip_header = &ip;
    icmp.icmph.type = ICMP_ECHO;
    icmp.icmph.code = 0;
    icmp.icmph.un.echo.id = htons(ident);
    icmp.icmph.un.echo.sequence = htons(seq);
    icmp.icmph.checksum = htons(checksum);
}

NatConfig make_base_config() {
    NatConfig cfg;
    cfg.private_netset = Netset::create("10.0.0.0/24");
    cfg.public_netset = Netset::create("198.51.100.0/24");
    cfg.udp_port_min = 40000;
    cfg.udp_port_max = 50000;
    cfg.tcp_port_min = 20000;
    cfg.tcp_port_max = 30000;
    cfg.ip_thread_capacity = 128;
    cfg.tcp_thread_capacity = 128;
    cfg.udp_thread_capacity = 128;
    cfg.icmp_thread_capacity = 64;
    return cfg;
}

void test_tcp_translation(const NatConfig& cfg) {
    Nat nat(cfg, 0, 4);
    uint32_t prv_ip = ip_from_string("10.0.0.10");
    uint32_t dst_ip = ip_from_string("203.0.113.8");

    IPv4Header ip{};
    setup_ipv4(ip, prv_ip, dst_ip, IPPROTO_TCP, sizeof(tcphdr));
    TCPHeader tcp{};
    setup_tcp(tcp, ip, 12345, 443, 0x1a2b);

    const uint16_t ip_check_before = ip.iph.check;
    const uint16_t tcp_check_before = tcp.tcph.check;

    nat.process(tcp);

    uint32_t pub_ip = ntohl(ip.iph.saddr);
    uint16_t pub_port = ntohs(tcp.tcph.source);

    assert(pub_ip != prv_ip);
    assert(pub_port != 12345);

    uint16_t expected_ip_check = checksum::adjust_checksum32(ip_check_before, prv_ip, pub_ip);
    assert(ip.iph.check == expected_ip_check);

    uint16_t expected_tcp_check =
        checksum::adjust_checksum32(tcp_check_before, prv_ip, pub_ip);
    expected_tcp_check =
        checksum::adjust_checksum16(expected_tcp_check, static_cast<uint16_t>(12345),
                                       pub_port);
    assert(tcp.tcph.check == expected_tcp_check);

    // inbound reply
    IPv4Header reply_ip{};
    setup_ipv4(reply_ip, dst_ip, pub_ip, IPPROTO_TCP, sizeof(tcphdr));
    TCPHeader reply_tcp{};
    setup_tcp(reply_tcp, reply_ip, 443, pub_port, 0x2b3c);

    const uint16_t reply_ip_before = reply_ip.iph.check;
    const uint16_t reply_tcp_before = reply_tcp.tcph.check;

    nat.process(reply_tcp);

    assert(ntohl(reply_ip.iph.daddr) == prv_ip);
    assert(ntohs(reply_tcp.tcph.dest) == 12345);

    uint16_t reply_ip_expected =
        checksum::adjust_checksum32(reply_ip_before, pub_ip, prv_ip);
    assert(reply_ip.iph.check == reply_ip_expected);

    if (reply_tcp.tcph.check != 0) {
        uint16_t reply_tcp_expected =
            checksum::adjust_checksum32(reply_tcp_before, pub_ip, prv_ip);
        reply_tcp_expected =
            checksum::adjust_checksum16(reply_tcp_expected, pub_port, static_cast<uint16_t>(12345));
        assert(reply_tcp.tcph.check == reply_tcp_expected);
    }
}

void test_udp_translation(const NatConfig& cfg) {
    Nat nat(cfg, 0, 4);
    uint32_t prv_ip = ip_from_string("10.0.0.11");
    uint32_t dst_ip = ip_from_string("198.51.100.10");

    IPv4Header ip{};
    setup_ipv4(ip, prv_ip, dst_ip, IPPROTO_UDP, sizeof(udphdr));
    UDPHeader udp{};
    setup_udp(udp, ip, 40000, 53, 0x2b3c);

    const uint16_t ip_check_before = ip.iph.check;
    const uint16_t udp_check_before = udp.udph.check;

    nat.process(udp);

    uint32_t pub_ip = ntohl(ip.iph.saddr);
    uint16_t pub_port = ntohs(udp.udph.source);

    assert(pub_ip != prv_ip);
    assert(pub_port != 40000);

    uint16_t expected_ip_check = checksum::adjust_checksum32(ip_check_before, prv_ip, pub_ip);
    assert(ip.iph.check == expected_ip_check);

    if (udp.udph.check != 0) {
        uint16_t expected_udp_check =
            checksum::adjust_checksum32(udp_check_before, prv_ip, pub_ip);
        expected_udp_check =
            checksum::adjust_checksum16(expected_udp_check, static_cast<uint16_t>(40000),
                                           pub_port);
        assert(udp.udph.check == expected_udp_check || udp.udph.check == htons(0xFFFF));
    }

    IPv4Header reply_ip{};
    setup_ipv4(reply_ip, dst_ip, pub_ip, IPPROTO_UDP, sizeof(udphdr));
    UDPHeader reply_udp{};
    setup_udp(reply_udp, reply_ip, 53, pub_port, 0x1d2c);

    const uint16_t reply_ip_before = reply_ip.iph.check;
    const uint16_t reply_udp_before = reply_udp.udph.check;

    nat.process(reply_udp);

    assert(ntohl(reply_ip.iph.daddr) == prv_ip);
    assert(ntohs(reply_udp.udph.dest) == 40000);

    uint16_t reply_ip_expected =
        checksum::adjust_checksum32(reply_ip_before, pub_ip, prv_ip);
    assert(reply_ip.iph.check == reply_ip_expected);

    if (reply_udp.udph.check != 0) {
        uint16_t reply_udp_expected =
            checksum::adjust_checksum32(reply_udp_before, pub_ip, prv_ip);
        reply_udp_expected =
            checksum::adjust_checksum16(reply_udp_expected, pub_port, static_cast<uint16_t>(40000));
        assert(reply_udp.udph.check == reply_udp_expected || reply_udp.udph.check == htons(0xFFFF));
    }
}

void test_udp_zero_checksum_stays_zero(const NatConfig& cfg) {
    Nat nat(cfg, 0, 4);
    uint32_t prv_ip = ip_from_string("10.0.0.12");
    uint32_t dst_ip = ip_from_string("198.51.100.12");

    IPv4Header ip{};
    setup_ipv4(ip, prv_ip, dst_ip, IPPROTO_UDP, sizeof(udphdr));
    UDPHeader udp{};
    setup_udp(udp, ip, 1234, 4321, 0);

    nat.process(udp);
    assert(udp.udph.check == 0);
}

void test_icmp_translation(const NatConfig& cfg) {
    Nat nat(cfg, 0, 4);
    uint32_t prv_ip = ip_from_string("10.0.0.13");
    uint32_t dst_ip = ip_from_string("203.0.113.9");

    IPv4Header ip{};
    setup_ipv4(ip, prv_ip, dst_ip, IPPROTO_ICMP, sizeof(icmphdr));
    ICMPHeader icmp{};
    setup_icmp(icmp, ip, 0x1000, 7, 0x3c4d);

    const uint16_t ip_check_before = ip.iph.check;
    const uint16_t icmp_check_before = icmp.icmph.checksum;

    nat.process(icmp);

    uint32_t pub_ip = ntohl(ip.iph.saddr);
    uint16_t pub_id = ntohs(icmp.icmph.un.echo.id);

    assert(pub_ip != prv_ip);
    assert(pub_id != 0x1000);

    uint16_t expected_ip_check = checksum::adjust_checksum32(ip_check_before, prv_ip, pub_ip);
    assert(ip.iph.check == expected_ip_check);

    uint16_t expected_icmp_check =
        checksum::adjust_checksum16(icmp_check_before, static_cast<uint16_t>(0x1000), pub_id);
    assert(icmp.icmph.checksum == expected_icmp_check);

    IPv4Header reply_ip{};
    setup_ipv4(reply_ip, dst_ip, pub_ip, IPPROTO_ICMP, sizeof(icmphdr));
    ICMPHeader reply_icmp{};
    setup_icmp(reply_icmp, reply_ip, pub_id, 7, 0x4d5e);

    const uint16_t reply_ip_before = reply_ip.iph.check;
    const uint16_t reply_icmp_before = reply_icmp.icmph.checksum;

    nat.process(reply_icmp);

    assert(ntohl(reply_ip.iph.daddr) == prv_ip);
    assert(ntohs(reply_icmp.icmph.un.echo.id) == 0x1000);

    uint16_t reply_ip_expected =
        checksum::adjust_checksum32(reply_ip_before, pub_ip, prv_ip);
    assert(reply_ip.iph.check == reply_ip_expected);

    uint16_t reply_icmp_expected =
        checksum::adjust_checksum16(reply_icmp_before, pub_id, static_cast<uint16_t>(0x1000));
    assert(reply_icmp.icmph.checksum == reply_icmp_expected);
}

void test_non_private_source_untouched(const NatConfig& cfg) {
    Nat nat(cfg, 0, 4);
    uint32_t pub_src = ip_from_string("198.51.100.50");
    uint32_t dst_ip = ip_from_string("203.0.113.30");

    IPv4Header ip{};
    setup_ipv4(ip, pub_src, dst_ip, IPPROTO_TCP, sizeof(tcphdr));
    TCPHeader tcp{};
    setup_tcp(tcp, ip, 5555, 80, 0x7777);

    nat.process(tcp);

    assert(ntohl(ip.iph.saddr) == pub_src);
    assert(ntohs(tcp.tcph.source) == 5555);
}

void test_capacity_eviction(const NatConfig& base_cfg) {
    NatConfig cfg = base_cfg;
    cfg.udp_thread_capacity = 1;
    Nat nat(cfg, 0, 1);

    uint32_t prv_ip_a = ip_from_string("10.0.0.20");
    uint32_t dst_ip = ip_from_string("198.51.100.30");

    IPv4Header ip_a{};
    setup_ipv4(ip_a, prv_ip_a, dst_ip, IPPROTO_UDP, sizeof(udphdr));
    UDPHeader udp_a{};
    setup_udp(udp_a, ip_a, 2500, 2501, 0x1111);
    nat.process(udp_a);

    uint32_t pub_ip_a = ntohl(ip_a.iph.saddr);
    uint16_t pub_port_a = ntohs(udp_a.udph.source);

    uint32_t prv_ip_b = ip_from_string("10.0.0.21");
    IPv4Header ip_b{};
    setup_ipv4(ip_b, prv_ip_b, dst_ip, IPPROTO_UDP, sizeof(udphdr));
    UDPHeader udp_b{};
    setup_udp(udp_b, ip_b, 2600, 2601, 0x3333);
    nat.process(udp_b);

    uint32_t pub_ip_b = ntohl(ip_b.iph.saddr);
    uint16_t pub_port_b = ntohs(udp_b.udph.source);

    IPv4Header reply_b{};
    setup_ipv4(reply_b, dst_ip, pub_ip_b, IPPROTO_UDP, sizeof(udphdr));
    UDPHeader udp_reply_b{};
    setup_udp(udp_reply_b, reply_b, 2601, pub_port_b, 0x4444);
    nat.process(udp_reply_b);
    assert(ntohl(reply_b.iph.daddr) == prv_ip_b);
    assert(ntohs(udp_reply_b.udph.dest) == 2600);

    IPv4Header reply_a{};
    setup_ipv4(reply_a, dst_ip, pub_ip_a, IPPROTO_UDP, sizeof(udphdr));
    UDPHeader udp_reply_a{};
    setup_udp(udp_reply_a, reply_a, 2501, pub_port_a, 0x5555);
    nat.process(udp_reply_a);
    assert(ntohl(reply_a.iph.daddr) == pub_ip_a);
    assert(ntohs(udp_reply_a.udph.dest) == pub_port_a);
}

void test_static_tcp(const NatConfig& cfg) {
    Nat nat(cfg, 0, 4);
    uint32_t prv_ip = ip_from_string("10.0.0.14");
    uint32_t dst_ip = ip_from_string("203.0.113.40");
    uint32_t pub_ip = ip_from_string("198.51.100.150");
    uint16_t pub_port = 55000;
    nat.add_static_tcp_mapping(prv_ip, 12345, pub_ip, pub_port);

    IPv4Header ip{};
    setup_ipv4(ip, prv_ip, dst_ip, IPPROTO_TCP, sizeof(tcphdr));
    TCPHeader tcp{};
    setup_tcp(tcp, ip, 12345, 80, 0x6a6a);
    nat.process(tcp);
    assert(ntohl(ip.iph.saddr) == pub_ip);
    assert(ntohs(tcp.tcph.source) == pub_port);

    IPv4Header reply{};
    setup_ipv4(reply, dst_ip, pub_ip, IPPROTO_TCP, sizeof(tcphdr));
    TCPHeader reply_tcp{};
    setup_tcp(reply_tcp, reply, 80, pub_port, 0x5b5b);
    nat.process(reply_tcp);
    assert(ntohl(reply.iph.daddr) == prv_ip);
    assert(ntohs(reply_tcp.tcph.dest) == 12345);
}

void test_dynamic_ip_translation(const NatConfig& cfg) {
    Nat nat(cfg, 0, 4);
    uint32_t prv_ip = ip_from_string("10.0.0.40");
    uint32_t dst_ip = ip_from_string("203.0.113.70");

    IPv4Header ip{};
    setup_ipv4(ip, prv_ip, dst_ip, 47 /* GRE */, 0);
    nat.process(ip);
    uint32_t pub_ip = ntohl(ip.iph.saddr);
    assert(pub_ip != prv_ip);

    IPv4Header reply{};
    setup_ipv4(reply, dst_ip, pub_ip, 47, 0);
    nat.process(reply);
    assert(ntohl(reply.iph.daddr) == prv_ip);
}

void test_static_ip(const NatConfig& cfg) {
    Nat nat(cfg, 0, 4);
    uint32_t prv_ip = ip_from_string("10.0.0.30");
    uint32_t dst_ip = ip_from_string("203.0.113.60");
    uint32_t pub_ip = ip_from_string("198.51.100.200");
    nat.add_static_ip_mapping(prv_ip, pub_ip);

    IPv4Header ip{};
    setup_ipv4(ip, prv_ip, dst_ip, 47 /* GRE */, 0);
    nat.process(ip);
    assert(ntohl(ip.iph.saddr) == pub_ip);

    IPv4Header reply{};
    setup_ipv4(reply, dst_ip, pub_ip, 47, 0);
    nat.process(reply);
    assert(ntohl(reply.iph.daddr) == prv_ip);
}

} // namespace

int main() {
    NatConfig cfg = make_base_config();

    test_tcp_translation(cfg);
    test_udp_translation(cfg);
    test_udp_zero_checksum_stays_zero(cfg);
    test_icmp_translation(cfg);
    test_non_private_source_untouched(cfg);
    test_capacity_eviction(cfg);
    test_static_tcp(cfg);
    test_dynamic_ip_translation(cfg);
    test_static_ip(cfg);

    std::cout << "NAT tests passed" << std::endl;
    return 0;
}
