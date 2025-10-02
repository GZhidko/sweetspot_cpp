
#include "../af_packet_io/checksum_utils.h"
#include "../nat/checksum_utils.hpp"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <array>
#include <cstdint>
#include <iostream>
#include <random>
#include <vector>

int main() {
    std::mt19937 rng(12345);
    std::uniform_int_distribution<uint32_t> ip_dist;
    std::uniform_int_distribution<uint16_t> port_dist(1, 65535);
    std::uniform_int_distribution<int> payload_len_dist(0, 64);
    std::uniform_int_distribution<int> byte_dist(0, 255);

    auto check_ip = [&](uint32_t old_src, uint32_t new_src) {
        iphdr ip{};
        ip.version = 4;
        ip.ihl = 5;
        ip.ttl = 64;
        ip.protocol = IPPROTO_ICMP;
        ip.tot_len = htons(static_cast<uint16_t>(ip.ihl * 4));
        ip.saddr = htonl(old_src);
        ip.daddr = htonl(ip_dist(rng));
        ip.check = 0;
        uint16_t orig = af_packet_io::ip_checksum(reinterpret_cast<const uint8_t*>(&ip), ip.ihl * 4);
        ip.check = htons(orig);
        uint16_t adjusted = ntohs(nat::detail::adjust_checksum32(ip.check, old_src, new_src));
        ip.saddr = htonl(new_src);
        ip.check = 0;
        uint16_t recomputed = af_packet_io::ip_checksum(reinterpret_cast<const uint8_t*>(&ip), ip.ihl * 4);
        return adjusted == recomputed;
    };

    for (int i = 0; i < 1000; ++i) {
        if (!check_ip(ip_dist(rng), ip_dist(rng))) {
            std::cerr << "IPv4 checksum mismatch" << std::endl;
            return 1;
        }
    }
    auto check_icmp_echo = [&]() {
        iphdr ip{};
        ip.version = 4;
        ip.ihl = 5;
        ip.ttl = 64;
        ip.protocol = IPPROTO_ICMP;
        ip.tos = 0;
        ip.id = 0;
        ip.frag_off = 0;
        uint32_t src_ip = ip_dist(rng);
        uint32_t dst_ip = ip_dist(rng);
        ip.saddr = htonl(src_ip);
        ip.daddr = htonl(dst_ip);
        size_t seg_len = sizeof(icmphdr) + payload_len_dist(rng);
        std::vector<uint8_t> seg(seg_len);
        for (auto& b : seg) b = static_cast<uint8_t>(byte_dist(rng));
        auto* icmp = reinterpret_cast<icmphdr*>(seg.data());
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        uint16_t old_id = port_dist(rng);
        icmp->un.echo.id = htons(old_id);
        icmp->un.echo.sequence = htons(port_dist(rng));
        icmp->checksum = 0;
        ip.tot_len = htons(static_cast<uint16_t>(ip.ihl * 4 + seg_len));
        ip.check = 0;
        ip.check = htons(af_packet_io::ip_checksum(reinterpret_cast<const uint8_t*>(&ip), ip.ihl * 4));
        uint16_t orig = af_packet_io::l4_checksum(&ip, seg.data(), seg.size(), IPPROTO_ICMP);
        icmp->checksum = htons(orig);

        uint16_t checksum_host = ntohs(icmp->checksum);
        uint16_t partial = 0;
        if (!nat::detail::checksum_block_decrement(partial, checksum_host, true,
                                                   reinterpret_cast<const uint8_t*>(&icmp->un),
                                                   sizeof(icmp->un))) {
            return false;
        }

        uint16_t new_id = port_dist(rng);
        icmp->un.echo.id = htons(new_id);

        if (!nat::detail::checksum_block_increment(checksum_host, partial, true,
                                                   reinterpret_cast<const uint8_t*>(&icmp->un),
                                                   sizeof(icmp->un))) {
            return false;
        }

        uint16_t final_checksum = checksum_host;
        icmp->checksum = 0;
        uint16_t recomputed = af_packet_io::l4_checksum(&ip, seg.data(), seg.size(), IPPROTO_ICMP);
        return final_checksum == recomputed;
    };

    for (int i = 0; i < 1000; ++i) {
        if (!check_icmp_echo()) {
            std::cerr << "ICMP echo checksum mismatch" << std::endl;
            return 1;
        }
    }

    auto check_icmp_time_exceeded = [&]() {
        iphdr outer_ip{};
        outer_ip.version = 4;
        outer_ip.ihl = 5;
        outer_ip.ttl = 64;
        outer_ip.protocol = IPPROTO_ICMP;
        outer_ip.tos = 0;
        outer_ip.id = 0;
        outer_ip.frag_off = 0;
        uint32_t outer_src = ip_dist(rng);
        uint32_t outer_dst = ip_dist(rng);
        outer_ip.saddr = htonl(outer_src);
        outer_ip.daddr = htonl(outer_dst);

        constexpr size_t inner_block_len = sizeof(iphdr) + sizeof(icmphdr);
        std::array<uint8_t, sizeof(icmphdr) + inner_block_len> payload{};
        auto* outer_icmp = reinterpret_cast<icmphdr*>(payload.data());
        outer_icmp->type = ICMP_TIME_EXCEEDED;
        outer_icmp->code = 0;
        outer_icmp->checksum = 0;
        outer_icmp->un.gateway = 0;

        auto* inner_ip = reinterpret_cast<iphdr*>(payload.data() + sizeof(icmphdr));
        inner_ip->version = 4;
        inner_ip->ihl = 5;
        inner_ip->tos = 0;
        inner_ip->tot_len = htons(static_cast<uint16_t>(inner_ip->ihl * 4 + sizeof(icmphdr)));
        inner_ip->id = 0;
        inner_ip->frag_off = 0;
        inner_ip->ttl = 32;
        inner_ip->protocol = IPPROTO_ICMP;
        uint32_t inner_src = ip_dist(rng);
        uint32_t inner_dst = ip_dist(rng);
        inner_ip->saddr = htonl(inner_src);
        inner_ip->daddr = htonl(inner_dst);
        inner_ip->check = 0;

        auto* inner_icmp = reinterpret_cast<icmphdr*>(payload.data() + sizeof(icmphdr) + sizeof(iphdr));
        inner_icmp->type = ICMP_ECHO;
        inner_icmp->code = 0;
        uint16_t inner_id = port_dist(rng);
        uint16_t inner_seq = port_dist(rng);
        inner_icmp->un.echo.id = htons(inner_id);
        inner_icmp->un.echo.sequence = htons(inner_seq);
        inner_icmp->checksum = htons(port_dist(rng));

        outer_ip.tot_len = htons(static_cast<uint16_t>(outer_ip.ihl * 4 + payload.size()));
        outer_ip.check = 0;
        outer_ip.check = htons(af_packet_io::ip_checksum(reinterpret_cast<const uint8_t*>(&outer_ip),
                                                         outer_ip.ihl * 4));

        uint16_t orig = af_packet_io::l4_checksum(&outer_ip, payload.data(), payload.size(), IPPROTO_ICMP);
        outer_icmp->checksum = htons(orig);

        uint16_t checksum_host = ntohs(outer_icmp->checksum);
        uint16_t partial = 0;
        if (!nat::detail::checksum_block_decrement(partial, checksum_host, true,
                                                   payload.data() + sizeof(icmphdr), inner_block_len)) {
            return false;
        }

        uint32_t new_inner_src = ip_dist(rng);
        uint16_t new_inner_id = port_dist(rng);
        uint16_t new_inner_seq = port_dist(rng);
        inner_ip->saddr = htonl(new_inner_src);
        inner_icmp->un.echo.id = htons(new_inner_id);
        inner_icmp->un.echo.sequence = htons(new_inner_seq);

        if (!nat::detail::checksum_block_increment(checksum_host, partial, true,
                                                   payload.data() + sizeof(icmphdr), inner_block_len)) {
            return false;
        }

        uint16_t final_checksum = checksum_host;
        outer_icmp->checksum = 0;
        uint16_t recomputed = af_packet_io::l4_checksum(&outer_ip, payload.data(), payload.size(), IPPROTO_ICMP);
        return final_checksum == recomputed;
    };

    for (int i = 0; i < 500; ++i) {
        if (!check_icmp_time_exceeded()) {
            std::cerr << "ICMP time exceeded checksum mismatch" << std::endl;
            return 1;
        }
    }


    auto check_tcp = [&]() {
        iphdr ip{};
        ip.version = 4;
        ip.ihl = 5;
        ip.ttl = 64;
        ip.protocol = IPPROTO_TCP;
        uint32_t src_ip = ip_dist(rng);
        uint32_t dst_ip = ip_dist(rng);
        ip.saddr = htonl(src_ip);
        ip.daddr = htonl(dst_ip);
        size_t seg_len = sizeof(tcphdr) + payload_len_dist(rng);
        std::vector<uint8_t> seg(seg_len);
        for (auto& b : seg) b = static_cast<uint8_t>(byte_dist(rng));
        auto* tcp = reinterpret_cast<tcphdr*>(seg.data());
        tcp->source = htons(port_dist(rng));
        tcp->dest = htons(port_dist(rng));
        tcp->doff = 5;
        tcp->check = 0;
        ip.tot_len = htons(static_cast<uint16_t>(ip.ihl * 4 + seg_len));
        uint16_t orig = af_packet_io::l4_checksum(&ip, seg.data(), seg.size(), IPPROTO_TCP);
        tcp->check = htons(orig);
        uint16_t new_src_port = port_dist(rng);
        uint16_t checksum = nat::detail::adjust_checksum16(tcp->check, ntohs(tcp->source), new_src_port);
        tcp->source = htons(new_src_port);
        uint16_t final_checksum = ntohs(checksum);
        uint16_t saved = tcp->check;
        tcp->check = 0;
        uint16_t recomputed = af_packet_io::l4_checksum(&ip, seg.data(), seg.size(), IPPROTO_TCP);
        tcp->check = saved;
        return final_checksum == recomputed;
    };

    for (int i = 0; i < 1000; ++i) {
        if (!check_tcp()) {
            std::cerr << "TCP checksum mismatch" << std::endl;
            return 1;
        }
    }

    auto check_udp = [&]() {
        iphdr ip{};
        ip.version = 4;
        ip.ihl = 5;
        ip.ttl = 64;
        ip.protocol = IPPROTO_UDP;
        uint32_t src_ip = ip_dist(rng);
        uint32_t dst_ip = ip_dist(rng);
        ip.saddr = htonl(src_ip);
        ip.daddr = htonl(dst_ip);
        size_t seg_len = sizeof(udphdr) + payload_len_dist(rng);
        std::vector<uint8_t> seg(seg_len);
        for (auto& b : seg) b = static_cast<uint8_t>(byte_dist(rng));
        auto* udp = reinterpret_cast<udphdr*>(seg.data());
        udp->source = htons(port_dist(rng));
        udp->dest = htons(port_dist(rng));
        udp->len = htons(static_cast<uint16_t>(seg_len));
        udp->check = 0;
        ip.tot_len = htons(static_cast<uint16_t>(ip.ihl * 4 + seg_len));
        uint16_t orig = af_packet_io::l4_checksum(&ip, seg.data(), seg.size(), IPPROTO_UDP);
        udp->check = htons(orig);
        if (orig == 0) return true;
        uint16_t new_src_port = port_dist(rng);
        uint16_t checksum = nat::detail::adjust_checksum16(udp->check, ntohs(udp->source), new_src_port);
        udp->source = htons(new_src_port);
        uint16_t final_checksum = ntohs(checksum);
        uint16_t saved = udp->check;
        udp->check = 0;
        uint16_t recomputed = af_packet_io::l4_checksum(&ip, seg.data(), seg.size(), IPPROTO_UDP);
        udp->check = saved;
        return final_checksum == recomputed;
    };

    for (int i = 0; i < 1000; ++i) {
        if (!check_udp()) {
            std::cerr << "UDP checksum mismatch" << std::endl;
            return 1;
        }
    }

        std::cout << "Checksum tests passed" << std::endl;
    return 0;
}
