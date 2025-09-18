#pragma once
#include "jenkins_hash.hpp"
#include <cstdint>
#include <tuple>
#include "forward_dec.h"
#include "ipv4.h"
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
struct ICMPHeader {
    struct icmphdr icmph;
    IPv4Header* ip_header = nullptr;

    static constexpr const char* name = "ICMP";
    static constexpr bool uses_ports = false; // используется идентификатор+seq

    struct Flow {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t ident;
        uint16_t seq;
        uint8_t  protocol;

        auto to_tuple() const {
            return std::tie(src_ip, ident, dst_ip, seq, protocol);
        }
    };

    Flow get_flow() const {
        return Flow{
            ip_header->iph.saddr,
            ip_header->iph.daddr,
            icmph.un.echo.id,
            icmph.un.echo.sequence,
            ip_header->iph.protocol
        };
    }

    static uint32_t hash(uint32_t saddr, uint32_t daddr,
                         uint16_t ident, uint16_t seq) {
        return CPUFanoutHash::hash_ipv4(saddr, daddr, ident, seq, IPPROTO_ICMP);
    }
};
