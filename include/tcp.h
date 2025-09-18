#pragma once
#include "jenkins_hash.hpp"
#include <cstdint>
#include <tuple>
#include "forward_dec.h"
#include "ipv4.h"
#include <arpa/inet.h>
#include <netinet/tcp.h>
struct TCPHeader {
    struct tcphdr tcph;
    IPv4Header* ip_header = nullptr;

    static constexpr const char* name = "TCP";
    static constexpr bool uses_ports = true;

    struct Flow {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t  protocol;

        auto to_tuple() const {
            return std::tie(src_ip, src_port, dst_ip, dst_port, protocol);
        }
    };

    Flow get_flow() const {
        return Flow{
            ip_header->iph.saddr,
            ip_header->iph.daddr,
            tcph.source,
            tcph.dest,
            ip_header->iph.protocol
        };
    }

    static uint32_t hash(uint32_t saddr, uint32_t daddr,
                         uint16_t sport, uint16_t dport) {
        return CPUFanoutHash::hash_ipv4(saddr, daddr, sport, dport, IPPROTO_TCP);
    }
};
