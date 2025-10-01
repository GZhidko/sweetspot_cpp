#pragma once
#include "jenkins_hash.hpp"
#include <arpa/inet.h>
#include <cstdint>
#include <netinet/ip.h>
#include <string>
#include <tuple>
struct IPv4Header {

    struct iphdr iph;
    // Указатели на вложенные заголовки

    static constexpr const char* name = "IP";
    static constexpr bool uses_ports = false;

    struct Flow {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint8_t protocol;

        auto to_tuple() const {
            return std::tie(src_ip, dst_ip, protocol);
        }
    };

    Flow get_flow() const {
        return Flow{iph.saddr, iph.daddr, iph.protocol};
    }

    static uint32_t hash(uint32_t saddr, uint32_t daddr, uint16_t sport = 0, uint16_t dport = 0) {
        return CPUFanoutHash::hash_ipv4(saddr, daddr, sport, dport, 0);
    }
    static std::string ip_to_string(uint32_t ip) {
        char buf[INET_ADDRSTRLEN];
        struct in_addr addr;
        addr.s_addr = ip;
        if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)) == nullptr) {
            return "invalid_ip";
        }
        return buf;
    }
};
