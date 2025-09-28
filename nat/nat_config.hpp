#pragma once
#include <cstdint>
#include <memory>
#include <vector>
#include "netset.hpp"

struct NatConfig {
    std::shared_ptr<Netset> private_netset;
    std::shared_ptr<Netset> public_netset;

    uint16_t tcp_port_min = 10000;
    uint16_t tcp_port_max = 20000;
    uint16_t udp_port_min = 10000;
    uint16_t udp_port_max = 20000;
    uint16_t icmp_id_min = 1000;
    uint16_t icmp_id_max = 65535;

    uint32_t ip_thread_capacity = 1024;
    uint32_t tcp_thread_capacity = 2048;
    uint32_t udp_thread_capacity = 2048;
    uint32_t icmp_thread_capacity = 1024;

    bool is_valid() const {
        return private_netset && public_netset && private_netset->size() > 0 &&
               public_netset->size() > 0;
    }

    uint32_t private_ip_count() const {
        return private_netset ? private_netset->size() : 0;
    }

    uint32_t public_ip_count() const {
        return public_netset ? public_netset->size() : 0;
    }
};
