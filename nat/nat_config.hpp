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
    
    // Проверка валидности конфигурации
    bool is_valid() const {
        return private_netset && public_netset && 
               private_netset->size() > 0 && 
               public_netset->size() > 0;
    }
    
    // Получение количества приватных IP
    uint32_t private_ip_count() const {
        return private_netset ? private_netset->size() : 0;
    }
    
    // Получение количества публичных IP
    uint32_t public_ip_count() const {
        return public_netset ? public_netset->size() : 0;
    }
};
