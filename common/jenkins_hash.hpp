#pragma once
#include <cstdint>
#include <cstring>
// Точная копия хэш-функции из Linux kernel для PACKET_FANOUT_CPU
class CPUFanoutHash {
public:
    // Основная функция как в __fanout_hash() из Linux kernel
    static uint32_t hash(const void* data, size_t len, uint32_t seed) {
        return jenkins_hash(data, len, seed);
    }
    
    // Для IP пакетов (как в net/core/filter.c)
    static uint32_t hash_ipv4(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport, uint8_t protocol) {
        // Точный порядок как в Linux kernel
        struct flow_keys {
            uint32_t src;
            uint32_t dst;
            union {
                struct {
                    uint16_t sport;
                    uint16_t dport;
                };
                uint32_t ports;
            };
            uint8_t ip_proto;
        } __attribute__((packed)) keys;
        
        keys.src = saddr;
        keys.dst = daddr;
        keys.sport = sport;
        keys.dport = dport;
        keys.ip_proto = protocol;
        
        return jenkins_hash(&keys, sizeof(keys), 0);
    }
    
    // Для Ethernet фреймов
    static uint32_t hash_ethernet(const void* frame_data, size_t frame_len) {
        // Linux использует весь кадр для хэширования
        return jenkins_hash(frame_data, frame_len, 0);
    }
    
    // UDP специфичный хэш (как в UDP_GRO)
    static uint32_t hash_udp(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport) {
        return hash_ipv4(saddr, daddr, sport, dport, 17); // 17 = IPPROTO_UDP
    }
    
    // TCP специфичный хэш
    static uint32_t hash_tcp(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport) {
        return hash_ipv4(saddr, daddr, sport, dport, 6); // 6 = IPPROTO_TCP
    }
    
    // ICMP специфичный хэш
    static uint32_t hash_icmp(uint32_t saddr, uint32_t daddr, uint16_t id, uint16_t seq) {
        // Для ICMP используем id как порт
        return hash_ipv4(saddr, daddr, id, seq, 1); // 1 = IPPROTO_ICMP
    }

private:
    // Точная копия jhash из Linux kernel
    static uint32_t jenkins_hash(const void* key, size_t length, uint32_t initval) {
        uint32_t a, b, c;
        const uint8_t* k = (const uint8_t*)key;
        
        a = b = c = 0x9e3779b9 + length + initval;
        
        while (length > 12) {
            a += (k[0] + (k[1] << 8) + (k[2] << 16) + (k[3] << 24));
            b += (k[4] + (k[5] << 8) + (k[6] << 16) + (k[7] << 24));
            c += (k[8] + (k[9] << 8) + (k[10] << 16) + (k[11] << 24));
            
            // Миксинг как в Linux
            a -= b; a -= c; a ^= (c >> 13);
            b -= c; b -= a; b ^= (a << 8);
            c -= a; c -= b; c ^= (b >> 13);
            a -= b; a -= c; a ^= (c >> 12);
            b -= c; b -= a; b ^= (a << 16);
            c -= a; c -= b; c ^= (b >> 5);
            a -= b; a -= c; a ^= (c >> 3);
            b -= c; b -= a; b ^= (a << 10);
            c -= a; c -= b; c ^= (b >> 15);
            
            k += 12;
            length -= 12;
        }
        
        // Обработка хвоста
        switch (length) {
            case 12: c += (k[11] << 24); [[fallthrough]];
            case 11: c += (k[10] << 16); [[fallthrough]];
            case 10: c += (k[9] << 8);   [[fallthrough]];
            case 9:  c += k[8];          [[fallthrough]];
            case 8:  b += (k[7] << 24);  [[fallthrough]];
            case 7:  b += (k[6] << 16);  [[fallthrough]];
            case 6:  b += (k[5] << 8);   [[fallthrough]];
            case 5:  b += k[4];          [[fallthrough]];
            case 4:  a += (k[3] << 24);  [[fallthrough]];
            case 3:  a += (k[2] << 16);  [[fallthrough]];
            case 2:  a += (k[1] << 8);   [[fallthrough]];
            case 1:  a += k[0];          [[fallthrough]];
            default: break;
        }
        
        // Финальный миксинг
        c ^= b; c -= (b << 14);
        a ^= c; a -= (c << 11);
        b ^= a; b -= (a << 25);
        c ^= b; c -= (b << 16);
        a ^= c; a -= (c << 4);
        b ^= a; b -= (a << 14);
        c ^= b; c -= (b << 24);
        
        return c;
    }
};
