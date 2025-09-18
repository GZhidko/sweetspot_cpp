#pragma once
#include <cstdint>
#include <cstring>
#include <tuple>

// Точная копия хэш-функции из Linux kernel для PACKET_FANOUT_CPU
// Адаптирована для использования в NAT (njn rjl)
class CPUFanoutHash {
public:
    // Основная функция хэширования для NAT
    template<typename Tuple>
    static uint32_t hash_tuple(const Tuple& tuple) {
        // Сериализуем tuple в байтовый буфер
        constexpr size_t max_size = 64;
        uint8_t buffer[max_size];
        size_t offset = 0;
        
        // Сериализация tuple с сохранением выравнивания как в ядре
        auto serialize = [&](const auto& value) {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_integral_v<T> || std::is_enum_v<T>) {
                std::memcpy(buffer + offset, &value, sizeof(value));
                offset += sizeof(value);
            }
        };
        
        std::apply([&](const auto&... args) {
            (serialize(args), ...);
        }, tuple);
        
        // Хэшируем только данные потока, БЕЗ CPU_ID!
        return jenkins_hash(buffer, offset, 0);
    }   
    // Специализированные хэш-функции для NAT
    
    // Для IP пакетов в NAT
    static uint32_t hash_ipv4(uint32_t saddr, uint32_t daddr, 
                                 uint16_t sport, uint16_t dport, 
                                 uint8_t protocol) {
        return hash_tuple(std::make_tuple(saddr, daddr, sport, dport, protocol));
    }
    
    static uint32_t hash_udp(uint32_t saddr, uint32_t daddr, 
                                uint16_t sport, uint16_t dport) {
        return hash_ipv4(saddr, daddr, sport, dport, 17);
    }
    
    static uint32_t hash_tcp(uint32_t saddr, uint32_t daddr, 
                                uint16_t sport, uint16_t dport) {
        return hash_ipv4(saddr, daddr, sport, dport, 6);
    }
    
    static uint32_t hash_icmp(uint32_t saddr, uint32_t daddr, 
                                 uint16_t id, uint16_t seq) {
        return hash_ipv4(saddr, daddr, id, seq, 1);
    }    
    // Хэш для выбора порта в диапазоне (для CPU affinity)
    static uint16_t select_port_in_range(uint32_t hash_value, uint16_t port_min, uint16_t port_max) {
        uint32_t range_size = port_max - port_min + 1;
        return port_min + (hash_value % range_size);
    }
    
    // Выбор CPU на основе хэша (для fanout)
    static uint32_t select_cpu(uint32_t hash_value, uint32_t cpu_count) {
        return hash_value % cpu_count;
    }

private:
    // Точная копия jhash из Linux kernel (ваша реализация)
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
