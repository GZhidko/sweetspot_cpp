#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include "logger.h"

class Netset {
public:
    struct Range {
        uint32_t ip_min;
        uint32_t ip_max;
        std::shared_ptr<Range> next;
        
        Range(uint32_t min, uint32_t max) : ip_min(min), ip_max(max), next(nullptr) {}
    };

    Netset() = default;
    ~Netset() { destroy(); }
    
    // Создание netset из строки CIDR
    static std::shared_ptr<Netset> create(const std::string& cidrs);
    
    // Уничтожение netset
    void destroy();
    
    // Получение красивого строкового представления
    std::string pretty() const;
    
    // Получение общего количества адресов
    uint32_t size() const;
    
    // Получение индекса для IP адреса
    uint32_t idx(uint32_t ip) const;
    
    // Получение IP адреса по индексу
    uint32_t ip(uint32_t ip_idx) const;
    
    // Проверка принадлежности IP к netset
    bool contains(uint32_t ip) const;
    
    // Получение первого диапазона
    std::shared_ptr<Range> get_head() const { return head; }
    
private:
    std::shared_ptr<Range> head = nullptr;
    
    // Вспомогательные методы
    static uint32_t parse_ip(const std::string& ip_str);
    static std::string ip_to_string(uint32_t ip);
    static uint32_t calculate_netmask(int prefix_len);
};
