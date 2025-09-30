#include "netset.hpp"
#include <stdexcept>
#include <sstream>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

// Вспомогательная функция для парсинга IP
uint32_t Netset::parse_ip(const std::string& ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
        throw std::runtime_error("Invalid IP address: " + ip_str);
    }
    return ntohl(addr.s_addr);
}

// Вспомогательная функция для преобразования IP в строку
std::string Netset::ip_to_string(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    char buf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)) == nullptr) {
        return "invalid_ip";
    }
    return buf;
}

// Расчет netmask по длине префикса
uint32_t Netset::calculate_netmask(int prefix_len) {
    if (prefix_len < 0 || prefix_len > 32) {
        throw std::runtime_error("Invalid prefix length: " + std::to_string(prefix_len));
    }
    return (0xFFFFFFFFu << (32 - prefix_len));
}

// Создание Netset из строки CIDR
std::shared_ptr<Netset> Netset::create(const std::string& cidrs) {
    auto netset = std::make_shared<Netset>();
    std::istringstream iss(cidrs);
    std::string token;
    
    std::vector<std::string> tokens;
    while (std::getline(iss, token, ' ')) {
        if (!token.empty()) {
            tokens.push_back(token);
        }
    }
    
    // Также поддерживаем разделители : и ,
    if (tokens.empty()) {
        std::string temp = cidrs;
        size_t pos = 0;
        while ((pos = temp.find_first_of(":,")) != std::string::npos) {
            token = temp.substr(0, pos);
            if (!token.empty()) {
                tokens.push_back(token);
            }
            temp.erase(0, pos + 1);
        }
        if (!temp.empty()) {
            tokens.push_back(temp);
        }
    }
    
    for (const auto& cidr : tokens) {
        size_t slash_pos = cidr.find('/');
        std::string ip_str = cidr;
        int prefix_len = 32;
        
        if (slash_pos != std::string::npos) {
            ip_str = cidr.substr(0, slash_pos);
            try {
                prefix_len = std::stoi(cidr.substr(slash_pos + 1));
            } catch (const std::exception& e) {
                LOG(DEBUG_ERROR, "Invalid prefix length in CIDR: ", cidr);
                continue;
            }
        }
        
        if (prefix_len < 0 || prefix_len > 32) {
            LOG(DEBUG_ERROR, "Invalid prefix length: ", prefix_len, " in CIDR: ", cidr);
            continue;
        }
        
        try {
            uint32_t ip_min = parse_ip(ip_str);
            uint32_t netmask = calculate_netmask(prefix_len);
            uint32_t ip_max = ip_min | (~netmask);
            
            // Создаем новый диапазон
            auto new_range = std::make_shared<Range>(ip_min, ip_max);
            
            // Добавляем в список
            if (!netset->head) {
                netset->head = new_range;
            } else {
                auto current = netset->head;
                while (current->next) {
                    current = current->next;
                }
                current->next = new_range;
            }
            
            LOG(DEBUG_NETSET, "Added IP range: ", ip_to_string(ip_min), 
                " - ", ip_to_string(ip_max), " (CIDR: ", cidr, ")");
            
        } catch (const std::exception& e) {
            LOG(DEBUG_ERROR, "Failed to parse CIDR: ", cidr, " - ", e.what());
            continue;
        }
    }
    
    if (netset->head) {
        LOG(DEBUG_NETSET, "Networks loaded: ", netset->pretty(), 
            " (", netset->size(), " addresses)");
    } else {
        LOG(DEBUG_ERROR, "No valid networks found in: ", cidrs);
    }
    
    return netset;
}

// Уничтожение netset
void Netset::destroy() {
    head = nullptr; // shared_ptr автоматически управляет памятью
}

// Красивое строковое представление
std::string Netset::pretty() const {
    if (!head) {
        return "";
    }
    
    std::ostringstream oss;
    auto current = head;
    bool first = true;
    
    while (current) {
        if (!first) {
            oss << ",";
        }
        oss << ip_to_string(current->ip_min) << "-" << ip_to_string(current->ip_max);
        first = false;
        current = current->next;
    }
    
    return oss.str();
}

// Общее количество адресов
uint32_t Netset::size() const {
    uint32_t total_size = 0;
    auto current = head;
    
    while (current) {
        total_size += current->ip_max - current->ip_min + 1;
        current = current->next;
    }
    LOG(DEBUG_NETSET, "Netset size computed: ", total_size);
    return total_size;
}

// Получение индекса для IP адреса
uint32_t Netset::idx(uint32_t ip) const {
    uint32_t index = 0;
    auto current = head;
    
    while (current) {
        if (ip >= current->ip_min && ip <= current->ip_max) {
            LOG(DEBUG_NETSET, "Netset idx for ", ip_to_string(ip), " = ",
                index + (ip - current->ip_min));
            return index + (ip - current->ip_min);
        } else if (ip > current->ip_max) {
            index += current->ip_max - current->ip_min + 1;
        } else {
            // IP меньше текущего диапазона, но не входит в него
            break;
        }
        current = current->next;
    }
    
    throw std::out_of_range("IP not found in netset: " + ip_to_string(ip));
}

// Получение IP адреса по индексу
uint32_t Netset::ip(uint32_t ip_idx) const {
    uint32_t current_idx = 0;
    auto current = head;
    
    while (current) {
        uint32_t range_size = current->ip_max - current->ip_min + 1;
        
        if (ip_idx < current_idx + range_size) {
            return current->ip_min + (ip_idx - current_idx);
        }
        
        current_idx += range_size;
        current = current->next;
    }
    
    throw std::out_of_range("Index out of range: " + std::to_string(ip_idx));
}

// Проверка принадлежности IP к netset
bool Netset::contains(uint32_t ip) const {
    auto current = head;
    
    while (current) {
        if (ip >= current->ip_min && ip <= current->ip_max) {
            LOG(DEBUG_NETSET, "Netset contains ", ip_to_string(ip), " -> true");
            return true;
        }
        current = current->next;
    }
    LOG(DEBUG_NETSET, "Netset contains ", ip_to_string(ip), " -> false");
    return false;
};
