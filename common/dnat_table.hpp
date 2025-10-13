#pragma once

#include <chrono>
#include <cstdint>
#include <list>
#include <optional>
#include <unordered_map>

class DnatTable {
  public:
    struct LookupResult {
        uint32_t original_ip;
        uint16_t original_port;
        bool connection_oriented;
    };

    void upsert(uint32_t target_ip, uint16_t target_port,
                uint32_t remote_ip, uint16_t remote_port,
                uint32_t original_ip, uint16_t original_port,
                uint8_t protocol, bool connection_oriented,
                std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    std::optional<LookupResult> consume(uint32_t target_ip, uint16_t target_port,
                                        uint32_t remote_ip, uint16_t remote_port,
                                        uint8_t protocol,
                                        std::chrono::steady_clock::time_point now =
                                            std::chrono::steady_clock::now());

    void clear();

  private:
    struct Key {
        uint32_t target_ip;
        uint16_t target_port;
        uint32_t remote_ip;
        uint16_t remote_port;
        uint8_t protocol;

        bool operator==(const Key& other) const noexcept;
    };

    struct KeyHash {
        size_t operator()(const Key& key) const noexcept;
    };

    struct Entry {
        uint32_t original_ip;
        uint16_t original_port;
        bool connection_oriented;
        std::chrono::steady_clock::time_point expires_at;
        std::list<Key>::iterator lru_it;
    };

    static constexpr std::chrono::seconds kDefaultTtl{300};
    static constexpr std::size_t kMaxEntries = 4096;

    using Map = std::unordered_map<Key, Entry, KeyHash>;

    void purge_expired(std::chrono::steady_clock::time_point now);
    void evict_if_needed();

    Map map_;
    std::list<Key> lru_;
};
