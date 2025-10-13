#include "dnat_table.hpp"

#include <functional>
#include <iterator>

namespace {

inline uint64_t pack32(uint32_t hi, uint32_t lo) {
    return (static_cast<uint64_t>(hi) << 32) | static_cast<uint64_t>(lo);
}

inline std::size_t mix_hash(uint64_t value) {
    value ^= value >> 33;
    value *= 0xff51afd7ed558ccdULL;
    value ^= value >> 33;
    value *= 0xc4ceb9fe1a85ec53ULL;
    value ^= value >> 33;
    return static_cast<std::size_t>(value);
}

} // namespace

bool DnatTable::Key::operator==(const Key& other) const noexcept {
    return target_ip == other.target_ip && target_port == other.target_port &&
           remote_ip == other.remote_ip && remote_port == other.remote_port &&
           protocol == other.protocol;
}

std::size_t DnatTable::KeyHash::operator()(const Key& key) const noexcept {
    uint64_t packed1 = pack32(key.target_ip, key.remote_ip);
    uint64_t packed2 = (static_cast<uint64_t>(key.target_port) << 16) | key.remote_port;
    packed2 = (packed2 << 8) | key.protocol;
    return mix_hash(packed1 ^ packed2);
}

void DnatTable::purge_expired(std::chrono::steady_clock::time_point now) {
    for (auto it = map_.begin(); it != map_.end();) {
        if (it->second.expires_at <= now) {
            lru_.erase(it->second.lru_it);
            it = map_.erase(it);
        } else {
            ++it;
        }
    }
}

void DnatTable::upsert(uint32_t target_ip, uint16_t target_port,
                       uint32_t remote_ip, uint16_t remote_port,
                       uint32_t original_ip, uint16_t original_port,
                       uint8_t protocol, bool connection_oriented,
                       std::chrono::steady_clock::time_point now) {
    Key key{target_ip, target_port, remote_ip, remote_port, protocol};
    purge_expired(now);

    auto iter = map_.find(key);
    if (iter == map_.end()) {
        lru_.push_back(key);
        auto lru_it = std::prev(lru_.end());
        Entry entry{};
        entry.original_ip = original_ip;
        entry.original_port = original_port;
        entry.connection_oriented = connection_oriented;
        entry.expires_at = now + kDefaultTtl;
        entry.lru_it = lru_it;
        map_.emplace(key, entry);
    } else {
        iter->second.original_ip = original_ip;
        iter->second.original_port = original_port;
        iter->second.connection_oriented = connection_oriented;
        iter->second.expires_at = now + kDefaultTtl;
        lru_.erase(iter->second.lru_it);
        lru_.push_back(key);
        iter->second.lru_it = std::prev(lru_.end());
    }

    evict_if_needed();
}

std::optional<DnatTable::LookupResult>
DnatTable::consume(uint32_t target_ip, uint16_t target_port,
                   uint32_t remote_ip, uint16_t remote_port,
                   uint8_t protocol,
                   std::chrono::steady_clock::time_point now) {
    Key key{target_ip, target_port, remote_ip, remote_port, protocol};
    purge_expired(now);

    auto it = map_.find(key);
    if (it == map_.end()) {
        return std::nullopt;
    }

    LookupResult result{it->second.original_ip, it->second.original_port,
                        it->second.connection_oriented};
    it->second.expires_at = now + kDefaultTtl;
    lru_.erase(it->second.lru_it);
    lru_.push_back(key);
    it->second.lru_it = std::prev(lru_.end());

    return result;
}

void DnatTable::clear() {
    map_.clear();
    lru_.clear();
}

void DnatTable::evict_if_needed() {
    while (map_.size() > kMaxEntries && !lru_.empty()) {
        const Key& oldest = lru_.front();
        auto it = map_.find(oldest);
        if (it != map_.end()) {
            map_.erase(it);
        }
        lru_.pop_front();
    }
}
