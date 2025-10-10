#include "dnat_table.hpp"

#include <functional>

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

DnatTable& DnatTable::instance() {
    static DnatTable table;
    return table;
}

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

std::size_t DnatTable::stripe_for(const Key& key) const noexcept {
    return KeyHash{}(key) % kStripeCount;
}

void DnatTable::purge_expired_locked(Map& map, std::chrono::steady_clock::time_point now) {
    for (auto it = map.begin(); it != map.end();) {
        if (it->second.expires_at <= now) {
            it = map.erase(it);
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
    std::size_t stripe = stripe_for(key);
    std::lock_guard<std::mutex> lock(mutexes_[stripe]);
    auto& map = maps_[stripe];
    purge_expired_locked(map, now);

    Entry& entry = map[key];
    entry.original_ip = original_ip;
    entry.original_port = original_port;
    entry.connection_oriented = connection_oriented;
    entry.expires_at = now + kDefaultTtl;
}

std::optional<DnatTable::LookupResult>
DnatTable::consume(uint32_t target_ip, uint16_t target_port,
                   uint32_t remote_ip, uint16_t remote_port,
                   uint8_t protocol,
                   std::chrono::steady_clock::time_point now) {
    Key key{target_ip, target_port, remote_ip, remote_port, protocol};
    std::size_t stripe = stripe_for(key);
    std::lock_guard<std::mutex> lock(mutexes_[stripe]);
    auto& map = maps_[stripe];
    purge_expired_locked(map, now);

    auto it = map.find(key);
    if (it == map.end()) {
        return std::nullopt;
    }

    LookupResult result{it->second.original_ip, it->second.original_port,
                        it->second.connection_oriented};
    it->second.expires_at = now + kDefaultTtl;
    return result;
}

void DnatTable::clear() {
    for (std::size_t stripe = 0; stripe < kStripeCount; ++stripe) {
        std::lock_guard<std::mutex> lock(mutexes_[stripe]);
        maps_[stripe].clear();
    }
}
