#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <unordered_map>

namespace accounting {

class SnatTracker {
  public:
    struct Snapshot {
        bool valid = false;
        uint32_t public_ip = 0;
        bool has_tcp = false;
        uint16_t tcp_low = 0;
        uint16_t tcp_high = 0;
        bool has_udp = false;
        uint16_t udp_low = 0;
        uint16_t udp_high = 0;
        bool has_icmp = false;
        uint16_t icmp_low = 0;
        uint16_t icmp_high = 0;
    };

    static SnatTracker& instance();

    void observe_tcp(uint32_t private_ip, uint32_t public_ip, uint16_t public_port);
    void observe_udp(uint32_t private_ip, uint32_t public_ip, uint16_t public_port);
    void observe_icmp(uint32_t private_ip, uint32_t public_ip, uint16_t public_id);

    Snapshot snapshot(uint32_t private_ip) const;
    void reset(uint32_t private_ip);
    void reset_all();

  private:
    SnatTracker() = default;

    struct Entry {
        uint32_t public_ip = 0;
        bool has_public_ip = false;
        bool has_tcp = false;
        uint16_t tcp_low = 0;
        uint16_t tcp_high = 0;
        bool has_udp = false;
        uint16_t udp_low = 0;
        uint16_t udp_high = 0;
        bool has_icmp = false;
        uint16_t icmp_low = 0;
        uint16_t icmp_high = 0;
    };

    void observe(Entry& entry, uint32_t public_ip);

    mutable std::mutex mutex_;
    std::unordered_map<uint32_t, Entry> entries_;
};

} // namespace accounting
