#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <unordered_map>

namespace accounting {

class GaugeTracker {
  public:
    using Clock = std::chrono::steady_clock;

    enum class Direction { Inbound, Outbound };

    struct Limits {
        uint64_t max_octets_in = 0xfffffffffff70000ULL;
        uint64_t max_octets_out = 0xfffffffffff70000ULL;
        uint64_t max_bps_in = 0xfffffffffff70000ULL;
        uint64_t max_bps_out = 0xfffffffffff70000ULL;
        std::chrono::seconds max_duration{3600};
        std::chrono::seconds max_idle{600};
    };

    struct Snapshot {
        bool valid = false;
        Limits limits{};
        uint64_t octets_in = 0;
        uint64_t octets_out = 0;
        uint64_t packets_in = 0;
        uint64_t packets_out = 0;
        uint64_t peak_bps_in = 0;
        uint64_t peak_bps_out = 0;
        std::chrono::seconds duration{0};
        std::chrono::seconds idle{0};
    };

    static GaugeTracker& instance();

    void set_limits(uint32_t ip, const Limits& limits);
    void record(uint32_t ip, size_t octets, Direction direction);
    Snapshot snapshot(uint32_t ip) const;
    void reset(uint32_t ip);
    void reset_all();

  private:
    GaugeTracker() = default;

    struct Entry {
        Limits limits{};
        uint64_t octets_in = 0;
        uint64_t octets_out = 0;
        uint64_t packets_in = 0;
        uint64_t packets_out = 0;
        uint64_t peak_bps_in = 0;
        uint64_t peak_bps_out = 0;
        Clock::time_point first_seen = Clock::now();
        Clock::time_point last_activity = Clock::now();
        Clock::time_point last_in_sample = Clock::now();
        Clock::time_point last_out_sample = Clock::now();
        uint64_t bytes_since_last_in = 0;
        uint64_t bytes_since_last_out = 0;
        bool initialized = false;
    };

    Entry& ensure_entry(uint32_t ip);

    mutable std::mutex mutex_;
    std::unordered_map<uint32_t, Entry> entries_;
};

} // namespace accounting
