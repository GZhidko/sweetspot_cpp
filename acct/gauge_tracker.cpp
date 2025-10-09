#include "gauge_tracker.hpp"

#include <algorithm>

#include "../common/logger.h"

namespace accounting {

GaugeTracker& GaugeTracker::instance() {
    static GaugeTracker tracker;
    return tracker;
}

void GaugeTracker::set_limits(uint32_t ip, const Limits& limits) {
    if (ip == 0) {
        return;
    }
    std::scoped_lock lock(mutex_);
    Entry& entry = ensure_entry(ip);
    entry.limits = limits;
    LOG(DEBUG_ACCT, "acct gauge set_limits ip=", ip, " max_octets_in=", limits.max_octets_in,
        " max_octets_out=", limits.max_octets_out, " max_bps_in=", limits.max_bps_in,
        " max_bps_out=", limits.max_bps_out, " max_duration=",
        limits.max_duration.count(), " max_idle=", limits.max_idle.count());
}

void GaugeTracker::record(uint32_t ip, size_t octets, Direction direction) {
    if (ip == 0) {
        return;
    }
    auto now = Clock::now();
    std::scoped_lock lock(mutex_);
    Entry& entry = ensure_entry(ip);
    if (!entry.initialized) {
        entry.first_seen = now;
        entry.last_activity = now;
        entry.last_in_sample = now;
        entry.last_out_sample = now;
        entry.initialized = true;
        LOG(DEBUG_ACCT, "acct gauge init ip=", ip);
    }

    entry.last_activity = now;

    if (direction == Direction::Inbound) {
        entry.octets_in += octets;
        entry.packets_in += 1;
        entry.bytes_since_last_in += octets;
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - entry.last_in_sample);
        if (elapsed.count() >= 1) {
            const auto bits = static_cast<uint64_t>(entry.bytes_since_last_in) * 8ULL;
            const auto bps = bits / static_cast<uint64_t>(elapsed.count());
            if (bps > entry.peak_bps_in) {
                entry.peak_bps_in = bps;
            }
            entry.bytes_since_last_in = 0;
            entry.last_in_sample = now;
            LOG(DEBUG_ACCT, "acct gauge inbound ip=", ip, " octets=", entry.octets_in,
                " peak_bps=", entry.peak_bps_in);
        }
    } else {
        entry.octets_out += octets;
        entry.packets_out += 1;
        entry.bytes_since_last_out += octets;
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - entry.last_out_sample);
        if (elapsed.count() >= 1) {
            const auto bits = static_cast<uint64_t>(entry.bytes_since_last_out) * 8ULL;
            const auto bps = bits / static_cast<uint64_t>(elapsed.count());
            if (bps > entry.peak_bps_out) {
                entry.peak_bps_out = bps;
            }
            entry.bytes_since_last_out = 0;
            entry.last_out_sample = now;
            LOG(DEBUG_ACCT, "acct gauge outbound ip=", ip, " octets=", entry.octets_out,
                " peak_bps=", entry.peak_bps_out);
        }
    }
}

GaugeTracker::Snapshot GaugeTracker::snapshot(uint32_t ip) const {
    Snapshot snapshot;
    if (ip == 0) {
        return snapshot;
    }
    auto now = Clock::now();
    std::scoped_lock lock(mutex_);
    auto it = entries_.find(ip);
    if (it == entries_.end() || !it->second.initialized) {
        return snapshot;
    }

    const Entry& entry = it->second;
    snapshot.valid = true;
    snapshot.limits = entry.limits;
    snapshot.octets_in = entry.octets_in;
    snapshot.octets_out = entry.octets_out;
    snapshot.packets_in = entry.packets_in;
    snapshot.packets_out = entry.packets_out;
    snapshot.peak_bps_in = entry.peak_bps_in;
    snapshot.peak_bps_out = entry.peak_bps_out;
    snapshot.duration = std::chrono::duration_cast<std::chrono::seconds>(now - entry.first_seen);
    snapshot.idle = std::chrono::duration_cast<std::chrono::seconds>(now - entry.last_activity);
    if (snapshot.duration.count() < 0) {
        snapshot.duration = std::chrono::seconds{0};
    }
    if (snapshot.idle.count() < 0) {
        snapshot.idle = std::chrono::seconds{0};
    }
    return snapshot;
}

void GaugeTracker::reset(uint32_t ip) {
    std::scoped_lock lock(mutex_);
    entries_.erase(ip);
    LOG(DEBUG_ACCT, "acct gauge reset ip=", ip);
}

void GaugeTracker::reset_all() {
    std::scoped_lock lock(mutex_);
    entries_.clear();
    LOG(DEBUG_ACCT, "acct gauge reset_all");
}

GaugeTracker::Entry& GaugeTracker::ensure_entry(uint32_t ip) {
    auto [it, inserted] = entries_.try_emplace(ip);
    if (inserted) {
        auto now = Clock::now();
        it->second.first_seen = now;
        it->second.last_activity = now;
        it->second.last_in_sample = now;
        it->second.last_out_sample = now;
        it->second.initialized = false;
    }
    return it->second;
}

} // namespace accounting
