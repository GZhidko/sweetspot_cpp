#include "snat_tracker.hpp"

#include <algorithm>

namespace accounting {

SnatTracker& SnatTracker::instance() {
    static SnatTracker tracker;
    return tracker;
}

void SnatTracker::observe_tcp(uint32_t private_ip, uint32_t public_ip, uint16_t public_port) {
    if (private_ip == 0 || public_ip == 0) {
        return;
    }
    std::scoped_lock lock(mutex_);
    Entry& entry = entries_[private_ip];
    observe(entry, public_ip);
    if (!entry.has_tcp) {
        entry.tcp_low = entry.tcp_high = public_port;
        entry.has_tcp = true;
    } else {
        entry.tcp_low = std::min(entry.tcp_low, public_port);
        entry.tcp_high = std::max(entry.tcp_high, public_port);
    }
}

void SnatTracker::observe_udp(uint32_t private_ip, uint32_t public_ip, uint16_t public_port) {
    if (private_ip == 0 || public_ip == 0) {
        return;
    }
    std::scoped_lock lock(mutex_);
    Entry& entry = entries_[private_ip];
    observe(entry, public_ip);
    if (!entry.has_udp) {
        entry.udp_low = entry.udp_high = public_port;
        entry.has_udp = true;
    } else {
        entry.udp_low = std::min(entry.udp_low, public_port);
        entry.udp_high = std::max(entry.udp_high, public_port);
    }
}

void SnatTracker::observe_icmp(uint32_t private_ip, uint32_t public_ip, uint16_t public_id) {
    if (private_ip == 0 || public_ip == 0) {
        return;
    }
    std::scoped_lock lock(mutex_);
    Entry& entry = entries_[private_ip];
    observe(entry, public_ip);
    if (!entry.has_icmp) {
        entry.icmp_low = entry.icmp_high = public_id;
        entry.has_icmp = true;
    } else {
        entry.icmp_low = std::min(entry.icmp_low, public_id);
        entry.icmp_high = std::max(entry.icmp_high, public_id);
    }
}

SnatTracker::Snapshot SnatTracker::snapshot(uint32_t private_ip) const {
    Snapshot snapshot;
    if (private_ip == 0) {
        return snapshot;
    }
    std::scoped_lock lock(mutex_);
    auto it = entries_.find(private_ip);
    if (it == entries_.end() || !it->second.has_public_ip) {
        return snapshot;
    }
    const Entry& entry = it->second;
    snapshot.valid = true;
    snapshot.public_ip = entry.public_ip;
    snapshot.has_tcp = entry.has_tcp;
    snapshot.tcp_low = entry.tcp_low;
    snapshot.tcp_high = entry.tcp_high;
    snapshot.has_udp = entry.has_udp;
    snapshot.udp_low = entry.udp_low;
    snapshot.udp_high = entry.udp_high;
    snapshot.has_icmp = entry.has_icmp;
    snapshot.icmp_low = entry.icmp_low;
    snapshot.icmp_high = entry.icmp_high;
    return snapshot;
}

void SnatTracker::reset(uint32_t private_ip) {
    std::scoped_lock lock(mutex_);
    entries_.erase(private_ip);
}

void SnatTracker::reset_all() {
    std::scoped_lock lock(mutex_);
    entries_.clear();
}

void SnatTracker::observe(Entry& entry, uint32_t public_ip) {
    if (!entry.has_public_ip) {
        entry.public_ip = public_ip;
        entry.has_public_ip = true;
    }
}

} // namespace accounting
