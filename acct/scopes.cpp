#include "scopes.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string_view>

namespace accounting {
namespace {

std::string format_ip(uint32_t ip_host_order) {
    in_addr addr{};
    addr.s_addr = htonl(ip_host_order);
    char buf[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
        return "<invalid_ip>";
    }
    return std::string(buf);
}

std::string quoted(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 2);
    out.push_back('"');
    out.append(value);
    out.push_back('"');
    return out;
}

std::string format_port(uint16_t port) { return std::to_string(static_cast<unsigned int>(port)); }

std::string termination_cause_to_string(sessions::TerminationCause cause) {
    switch (cause) {
    case sessions::TerminationCause::Idle: return "Idle-Timeout";
    case sessions::TerminationCause::Time: return "Session-Timeout";
    case sessions::TerminationCause::Volume: return "Service-Unavailable";
    case sessions::TerminationCause::Admin: return "Admin-Reset";
    case sessions::TerminationCause::User: return "User-Request";
    case sessions::TerminationCause::None: break;
    }
    return "NAS-Error";
}

} // namespace

EventScope::EventScope(RecordType type, std::chrono::system_clock::time_point timestamp,
                       std::string event_context)
    : type_(type), timestamp_(timestamp), event_context_(std::move(event_context)) {}

void EventScope::append_detail(std::string& buffer, std::chrono::seconds) const {
    buffer.append("\tAcct-Status-Type = ");
    switch (type_) {
    case RecordType::Start: buffer.append("Start\n"); break;
    case RecordType::Stop:
    case RecordType::StopTime: buffer.append("Stop\n"); break;
    case RecordType::Interim: buffer.append("Interim-Update\n"); break;
    }

    auto ts = std::chrono::system_clock::to_time_t(timestamp_);
    buffer.append("\tEvent-Timestamp = ");
    buffer.append(std::to_string(static_cast<unsigned long>(ts)));
    buffer.push_back('\n');

    if (!event_context_.empty()) {
        buffer.append("\tSweet-Event-Context = ");
        buffer.append(quoted(event_context_));
        buffer.push_back('\n');
    }
}

std::string EventScope::pretty() const { return to_string(type_); }

SessionScope::SessionScope(const sessions::Session& session, RecordType type)
    : type_(type),
      ip_(session.ip),
      session_id_(session.session_id),
      termination_cause_(session.termination_cause),
      session_context_(session.session_context),
      filter_name_(session.filter_name) {}

void SessionScope::append_detail(std::string& buffer, std::chrono::seconds) const {
    char id_buf[16];
    std::snprintf(id_buf, sizeof(id_buf), "%08lX", static_cast<unsigned long>(session_id_));
    buffer.append("\tAcct-Session-Id = ");
    buffer.append(quoted(id_buf));
    buffer.push_back('\n');
    buffer.append("\tService-Type = Login\n");
    buffer.append("\tFramed-IP-Address = ");
    buffer.append(format_ip(ip_));
    buffer.push_back('\n');

    if (!filter_name_.empty()) {
        buffer.append("\tFilter-Id = ");
        buffer.append(quoted(filter_name_));
        buffer.push_back('\n');
    }

    if (type_ == RecordType::Stop || type_ == RecordType::StopTime) {
        buffer.append("\tAcct-Terminate-Cause = ");
        buffer.append(termination_cause_to_string(termination_cause_));
        buffer.push_back('\n');
        if (termination_cause_ == sessions::TerminationCause::Volume) {
            buffer.append("\tSweet-Session-Terminate-Cause = Traffic-Exhausted\n");
        }
    }

    if (!session_context_.empty()) {
        buffer.append("\tSweet-Session-Context = ");
        buffer.append(quoted(session_context_));
        buffer.push_back('\n');
    }
}

std::string SessionScope::pretty() const {
    char id_buf[16];
    std::snprintf(id_buf, sizeof(id_buf), "%08lX", static_cast<unsigned long>(session_id_));
    return id_buf;
}

GaugeScope::GaugeScope(GaugeTracker::Snapshot snapshot, RecordType type)
    : snapshot_(std::move(snapshot)), type_(type) {}

void GaugeScope::append_detail(std::string& buffer, std::chrono::seconds delay) const {
    if (!snapshot_.valid) {
        return;
    }

    const auto delay_seconds = static_cast<uint64_t>(delay.count());
    const auto idle_seconds = static_cast<uint64_t>(std::max<std::int64_t>(0, snapshot_.idle.count()));
    buffer.append("\tAcct-Delay-Time = ");
    buffer.append(std::to_string(delay_seconds + idle_seconds));
    buffer.push_back('\n');

    if (type_ == RecordType::Interim || type_ == RecordType::Stop || type_ == RecordType::StopTime) {
        const auto octets_in_lo = static_cast<uint32_t>(snapshot_.octets_in & 0xFFFFFFFFULL);
        const auto octets_out_lo = static_cast<uint32_t>(snapshot_.octets_out & 0xFFFFFFFFULL);

        buffer.append("\tAcct-Input-Octets = ");
        buffer.append(std::to_string(octets_in_lo));
        buffer.push_back('\n');
        buffer.append("\tAcct-Output-Octets = ");
        buffer.append(std::to_string(octets_out_lo));
        buffer.push_back('\n');

        const auto octets_in_hi = snapshot_.octets_in >> 32;
        const auto octets_out_hi = snapshot_.octets_out >> 32;
        if (octets_in_hi) {
            buffer.append("\tAcct-Input-Gigawords = ");
            buffer.append(std::to_string(static_cast<uint32_t>(octets_in_hi)));
            buffer.push_back('\n');
        }
        if (octets_out_hi) {
            buffer.append("\tAcct-Output-Gigawords = ");
            buffer.append(std::to_string(static_cast<uint32_t>(octets_out_hi)));
            buffer.push_back('\n');
        }

        buffer.append("\tAcct-Input-Packets = ");
        buffer.append(std::to_string(static_cast<uint32_t>(snapshot_.packets_in & 0xFFFFFFFFULL)));
        buffer.push_back('\n');
        buffer.append("\tAcct-Output-Packets = ");
        buffer.append(std::to_string(static_cast<uint32_t>(snapshot_.packets_out & 0xFFFFFFFFULL)));
        buffer.push_back('\n');

        buffer.append("\tBandwidth-Max-Up = ");
        buffer.append(std::to_string(snapshot_.peak_bps_in));
        buffer.push_back('\n');
        buffer.append("\tBandwidth-Max-Down = ");
        buffer.append(std::to_string(snapshot_.peak_bps_out));
        buffer.push_back('\n');

        auto duration_seconds = static_cast<int64_t>(snapshot_.duration.count()) -
                                static_cast<int64_t>(snapshot_.idle.count());
        if (duration_seconds < 0) {
            duration_seconds = 0;
        }
        buffer.append("\tAcct-Session-Time = ");
        buffer.append(std::to_string(static_cast<uint64_t>(duration_seconds)));
        buffer.push_back('\n');
    }

    if (snapshot_.limits.max_octets_in != 0xfffffffffff70000ULL) {
        buffer.append("\tSweet-Max-Octets-In = ");
        buffer.append(quoted(std::to_string(snapshot_.limits.max_octets_in)));
        buffer.push_back('\n');
    }
    if (snapshot_.limits.max_octets_out != 0xfffffffffff70000ULL) {
        buffer.append("\tSweet-Max-Octets-Out = ");
        buffer.append(quoted(std::to_string(snapshot_.limits.max_octets_out)));
        buffer.push_back('\n');
    }
    if (snapshot_.limits.max_bps_in != 0xfffffffffff70000ULL) {
        buffer.append("\tSweet-Max-Bps-Up = ");
        buffer.append(quoted(std::to_string(snapshot_.limits.max_bps_in)));
        buffer.push_back('\n');
    }
    if (snapshot_.limits.max_bps_out != 0xfffffffffff70000ULL) {
        buffer.append("\tSweet-Max-Bps-Down = ");
        buffer.append(quoted(std::to_string(snapshot_.limits.max_bps_out)));
        buffer.push_back('\n');
    }

    buffer.append("\tSweet-Max-Duration = ");
    buffer.append(std::to_string(static_cast<uint64_t>(snapshot_.limits.max_duration.count())));
    buffer.push_back('\n');
    buffer.append("\tSweet-Max-Idle = ");
    buffer.append(std::to_string(static_cast<uint64_t>(snapshot_.limits.max_idle.count())));
    buffer.push_back('\n');
}

std::string GaugeScope::pretty() const { return "gauge"; }

SnatScope::SnatScope(SnatTracker::Snapshot snapshot) : snapshot_(std::move(snapshot)) {}

void SnatScope::append_detail(std::string& buffer, std::chrono::seconds) const {
    if (!snapshot_.valid) {
        return;
    }
    buffer.append("\tSweet-SNAT-IP-Address = ");
    buffer.append(format_ip(snapshot_.public_ip));
    buffer.push_back('\n');
    if (snapshot_.has_tcp) {
        buffer.append("\tSweet-SNAT-TCP-Port-Low = ");
        buffer.append(format_port(snapshot_.tcp_low));
        buffer.push_back('\n');
        buffer.append("\tSweet-SNAT-TCP-Port-High = ");
        buffer.append(format_port(snapshot_.tcp_high));
        buffer.push_back('\n');
    }
    if (snapshot_.has_udp) {
        buffer.append("\tSweet-SNAT-UDP-Port-Low = ");
        buffer.append(format_port(snapshot_.udp_low));
        buffer.push_back('\n');
        buffer.append("\tSweet-SNAT-UDP-Port-High = ");
        buffer.append(format_port(snapshot_.udp_high));
        buffer.push_back('\n');
    }
    if (snapshot_.has_icmp) {
        buffer.append("\tSweet-SNAT-ICMP-Seq-Low = ");
        buffer.append(std::to_string(snapshot_.icmp_low));
        buffer.push_back('\n');
        buffer.append("\tSweet-SNAT-ICMP-Seq-High = ");
        buffer.append(std::to_string(snapshot_.icmp_high));
        buffer.push_back('\n');
    }
}

std::string SnatScope::pretty() const {
    return snapshot_.valid ? format_ip(snapshot_.public_ip) : std::string("snat");
}

} // namespace accounting
