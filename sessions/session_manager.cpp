#include "session_manager.hpp"

#include "../filters/filter_engine.hpp"
#include "../common/netset.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace sessions {

namespace {
std::string ip_to_string(uint32_t ip_host) {
    in_addr addr{};
    addr.s_addr = htonl(ip_host);
    char buf[INET_ADDRSTRLEN] = {};
    if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
        return "<invalid_ip>";
    }
    return buf;
}
}

SessionManager& SessionManager::instance() {
    static SessionManager manager;
    return manager;
}

void SessionManager::set_filters_directory(const std::filesystem::path& dir, bool recursive) {
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec)) {
        throw std::runtime_error("Filters directory not found: " + dir.string());
    }
    std::unique_lock lock(mutex_);
    filters_dir_ = dir;
    filters_recursive_ = recursive;
    filters::Engine::instance().load_directory(dir, recursive);
    if (default_filter_name_.empty()) {
        auto names = filters::Engine::instance().list_filters();
        if (!names.empty()) {
            default_filter_name_ = names.front();
        }
    }
}

Session SessionManager::start_session(uint32_t ip, const std::string& filter_name,
                                      const StartOptions& options) {
    std::unique_lock lock(mutex_);
    ensure_filter_loaded(filter_name);

    Session session;
    session.ip = ip;
    session.filter_name = filter_name.empty() ? default_filter_name_ : filter_name;
    session.status = options.status;
    session.session_id = options.session_id;
    if (session.session_id == 0) {
        session.session_id = next_session_id_++;
        if (next_session_id_ == 0) {
            next_session_id_ = 1;
        }
    }
    session.interim_interval = options.interim_interval;
    session.retention = options.retention.count() > 0 ? options.retention
                                                     : std::chrono::hours(1);
    session.session_context = options.session_context;
    session.event_context = options.event_context;
    session.termination_cause = TerminationCause::None;
    auto now = Clock::now();
    schedule_times(session, now);

    sessions_[ip] = session;

    if (default_filter_name_.empty()) {
        default_filter_name_ = session.filter_name;
    }

    if (const char* dbg = std::getenv("SWEETSPOT_SESSION_DEBUG")) {
        (void)dbg;
        std::cerr << "session start ip=" << ip_to_string(ip) << " filter='"
                  << session.filter_name << "'" << std::endl;
    }

    return session;
}

void SessionManager::stop_session(uint32_t ip, TerminationCause cause) {
    std::unique_lock lock(mutex_);
    auto it = sessions_.find(ip);
    if (it == sessions_.end()) {
        return;
    }
    it->second.status = SessionStatus::Captured;
    it->second.termination_cause = cause;
    schedule_times(it->second, Clock::now());

    if (const char* dbg = std::getenv("SWEETSPOT_SESSION_DEBUG")) {
        (void)dbg;
        std::cerr << "session stop ip=" << ip_to_string(ip) << " cause="
                  << static_cast<int>(cause) << std::endl;
    }
}

bool SessionManager::remove_session(uint32_t ip) {
    std::unique_lock lock(mutex_);
    return sessions_.erase(ip) > 0;
}

std::optional<Session> SessionManager::find_session(uint32_t ip) const {
    std::shared_lock lock(mutex_);
    auto it = sessions_.find(ip);
    if (it == sessions_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<Session> SessionManager::snapshot() const {
    std::shared_lock lock(mutex_);
    std::vector<Session> out;
    out.reserve(sessions_.size());
    for (const auto& [_, session] : sessions_) {
        out.push_back(session);
    }
    return out;
}

void SessionManager::set_default_filter(const std::string& filter_name) {
    std::unique_lock lock(mutex_);
    ensure_filter_loaded(filter_name);
    default_filter_name_ = filter_name;
}

std::string SessionManager::default_filter() const {
    std::shared_lock lock(mutex_);
    return default_filter_name_;
}

void SessionManager::set_callbacks(std::function<void(const Session&)> interim_callback,
                                   std::function<void(const Session&)> expire_callback) {
    std::unique_lock lock(mutex_);
    interim_callback_ = std::move(interim_callback);
    expire_callback_ = std::move(expire_callback);
}

void SessionManager::run_maintenance() {
    run_maintenance(Clock::now());
}

void SessionManager::run_maintenance(Clock::time_point now) {
    std::vector<Session> interim_due;
    std::vector<Session> expired;

    {
        std::unique_lock lock(mutex_);
        for (auto& [ip, session] : sessions_) {
            if (session.status == SessionStatus::Released &&
                session.interim_interval.count() > 0 &&
                session.next_interim != Clock::time_point{} && session.next_interim <= now) {
                if (interim_callback_) {
                    interim_due.push_back(session);
                }
                session.next_interim = now + session.interim_interval;
                session.updated_at = now;
            }

            if (session.status == SessionStatus::Captured &&
                session.death_at != Clock::time_point{} && session.death_at <= now) {
                session.death_at = Clock::time_point{};
                session.next_interim = Clock::time_point{};
                session.termination_cause = TerminationCause::Time;
                if (expire_callback_) {
                    expired.push_back(session);
                }
            }
        }
    }

    for (const auto& session : interim_due) {
        try {
            if (interim_callback_) {
                interim_callback_(session);
            }
        } catch (...) {
            // Swallow exceptions to keep maintenance loop robust
        }
    }

    for (const auto& session : expired) {
        try {
            if (expire_callback_) {
                expire_callback_(session);
            }
        } catch (...) {
            // ignore
        }
    }
}

void SessionManager::initialize_from_netset(std::shared_ptr<Netset> netset,
                                            const std::string& default_filter) {
    if (!netset) {
        throw std::invalid_argument("initialize_from_netset requires non-null netset");
    }
    std::unique_lock lock(mutex_);
    if (initialized_) {
        return;
    }
    netset_ = netset;
    if (!default_filter.empty()) {
        ensure_filter_loaded(default_filter);
        default_filter_name_ = default_filter;
    } else if (default_filter_name_.empty()) {
        auto names = filters::Engine::instance().list_filters();
        if (!names.empty()) {
            default_filter_name_ = names.front();
        }
    }

    uint32_t total = netset_->size();
    sessions_.reserve(total);
    auto now = Clock::now();
    for (uint32_t idx = 0; idx < total; ++idx) {
        uint32_t ip = netset_->ip(idx);
        Session session;
        session.ip = ip;
        session.filter_name = default_filter_name_;
        session.status = SessionStatus::Captured;
        session.session_id = next_session_id_++;
        session.retention = std::chrono::hours(1);
        schedule_times(session, now);
        sessions_.emplace(ip, std::move(session));
    }
    initialized_ = true;
}

void SessionManager::ensure_filter_loaded(const std::string& filter_name) {
    if (filter_name.empty()) {
        return;
    }
    auto names = filters::Engine::instance().list_filters();
    if (std::find(names.begin(), names.end(), filter_name) != names.end()) {
        return;
    }
    if (filters_dir_.empty()) {
        throw std::runtime_error("Filter '" + filter_name + "' not loaded and no directory set");
    }
    auto candidate = filters_dir_ / filter_name;
    std::error_code ec;
    if (std::filesystem::is_regular_file(candidate, ec)) {
        filters::Engine::instance().load_filter(filter_name, candidate);
        return;
    }
    // Try with .conf extension for compatibility
    candidate.replace_extension(".conf");
    if (std::filesystem::is_regular_file(candidate, ec)) {
        filters::Engine::instance().load_filter(filter_name, candidate);
        return;
    }
    throw std::runtime_error("Filter file not found for '" + filter_name + "'");
}

void SessionManager::schedule_times(Session& session, Clock::time_point now) {
    session.updated_at = now;
    if (session.retention.count() > 0) {
        session.death_at = now + session.retention;
    } else {
        session.death_at = Clock::time_point{};
    }
    if (session.status == SessionStatus::Released && session.interim_interval.count() > 0) {
        session.next_interim = now + session.interim_interval;
    } else {
        session.next_interim = Clock::time_point{};
    }
}

} // namespace sessions
