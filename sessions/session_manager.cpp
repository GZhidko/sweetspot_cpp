#include "session_manager.hpp"

#include "../acct/gauge_tracker.hpp"
#include "../acct/manager.hpp"
#include "../acct/snat_tracker.hpp"
#include "../filters/filter_engine.hpp"
#include "../common/netset.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <limits>
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
    LOG(DEBUG_SESSION, "filters directory set to ", dir, " recursive=", recursive);
}

Session SessionManager::start_session(uint32_t ip, const std::string& filter_name,
                                      const StartOptions& options) {
    std::unique_lock lock(mutex_);
    LOG(DEBUG_SESSION, "start request ip=", ip_to_string(ip), " filter=", filter_name,
        " status=", static_cast<int>(options.status),
        " interim=", options.interim_interval.count(),
        " retention=", options.retention.count(),
        " session_ctx=", options.session_context,
        " event_ctx=", options.event_context);
    ensure_filter_loaded(filter_name);

    auto it = sessions_.find(ip);
    if (it == sessions_.end()) {
        Session base;
        base.ip = ip;
        base.filter_name = default_filter_name_;
        schedule_times(base, Clock::now());
        it = sessions_.emplace(ip, std::move(base)).first;
    }

    Session& session = it->second;
    session.filter_name = filter_name.empty() ? default_filter_name_ : filter_name;
    session.status = options.status;
    if (options.session_id != 0) {
        session.session_id = options.session_id;
    } else {
        session.session_id = next_session_id_++;
        if (next_session_id_ == 0) {
            next_session_id_ = 1;
        }
    }
    session.interim_interval = options.interim_interval;
    if (options.retention.count() > 0) {
        session.retention = options.retention;
    }
    session.session_context = options.session_context;
    session.event_context = options.event_context;
    session.termination_cause = TerminationCause::None;
    schedule_times(session, Clock::now());

    if (default_filter_name_.empty()) {
        default_filter_name_ = session.filter_name;
    }

    LOG(DEBUG_SESSION, "start created ip=", ip_to_string(ip), " filter=", session.filter_name,
        " session_id=", session.session_id, " status=", static_cast<int>(session.status));

    Session result = session;
    lock.unlock();

    accounting::GaugeTracker::instance().reset(result.ip);
    accounting::SnatTracker::instance().reset(result.ip);

    accounting::GaugeTracker::Limits limits;
    limits.max_duration = result.retention;
    if (result.interim_interval.count() > 0) {
        limits.max_idle = result.interim_interval;
    }
    accounting::GaugeTracker::instance().set_limits(result.ip, limits);
    accounting::Manager::instance().submit(result, accounting::RecordType::Start,
                                           result.event_context);

    return result;
}

void SessionManager::stop_session(uint32_t ip, TerminationCause cause) {
    std::unique_lock lock(mutex_);
    LOG(DEBUG_SESSION, "stop request ip=", ip_to_string(ip),
        " cause=", static_cast<int>(cause));
    auto it = sessions_.find(ip);
    if (it == sessions_.end()) {
        LOG(DEBUG_SESSION, "stop request missing ip=", ip_to_string(ip));
        return;
    }
    it->second.status = SessionStatus::Captured;
    it->second.termination_cause = cause;
    schedule_times(it->second, Clock::now());

    Session result = it->second;

    LOG(DEBUG_SESSION, "stop applied ip=", ip_to_string(ip),
        " cause=", static_cast<int>(cause),
        " status=", static_cast<int>(result.status));

    lock.unlock();

    auto record_type = (cause == TerminationCause::Idle || cause == TerminationCause::Time)
                           ? accounting::RecordType::StopTime
                           : accounting::RecordType::Stop;
    accounting::Manager::instance().submit(result, record_type, result.event_context);
}

bool SessionManager::remove_session(uint32_t ip) {
    std::unique_lock lock(mutex_);
    LOG(DEBUG_SESSION, "remove request ip=", ip_to_string(ip));
    auto it = sessions_.find(ip);
    if (it == sessions_.end()) {
        LOG(DEBUG_SESSION, "remove missing ip=", ip_to_string(ip));
        return false;
    }
    it->second.status = SessionStatus::Captured;
    it->second.termination_cause = TerminationCause::None;
    it->second.session_context.clear();
    it->second.event_context.clear();
    schedule_times(it->second, Clock::now());
    Session result = it->second;

    LOG(DEBUG_SESSION, "remove reset session ip=", ip_to_string(ip));

    lock.unlock();

    accounting::GaugeTracker::instance().reset(ip);
    accounting::SnatTracker::instance().reset(ip);
    return true;
}

std::optional<Session> SessionManager::find_session(uint32_t ip) const {
    std::shared_lock lock(mutex_);
    auto it = sessions_.find(ip);
    if (it == sessions_.end()) {
        LOG(DEBUG_SESSION, "find miss ip=", ip_to_string(ip));
        return std::nullopt;
    }
    LOG(DEBUG_SESSION, "find hit ip=", ip_to_string(ip), " status=",
        static_cast<int>(it->second.status), " filter=", it->second.filter_name);
    return it->second;
}

std::vector<Session> SessionManager::snapshot() const {
    std::shared_lock lock(mutex_);
    std::vector<Session> out;
    out.reserve(sessions_.size());
    for (const auto& [_, session] : sessions_) {
        out.push_back(session);
    }
    LOG(DEBUG_SESSION, "snapshot size=", out.size());
    return out;
}

void SessionManager::set_default_filter(const std::string& filter_name) {
    std::unique_lock lock(mutex_);
    ensure_filter_loaded(filter_name);
    default_filter_name_ = filter_name;
    LOG(DEBUG_SESSION, "default filter set name=", default_filter_name_);
}

std::string SessionManager::default_filter() const {
    std::shared_lock lock(mutex_);
    LOG(DEBUG_SESSION, "default filter query result=", default_filter_name_);
    return default_filter_name_;
}

void SessionManager::set_callbacks(std::function<void(const Session&)> interim_callback,
                                   std::function<void(const Session&)> expire_callback) {
    std::unique_lock lock(mutex_);
    interim_callback_ = std::move(interim_callback);
    expire_callback_ = std::move(expire_callback);
    LOG(DEBUG_SESSION, "callbacks set interim=", static_cast<bool>(interim_callback_),
        " expire=", static_cast<bool>(expire_callback_));
}

void SessionManager::run_maintenance() {
    LOG(DEBUG_SESSION, "maintenance run default now");
    run_maintenance(Clock::now());
}

void SessionManager::run_maintenance(Clock::time_point now) {
    LOG(DEBUG_SESSION, "maintenance start now=", now.time_since_epoch().count());
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
                LOG(DEBUG_SESSION, "interim scheduled ip=", ip_to_string(ip),
                    " next=", session.interim_interval.count(), "s");
            }

            if (session.status == SessionStatus::Captured &&
                session.death_at != Clock::time_point{} && session.death_at <= now) {
                session.death_at = Clock::time_point{};
                session.next_interim = Clock::time_point{};
                session.termination_cause = TerminationCause::Time;
                if (expire_callback_) {
                    expired.push_back(session);
                }
                LOG(DEBUG_SESSION, "retention expired ip=", ip_to_string(ip));
            }
        }
    }

    LOG(DEBUG_SESSION, "maintenance due interim=", interim_due.size(),
        " expired=", expired.size());

    for (const auto& session : interim_due) {
        accounting::Manager::instance().submit(session, accounting::RecordType::Interim,
                                              session.event_context);
        try {
            if (interim_callback_) {
                interim_callback_(session);
            }
        } catch (...) {
            // Swallow exceptions to keep maintenance loop robust
        }
    }

    for (const auto& session : expired) {
        accounting::Manager::instance().submit(session, accounting::RecordType::StopTime,
                                              session.event_context);
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
        LOG(DEBUG_SESSION, "initialize_from_netset skipped already initialized");
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
    LOG(DEBUG_SESSION, "initialize_from_netset total=", total,
        " default_filter=", default_filter_name_);
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
    LOG(DEBUG_SESSION, "initialize_from_netset complete sessions=", sessions_.size());
}

bool SessionManager::acquire_state_id(uint32_t ip, int& state_id, bool modified) {
    std::unique_lock lock(mutex_);
    auto it = sessions_.find(ip);
    if (it == sessions_.end()) {
        LOG(DEBUG_SESSION, "acquire_state_id miss ip=", ip_to_string(ip));
        return false;
    }
    Session& session = it->second;
    if (modified) {
        session.state_id++;
        if (session.state_id == std::numeric_limits<int>::max()) {
            session.state_id = 1;
        }
    } else if (session.state_id == 0) {
        session.state_id = 1;
    }
    state_id = session.state_id;
    LOG(DEBUG_SESSION, "acquire_state_id ip=", ip_to_string(ip), " state_id=", state_id,
        " modified=", modified);
    return true;
}

bool SessionManager::verify_state_id(uint32_t ip, int& state_id) const {
    std::shared_lock lock(mutex_);
    auto it = sessions_.find(ip);
    if (it == sessions_.end()) {
        LOG(DEBUG_SESSION, "verify_state_id miss ip=", ip_to_string(ip));
        return false;
    }
    const Session& session = it->second;
    if (state_id != 0 && state_id != session.state_id) {
        state_id = session.state_id;
        LOG(DEBUG_SESSION, "verify_state_id mismatch ip=", ip_to_string(ip),
            " new_state_id=", state_id);
        return false;
    }
    state_id = session.state_id;
    LOG(DEBUG_SESSION, "verify_state_id ok ip=", ip_to_string(ip),
        " state_id=", state_id);
    return true;
}

void SessionManager::ensure_filter_loaded(const std::string& filter_name) {
    if (filter_name.empty()) {
        return;
    }
    auto names = filters::Engine::instance().list_filters();
    if (std::find(names.begin(), names.end(), filter_name) != names.end()) {
        return;
    }
    LOG(DEBUG_SESSION, "ensure_filter_loaded load name=", filter_name);
    if (filters_dir_.empty()) {
        throw std::runtime_error("Filter '" + filter_name + "' not loaded and no directory set");
    }
    auto candidate = filters_dir_ / filter_name;
    std::error_code ec;
    if (std::filesystem::is_regular_file(candidate, ec)) {
        filters::Engine::instance().load_filter(filter_name, candidate);
        LOG(DEBUG_SESSION, "loaded filter ", filter_name, " from ", candidate);
        return;
    }
    // Try with .conf extension for compatibility
    candidate.replace_extension(".conf");
    if (std::filesystem::is_regular_file(candidate, ec)) {
        filters::Engine::instance().load_filter(filter_name, candidate);
        LOG(DEBUG_SESSION, "loaded filter ", filter_name, " from ", candidate);
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
    LOG(DEBUG_SESSION, "schedule_times ip=", ip_to_string(session.ip),
        " status=", static_cast<int>(session.status),
        " retention=", session.retention.count(),
        " interim=", session.interim_interval.count());
}

} // namespace sessions
