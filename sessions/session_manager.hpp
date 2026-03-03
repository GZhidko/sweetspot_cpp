#pragma once

#include "session.hpp"

#include <atomic>
#include <optional>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <filesystem>
#include <functional>
#include <chrono>

class Netset;

namespace sessions {

class SessionManager {
  public:
    using Clock = std::chrono::steady_clock;

    static SessionManager& instance();

    void set_filters_directory(const std::filesystem::path& dir, bool recursive = true);

    Session start_session(uint32_t ip, const std::string& filter_name,
                          const StartOptions& options = {});
    void stop_session(uint32_t ip, TerminationCause cause = TerminationCause::Admin);
    bool remove_session(uint32_t ip);

    std::optional<Session> find_session(uint32_t ip) const;
    bool find_session_fast(uint32_t ip, SessionStatus& status,
                           std::shared_ptr<const std::string>& filter_name) const;
    std::vector<Session> snapshot() const;

    void set_default_filter(const std::string& filter_name);
    std::string default_filter() const;

    void set_callbacks(std::function<void(const Session&)> interim_callback,
                       std::function<void(const Session&)> expire_callback);

    void run_maintenance();
    void run_maintenance(Clock::time_point now);

    void initialize_from_netset(std::shared_ptr<Netset> netset,
                                const std::string& default_filter = {});

    bool acquire_state_id(uint32_t ip, int& state_id, bool modified);
    bool verify_state_id(uint32_t ip, int& state_id) const;

  private:
    SessionManager() = default;

    void ensure_filter_loaded(const std::string& filter_name);
    void schedule_times(Session& session, Clock::time_point now);
    std::shared_ptr<const std::string> intern_filter_name_unlocked(const std::string& filter_name);
    void update_fast_slot_unlocked(const Session& session);

    mutable std::shared_mutex mutex_;
    std::unordered_map<uint32_t, Session> sessions_;
    std::filesystem::path filters_dir_;
    bool filters_recursive_ = true;
    std::string default_filter_name_;
    uint32_t next_session_id_ = 1;
    std::function<void(const Session&)> interim_callback_;
    std::function<void(const Session&)> expire_callback_;
    std::shared_ptr<Netset> netset_;
    std::unique_ptr<std::atomic<uint8_t>[]> fast_status_;
    size_t fast_status_size_ = 0;
    std::vector<std::shared_ptr<const std::string>> fast_filter_ptrs_;
    std::unordered_map<std::string, std::shared_ptr<const std::string>> filter_name_pool_;
    std::atomic<bool> fast_ready_{false};
    bool initialized_ = false;
};

} // namespace sessions
