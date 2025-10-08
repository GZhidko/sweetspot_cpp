#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace sessions {

enum class SessionStatus { Captured = 1, Released = 2 };

enum class TerminationCause {
    None = 0,
    Time = 1,
    Idle = 2,
    Volume = 3,
    Admin = 4,
    User = 5
};

struct Session {
    uint32_t ip = 0; // host order
    std::string filter_name;
    SessionStatus status = SessionStatus::Captured;
    uint32_t session_id = 0;
    int state_id = 0;
    TerminationCause termination_cause = TerminationCause::None;
    std::chrono::seconds interim_interval{0};
    std::chrono::seconds retention{std::chrono::hours(1)};
    std::chrono::steady_clock::time_point updated_at{};
    std::chrono::steady_clock::time_point death_at{};
    std::chrono::steady_clock::time_point next_interim{};
    std::string session_context;
    std::string event_context;
};

struct StartOptions {
    SessionStatus status = SessionStatus::Released;
    uint32_t session_id = 0;
    std::chrono::seconds interim_interval{0};
    std::chrono::seconds retention{std::chrono::hours(1)};
    std::string session_context;
    std::string event_context;
};

} // namespace sessions
