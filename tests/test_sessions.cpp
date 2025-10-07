#include "filters/filter_engine.hpp"
#include "filters/filter_runtime.hpp"
#include "sessions/session_manager.hpp"

#include <arpa/inet.h>

#include <cassert>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <vector>

namespace {
uint32_t ip_from_string(const char* str) {
    in_addr addr{};
    if (inet_pton(AF_INET, str, &addr) != 1) {
        std::cerr << "failed to parse ip" << std::endl;
        std::abort();
    }
    return ntohl(addr.s_addr);
}
}

int main() {
    auto repo_root = std::filesystem::path(__FILE__).parent_path().parent_path();
    auto filters_dir = repo_root / "filters" / "filters";
    assert(std::filesystem::exists(filters_dir));

    auto& engine = filters::Engine::instance();
    engine.load_directory(filters_dir, true);

    auto& manager = sessions::SessionManager::instance();
    manager.set_filters_directory(filters_dir, true);
    manager.set_default_filter("anonymous");

    std::vector<std::string> interim_events;
    std::vector<std::string> expired_events;
    manager.set_callbacks(
        [&](const sessions::Session& s) {
            interim_events.push_back(filters::Engine::instance().default_filter_name());
        },
        [&](const sessions::Session& s) {
            expired_events.push_back(filters::Engine::instance().default_filter_name());
        });

    sessions::StartOptions opts;
    opts.status = sessions::SessionStatus::Released;
    opts.interim_interval = std::chrono::seconds(5);
    opts.retention = std::chrono::seconds(30);
    auto session = manager.start_session(ip_from_string("10.0.0.10"), "example", opts);
    assert(session.filter_name == "example");
    auto fetched = manager.find_session(ip_from_string("10.0.0.10"));
    assert(fetched.has_value());
    assert(fetched->status == sessions::SessionStatus::Released);

    filters::set_current_filter(fetched->filter_name);
    filters::PacketState state;
    state.direction = filters::Direction::Outbound;
    state.has_ipv4 = true;
    state.src_ip = session.ip;
    state.dst_ip = ip_from_string("203.0.113.8");
    state.protocol = IPPROTO_TCP;
    auto decision = engine.evaluate(state, fetched->filter_name);
    (void)decision;

    manager.run_maintenance(sessions::SessionManager::Clock::now() + std::chrono::seconds(10));
    assert(!interim_events.empty());

    manager.stop_session(session.ip, sessions::TerminationCause::Admin);
    auto stopped = manager.find_session(session.ip);
    assert(stopped.has_value());
    assert(stopped->status == sessions::SessionStatus::Captured);

    manager.run_maintenance(sessions::SessionManager::Clock::now() + std::chrono::seconds(60));
    assert(!expired_events.empty());
    auto after = manager.find_session(session.ip);
    assert(after.has_value());
    assert(after->status == sessions::SessionStatus::Captured);

    return 0;
}
