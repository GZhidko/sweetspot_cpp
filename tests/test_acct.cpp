#include "acct/gauge_tracker.hpp"
#include "acct/manager.hpp"
#include "acct/snat_tracker.hpp"
#include "sessions/session.hpp"

#include <arpa/inet.h>

#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>

namespace {

uint32_t ip_from_string(const char* str) {
    in_addr addr{};
    auto rc = ::inet_pton(AF_INET, str, &addr);
    (void)rc;
    return ntohl(addr.s_addr);
}

} // namespace

int main() {
    using namespace std::chrono_literals;

    accounting::Manager::instance().reset_for_tests();
    accounting::GaugeTracker::instance().reset_all();
    accounting::SnatTracker::instance().reset_all();

    auto path = std::filesystem::temp_directory_path() / "sweetspot_acct_test.detail";
    std::filesystem::remove(path);

    accounting::Config cfg;
    cfg.detail_file = path.string();
    accounting::Manager::instance().configure(cfg);

    sessions::Session session;
    session.ip = ip_from_string("10.0.0.10");
    session.filter_name = "example";
    session.status = sessions::SessionStatus::Released;
    session.session_id = 0xABCDEF;
    session.interim_interval = std::chrono::seconds(300);
    session.retention = std::chrono::seconds(1800);
    session.session_context = "ctx";
    session.event_context = "evt";
    session.termination_cause = sessions::TerminationCause::User;

    accounting::GaugeTracker::instance().reset(session.ip);
    accounting::GaugeTracker::Limits limits;
    limits.max_duration = session.retention;
    limits.max_idle = session.interim_interval;
    accounting::GaugeTracker::instance().set_limits(session.ip, limits);
    accounting::GaugeTracker::instance().record(session.ip, 1500,
                                               accounting::GaugeTracker::Direction::Outbound);
    std::this_thread::sleep_for(5ms);
    accounting::GaugeTracker::instance().record(session.ip, 3000,
                                               accounting::GaugeTracker::Direction::Inbound);

    accounting::SnatTracker::instance().reset(session.ip);
    accounting::SnatTracker::instance().observe_tcp(session.ip, ip_from_string("198.51.100.10"),
                                                    40000);

    accounting::Manager::instance().submit(session, accounting::RecordType::Interim,
                                           session.event_context);
    accounting::Manager::instance().commit(true);

    std::ifstream input(path);
    assert(input.good());
    std::string content((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());

    assert(content.find("Acct-Status-Type = Interim-Update") != std::string::npos);
    assert(content.find("Framed-IP-Address = 10.0.0.10") != std::string::npos);
    assert(content.find("Sweet-SNAT-IP-Address = 198.51.100.10") != std::string::npos);

    return 0;
}
