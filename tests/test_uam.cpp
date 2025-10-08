#include "uam/uam_message.hpp"
#include "uam/uam_server.hpp"
#include "filters/filter_engine.hpp"
#include "sessions/session_manager.hpp"
#include "common/netset.hpp"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <iostream>

int main() {
    using namespace uam;

    {
        std::vector<std::string> argv = {"UP", "203.0.113.10", "arg1", "arg2"};
        auto encoded = build_message(argv);
        auto decoded = parse_message(encoded);
        assert(!decoded.serial.has_value());
        assert(!decoded.state_id.has_value());
        assert(decoded.arguments == argv);
    }

    {
        std::vector<std::string> argv = {"123", "5", "DN", "203.0.113.10", "bye"};
        auto encoded = build_message(argv);
        auto decoded = parse_message(encoded);
        assert(decoded.serial == 123);
        assert(decoded.state_id == 5);
        std::vector<std::string> expected = {"DN", "203.0.113.10", "bye"};
        assert(decoded.arguments == expected);
    }

    try {
        std::vector<std::string> big = {std::string(uam::kMaxArgSize, 'a')};
        build_message(big);
        std::cerr << "expected overflow" << std::endl;
        return 1;
    } catch (const std::runtime_error&) {
    }

    auto repo_root = std::filesystem::path(__FILE__).parent_path().parent_path();
    auto filters_dir = repo_root / "filters" / "filters";
    filters::Engine::instance().load_directory(filters_dir, true);

    auto netset = Netset::create("10.0.0.0/30");
    auto& manager = sessions::SessionManager::instance();
    manager.set_filters_directory(filters_dir, true);
    manager.initialize_from_netset(netset, "anonymous");

    ParsedMessage up_request;
    up_request.serial = 1;
    up_request.state_id = 0;
    up_request.arguments = {"UP", "10.0.0.1", "ctx", "5", "evt", "example"};
    int state_id = 0;
    auto up_response = handle_event(up_request, state_id);
    assert(up_response.has_value());
    assert(!up_response->empty() && (*up_response)[0] == "OK");
    assert(state_id > 0);

    ParsedMessage status_request;
    status_request.serial = 2;
    status_request.state_id = state_id;
    status_request.arguments = {"ST", "10.0.0.1"};
    auto st_response = handle_event(status_request, state_id);
    assert(st_response.has_value());
    assert(st_response->size() >= 5);
    assert((*st_response)[0] == "OK");

    return 0;
}
