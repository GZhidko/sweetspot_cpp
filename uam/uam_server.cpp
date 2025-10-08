#include "uam_server.hpp"

#include "../sessions/session_manager.hpp"
#include "../common/logger.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstring>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <vector>

namespace uam {
namespace {

uint32_t ip_from_string(const std::string& ip) {
    in_addr addr{};
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        throw std::runtime_error("invalid ip address: " + ip);
    }
    return ntohl(addr.s_addr);
}

std::string ip_to_string(uint32_t ip_host_order) {
    in_addr addr{};
    addr.s_addr = htonl(ip_host_order);
    char buf[INET_ADDRSTRLEN] = {};
    if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
        return "<invalid_ip>";
    }
    return buf;
}

} // namespace

std::optional<std::vector<std::string>> handle_event(const ParsedMessage& request,
                                                     int& state_id) {
    if (request.arguments.size() < 2) {
        LOG(DEBUG_UAM, "malformed request");
        return std::vector<std::string>{"ER", "malformed-request"};
    }

    const std::string& event = request.arguments[0];
    const std::string& ip_str = request.arguments[1];
    uint32_t ip = 0;
    try {
        ip = ip_from_string(ip_str);
    } catch (const std::exception&) {
        return std::vector<std::string>{"ER", "invalid-ip"};
    }

    auto& manager = sessions::SessionManager::instance();
    auto fail = [&](const std::string& reason) -> std::optional<std::vector<std::string>> {
        LOG(DEBUG_UAM, "event=", event, " ip=", ip_str, " fail=", reason);
        return std::vector<std::string>{"ER", reason};
    };

    auto succeed = [&](std::vector<std::string> args) -> std::optional<std::vector<std::string>> {
        LOG(DEBUG_UAM, "event=", event, " ip=", ip_str, " ok");
        return args;
    };

    auto verify_state = [&](bool required) -> bool {
        if (!request.state_id) {
            return !required;
        }
        int requested = *request.state_id;
        if (!manager.verify_state_id(ip, requested)) {
            state_id = requested;
            return false;
        }
        state_id = requested;
        return true;
    };

    if (event == "UP") {
        if (!verify_state(false)) {
            return fail("stateid-verification-failure");
        }

        sessions::StartOptions opts;
        opts.status = sessions::SessionStatus::Released;
        if (request.arguments.size() > 2 && !request.arguments[2].empty()) {
            opts.session_context = request.arguments[2];
        }
        if (request.arguments.size() > 3 && !request.arguments[3].empty()) {
            opts.interim_interval = std::chrono::seconds(std::stoi(request.arguments[3]));
        }
        if (request.arguments.size() > 4 && !request.arguments[4].empty()) {
            opts.event_context = request.arguments[4];
        }

        std::string filter = (request.arguments.size() > 5) ? request.arguments[5] : "";
        try {
            manager.start_session(ip, filter, opts);
        } catch (const std::exception& ex) {
            return fail(ex.what());
        }
        manager.acquire_state_id(ip, state_id, true);
        return succeed({"OK", ip_str});
    }

    if (event == "DN") {
        if (!verify_state(true)) {
            return fail("stateid-verification-failure");
        }
        manager.stop_session(ip, sessions::TerminationCause::User);
        manager.acquire_state_id(ip, state_id, true);
        return succeed({"OK", ip_str});
    }

    if (event == "ST") {
        auto session = manager.find_session(ip);
        if (!session) {
            return fail("session-not-found");
        }
        manager.acquire_state_id(ip, state_id, false);
        std::string status = session->status == sessions::SessionStatus::Released ? "UP" : "DN";
        std::string interim = std::to_string(session->interim_interval.count());
        return succeed({"OK", status, session->filter_name, interim, session->session_context});
    }

    if (event == "LI" || event == "CN") {
        manager.acquire_state_id(ip, state_id, false);
        return succeed({"OK", "0", "0", "0", "0", "0", "0"});
    }

    return fail("unsupported-event");
}

Server::~Server() { stop(); }

bool Server::start(const ServerConfig& config) {
    if (running_) {
        return false;
    }

    config_ = config;
    socket_fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd_ == -1) {
        LOG(DEBUG_ERROR, "UAM socket(): ", std::strerror(errno));
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.port);
    addr.sin_addr.s_addr = inet_addr(config_.listen_address.c_str());

    if (::bind(socket_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == -1) {
        LOG(DEBUG_ERROR, "UAM bind(): ", std::strerror(errno));
        ::close(socket_fd_);
        socket_fd_ = -1;
        return false;
    }

    socklen_t addr_len = sizeof(addr);
    if (::getsockname(socket_fd_, reinterpret_cast<sockaddr*>(&addr), &addr_len) == 0) {
        bound_port_ = ntohs(addr.sin_port);
    }

    timeval tv{};
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    ::setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    running_ = true;
    worker_ = std::thread(&Server::run, this);
    LOG(DEBUG_UAM, "server started on ", config_.listen_address, ":", bound_port_);
    return true;
}

void Server::stop() {
    if (!running_) {
        return;
    }
    running_ = false;
    if (socket_fd_ != -1) {
        ::shutdown(socket_fd_, SHUT_RDWR);
    }
    if (worker_.joinable()) {
        worker_.join();
    }
    if (socket_fd_ != -1) {
        ::close(socket_fd_);
        socket_fd_ = -1;
    }
    LOG(DEBUG_UAM, "server stopped");
}

void Server::run() {
    std::array<char, kMaxMessageSize> buffer{};

    while (running_) {
        sockaddr_in peer{};
        socklen_t peer_len = sizeof(peer);
        ssize_t n = ::recvfrom(socket_fd_, buffer.data(), buffer.size(), 0,
                               reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (n < 0) {
            if (!running_) {
                break;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            LOG(DEBUG_ERROR, "UAM recvfrom(): ", std::strerror(errno));
            continue;
        }

        ParsedMessage request;
        try {
            request = parse_message(std::string_view(buffer.data(), static_cast<std::size_t>(n)));
        } catch (const std::exception& ex) {
            LOG(DEBUG_ERROR, "UAM parse error: ", ex.what());
            continue;
        }

        int state_id = request.state_id.value_or(0);
        auto response_payload = handle_event(request, state_id);
        if (!response_payload) {
            continue;
        }

        std::vector<std::string> out_args;
        if (request.serial) {
            out_args.push_back(std::to_string(*request.serial));
            out_args.push_back(std::to_string(state_id));
        }
        out_args.insert(out_args.end(), response_payload->begin(), response_payload->end());

        std::string response;
        try {
            response = build_message(out_args);
        } catch (const std::exception& ex) {
            LOG(DEBUG_ERROR, "UAM build error: ", ex.what());
            continue;
        }
        ::sendto(socket_fd_, response.data(), response.size(), 0,
                 reinterpret_cast<sockaddr*>(&peer), peer_len);
    }
}

std::optional<std::vector<std::string>> Server::process_packet(const ParsedMessage& request,
                                                               int& state_id) {
    return handle_event(request, state_id);
}
} // namespace uam
