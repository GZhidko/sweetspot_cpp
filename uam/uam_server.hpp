#pragma once

#include "uam_message.hpp"

#include <atomic>
#include <cstdint>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace uam {

struct ServerConfig {
    std::string listen_address = "0.0.0.0";
    uint16_t port = 3993;
};

std::optional<std::vector<std::string>> handle_event(const ParsedMessage& request,
                                                     int& state_id);

class Server {
  public:
    Server() = default;
    ~Server();

    bool start(const ServerConfig& config);
    void stop();

    bool running() const { return running_; }
    uint16_t bound_port() const { return bound_port_; }

  private:
    void run();
    std::optional<std::vector<std::string>> process_packet(const ParsedMessage& request,
                                                           int& state_id);

    ServerConfig config_;
    std::atomic<bool> running_{false};
    int socket_fd_ = -1;
    std::thread worker_;
    uint16_t bound_port_ = 0;
};

} // namespace uam
