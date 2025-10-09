#include "../uam/uam_message.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstring>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

struct Options {
    std::string address = "127.0.0.1";
    uint16_t port = 3993;
    std::optional<int> serial;
    std::optional<int> state_id;
    std::chrono::milliseconds timeout{1000};
    int retries = 1;
    std::vector<std::string> payload;
};

void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog
              << " [--address ip] [--port port] [--serial id] [--state id]"
                 " [--timeout ms] [--retries n] <event> <ip> [args...]\n";
}

std::optional<Options> parse_args(int argc, char** argv) {
    Options opts;
    int i = 1;
    for (; i < argc; ++i) {
        std::string_view arg(argv[i]);
        if (arg.size() < 2 || arg.substr(0, 2) != "--") {
            break;
        }
        if (arg == "--address") {
            if (++i >= argc) {
                std::cerr << "Missing value for --address\n";
                return std::nullopt;
            }
            opts.address = argv[i];
        } else if (arg == "--port") {
            if (++i >= argc) {
                std::cerr << "Missing value for --port\n";
                return std::nullopt;
            }
            opts.port = static_cast<uint16_t>(std::stoi(argv[i]));
        } else if (arg == "--serial") {
            if (++i >= argc) {
                std::cerr << "Missing value for --serial\n";
                return std::nullopt;
            }
            opts.serial = std::stoi(argv[i]);
        } else if (arg == "--state") {
            if (++i >= argc) {
                std::cerr << "Missing value for --state\n";
                return std::nullopt;
            }
            opts.state_id = std::stoi(argv[i]);
        } else if (arg == "--timeout") {
            if (++i >= argc) {
                std::cerr << "Missing value for --timeout\n";
                return std::nullopt;
            }
            opts.timeout = std::chrono::milliseconds(std::stoi(argv[i]));
        } else if (arg == "--retries") {
            if (++i >= argc) {
                std::cerr << "Missing value for --retries\n";
                return std::nullopt;
            }
            opts.retries = std::max(1, std::stoi(argv[i]));
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            return std::nullopt;
        }
    }

    if (i >= argc) {
        std::cerr << "Missing event argument\n";
        return std::nullopt;
    }
    std::string event = argv[i++];
    if (i >= argc) {
        std::cerr << "Missing IP argument\n";
        return std::nullopt;
    }
    std::string ip = argv[i++];

    opts.payload.push_back(event);
    opts.payload.push_back(ip);

    for (; i < argc; ++i) {
        opts.payload.emplace_back(argv[i]);
    }
    return opts;
}

int create_socket(const Options& opts) {
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        throw std::runtime_error(std::string("socket(): ") + std::strerror(errno));
    }
    timeval tv{};
    tv.tv_sec = static_cast<long>(opts.timeout.count() / 1000);
    tv.tv_usec = static_cast<long>((opts.timeout.count() % 1000) * 1000);
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        ::close(fd);
        throw std::runtime_error(std::string("setsockopt(SO_RCVTIMEO): ") + std::strerror(errno));
    }
    return fd;
}

sockaddr_in build_address(const Options& opts) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(opts.port);
    if (::inet_pton(AF_INET, opts.address.c_str(), &addr.sin_addr) != 1) {
        throw std::runtime_error("Invalid address: " + opts.address);
    }
    return addr;
}

void print_response(const std::vector<std::string>& response) {
    if (response.empty()) {
        std::cout << "<empty response>\n";
        return;
    }
    std::cout << "Response:";
    for (const auto& token : response) {
        std::cout << ' ' << token;
    }
    std::cout << '\n';
}

} // namespace

int main(int argc, char** argv) {
    try {
        auto parsed = parse_args(argc, argv);
        if (!parsed) {
            print_usage(argv[0]);
            return 1;
        }
        const Options& opts = *parsed;

        if (opts.payload.size() < 2) {
            std::cerr << "Need at least event and IP\n";
            print_usage(argv[0]);
            return 1;
        }

        std::vector<std::string> message_args;
        if (opts.serial) {
            message_args.push_back(std::to_string(*opts.serial));
            if (opts.state_id) {
                message_args.push_back(std::to_string(*opts.state_id));
            }
        } else if (opts.state_id) {
            message_args.push_back("0");
            message_args.push_back(std::to_string(*opts.state_id));
        }
        message_args.insert(message_args.end(), opts.payload.begin(), opts.payload.end());

        auto buffer = uam::build_message(message_args);

        auto addr = build_address(opts);
        int fd = create_socket(opts);

        bool success = false;
        for (int attempt = 0; attempt < opts.retries && !success; ++attempt) {
            ssize_t sent = ::sendto(fd, buffer.data(), buffer.size(), 0,
                                    reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
            if (sent < 0) {
                std::cerr << "sendto failed: " << std::strerror(errno) << "\n";
                continue;
            }

            std::array<char, uam::kMaxMessageSize> recv_buf{};
            sockaddr_in peer{};
            socklen_t peer_len = sizeof(peer);
            ssize_t received = ::recvfrom(fd, recv_buf.data(), recv_buf.size(), 0,
                                          reinterpret_cast<sockaddr*>(&peer), &peer_len);
            if (received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    std::cerr << "timeout waiting for response (attempt " << (attempt + 1)
                              << "/" << opts.retries << ")\n";
                    continue;
                }
                std::cerr << "recvfrom failed: " << std::strerror(errno) << "\n";
                continue;
            }

            try {
                auto parsed_response = uam::parse_message(
                    std::string_view(recv_buf.data(), static_cast<std::size_t>(received)));
                print_response(parsed_response.arguments);
            } catch (const std::exception& ex) {
                std::cerr << "Failed to parse response: " << ex.what() << "\n";
                continue;
            }
            success = true;
        }

        ::close(fd);

        if (!success) {
            return 2;
        }
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}
