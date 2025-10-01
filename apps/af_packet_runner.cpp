#include "../common/logger.h"
#include "../common/netset.hpp"
#include "../common/worker.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <csignal>
#include <functional>
#include <iostream>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

std::atomic<bool> g_stop{false};

void signal_handler(int) { g_stop.store(true); }

void install_signal_handlers() {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
}

uint32_t parse_ip(const std::string& ip) {
    in_addr addr{};
    if (::inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        throw std::runtime_error("Invalid IP: " + ip);
    }
    return ntohl(addr.s_addr);
}

uint16_t parse_port(const std::string& port) {
    unsigned long val = std::stoul(port);
    if (val > 65535) {
        throw std::runtime_error("Invalid port: " + port);
    }
    return static_cast<uint16_t>(val);
}

NatConfig build_nat_config(const std::string& priv, const std::string& pub) {
    NatConfig cfg;
    cfg.private_netset = Netset::create(priv);
    cfg.public_netset = Netset::create(pub);
    return cfg;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 6) {
        std::cerr << "Usage: " << argv[0]
                  << " <priv_iface> <pub_iface> <private_net> <public_net> <worker_count>"
                  << std::endl;
        return 1;
    }

    std::string priv_iface = argv[1];
    std::string pub_iface = argv[2];
    std::string priv_net = argv[3];
    std::string pub_net = argv[4];
    uint32_t worker_count = static_cast<uint32_t>(std::stoul(argv[5]));
    if (worker_count == 0) {
        std::cerr << "worker_count must be > 0" << std::endl;
        return 1;
    }

    Logger::setFlags(DEBUG_ALL);

    NatConfig nat_cfg;
    try {
        nat_cfg = build_nat_config(priv_net, pub_net);
    } catch (const std::exception& e) {
        std::cerr << "Failed to build nat config: " << e.what() << std::endl;
        return 1;
    }

    std::vector<std::tuple<uint32_t, uint16_t, uint32_t, uint16_t>> static_tcp;
    std::vector<std::tuple<uint32_t, uint16_t, uint32_t, uint16_t>> static_udp;
    std::vector<std::tuple<uint32_t, uint16_t, uint32_t, uint16_t>> static_icmp;
    std::vector<std::pair<uint32_t, uint32_t>> static_ip;

    for (int i = 6; i < argc;) {
        std::string opt = argv[i];
        try {
            if (opt == "--static-tcp" && i + 4 < argc) {
                uint32_t priv_ip = parse_ip(argv[i + 1]);
                uint16_t priv_port = parse_port(argv[i + 2]);
                uint32_t pub_ip = parse_ip(argv[i + 3]);
                uint16_t pub_port = parse_port(argv[i + 4]);
                static_tcp.emplace_back(priv_ip, priv_port, pub_ip, pub_port);
                i += 5;
            } else if (opt == "--static-udp" && i + 4 < argc) {
                uint32_t priv_ip = parse_ip(argv[i + 1]);
                uint16_t priv_port = parse_port(argv[i + 2]);
                uint32_t pub_ip = parse_ip(argv[i + 3]);
                uint16_t pub_port = parse_port(argv[i + 4]);
                static_udp.emplace_back(priv_ip, priv_port, pub_ip, pub_port);
                i += 5;
            } else if (opt == "--static-icmp" && i + 4 < argc) {
                uint32_t priv_ip = parse_ip(argv[i + 1]);
                uint16_t priv_id = parse_port(argv[i + 2]);
                uint32_t pub_ip = parse_ip(argv[i + 3]);
                uint16_t pub_id = parse_port(argv[i + 4]);
                static_icmp.emplace_back(priv_ip, priv_id, pub_ip, pub_id);
                i += 5;
            } else if (opt == "--static-ip" && i + 2 < argc) {
                uint32_t priv_ip = parse_ip(argv[i + 1]);
                uint32_t pub_ip = parse_ip(argv[i + 2]);
                static_ip.emplace_back(priv_ip, pub_ip);
                i += 3;
            } else {
                std::cerr << "Unknown or malformed option: " << opt << std::endl;
                return 1;
            }
        } catch (const std::exception& e) {
            std::cerr << "Failed to parse option " << opt << ": " << e.what() << std::endl;
            return 1;
        }
    }

    uint32_t pid = static_cast<uint32_t>(getpid());
    uint16_t priv_group = static_cast<uint16_t>(pid & 0xffff);
    if (priv_group == 0) {
        priv_group = 1;
    }
    uint16_t pub_group = static_cast<uint16_t>((priv_group + 1) & 0xffff);
    if (pub_group == 0) {
        pub_group = 2;
    }
    af_packet_io::FanoutParams priv_fanout{priv_group, PACKET_FANOUT_HASH, 0};
    af_packet_io::FanoutParams pub_fanout{pub_group, PACKET_FANOUT_HASH, 0};

    auto configure_io = [](af_packet_io::IoConfig& cfg, const std::string& rx_iface,
                           const std::string& tx_iface,
                           const af_packet_io::FanoutParams& fanout) {
        cfg.rx_interface = rx_iface;
        cfg.tx_interface = tx_iface;
        cfg.protocol = ETH_P_ALL;
        cfg.rx_ring.block_size = 1 << 22;
        cfg.rx_ring.block_count = 64;
        cfg.rx_ring.frame_size = 1 << 11;
        cfg.rx_ring.timeout_ns = 60ULL * 1000ULL * 1000ULL;
        cfg.tx_ring.block_size = 0;
        cfg.tx_ring.block_count = 0;
        cfg.tx_ring.frame_size = 0;
        cfg.tx_ring.frame_count = 0;
        cfg.tx_ring.timeout_ns = 0;
        cfg.fanout = fanout;
    };

    af_packet_io::IoConfig io_priv;
    af_packet_io::IoConfig io_pub;
    configure_io(io_priv, priv_iface, pub_iface, priv_fanout);
    configure_io(io_pub, pub_iface, priv_iface, pub_fanout);

    std::vector<std::unique_ptr<Worker>> workers;
    workers.reserve(worker_count);

    for (uint32_t i = 0; i < worker_count; ++i) {
        WorkerPipelineConfig cfg;
        cfg.io_priv = io_priv;
        cfg.io_pub = io_pub;
        cfg.nat = nat_cfg;
        cfg.thread_index = i;
        cfg.thread_count = worker_count;
        cfg.enable_io = true;
        cfg.static_tcp = static_tcp;
        cfg.static_udp = static_udp;
        cfg.static_icmp = static_icmp;
        cfg.static_ip = static_ip;
        try {
            auto worker = std::make_unique<Worker>(cfg);
            workers.push_back(std::move(worker));
        } catch (const std::exception& e) {
            std::cerr << "Failed to start worker " << i << ": " << e.what() << std::endl;
            g_stop.store(true);
            break;
        }
    }

    if (workers.empty()) {
        std::cerr << "No workers running" << std::endl;
        return 1;
    }

    auto forward = [&workers](uint32_t target, Worker::FramePayload&& frame) {
        if (target < workers.size()) {
            workers[target]->submit_remote_frame(std::move(frame));
        }
    };

    for (auto& worker : workers) {
        worker->set_forward_callback(forward);
    }

    for (auto& worker : workers) {
        worker->start();
    }

    install_signal_handlers();
    std::cout << "af_packet_runner started on priv=" << priv_iface
              << " pub=" << pub_iface << " with " << workers.size()
              << " workers, fanout groups priv=" << priv_group
              << " pub=" << pub_group << std::endl;

    while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    std::cout << "Stopping workers..." << std::endl;
    for (auto& worker : workers) {
        worker->stop();
    }
    workers.clear();

    std::cout << "Stopped" << std::endl;
    return 0;
}
