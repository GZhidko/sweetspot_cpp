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
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0]
                  << " <interface> <private_net> <public_net> <worker_count>" << std::endl;
        return 1;
    }

    std::string ifname = argv[1];
    std::string priv_net = argv[2];
    std::string pub_net = argv[3];
    uint32_t worker_count = static_cast<uint32_t>(std::stoul(argv[4]));
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

    for (int i = 5; i < argc;) {
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

    af_packet_io::IoConfig io_cfg;
    io_cfg.interface = ifname;
    io_cfg.protocol = ETH_P_ALL;
    io_cfg.rx_ring.block_size = 1 << 22;   // 4 MiB blocks as in tpacket_v3 example
    io_cfg.rx_ring.block_count = 64;
    io_cfg.rx_ring.frame_size = 1 << 11;   // 2048-byte frames
    io_cfg.rx_ring.timeout_ns = 60ULL * 1000ULL * 1000ULL; // 60 ms
    io_cfg.tx_ring.block_size = 0;
    io_cfg.tx_ring.block_count = 0;
    io_cfg.tx_ring.frame_size = 0;
    io_cfg.tx_ring.frame_count = 0;
    io_cfg.tx_ring.timeout_ns = 0;
    uint16_t fanout_group = static_cast<uint16_t>(getpid() & 0xffff);
    io_cfg.fanout = {fanout_group, PACKET_FANOUT_HASH, 0};

    std::vector<std::unique_ptr<Worker>> workers;
    workers.reserve(worker_count);

    for (uint32_t i = 0; i < worker_count; ++i) {
        WorkerPipelineConfig cfg;
        cfg.io = io_cfg;
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
    std::cout << "af_packet_runner started on " << ifname << " with " << workers.size()
              << " workers, fanout group " << fanout_group << std::endl;

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
