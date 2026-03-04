#include "../acct/manager.hpp"
#include "../af_packet_io/io_context.hpp"
#include "../common/logger.h"
#include "../common/netset.hpp"
#include "../common/worker.hpp"
#include "../filters/filter_engine.hpp"
#include "../sessions/session_manager.hpp"
#include "../uam/uam_server.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <optional>
#include <sstream>
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

std::string trim_copy(const std::string& text) {
    const auto begin = text.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) {
        return {};
    }
    const auto end = text.find_last_not_of(" \t\r\n");
    return text.substr(begin, end - begin + 1);
}

std::vector<std::string> split_tokens(const std::string& text) {
    std::istringstream iss(text);
    std::vector<std::string> tokens;
    std::string token;
    while (iss >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

std::string join_tokens(const std::vector<std::string>& values) {
    std::ostringstream oss;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i != 0) {
            oss << ' ';
        }
        oss << values[i];
    }
    return oss.str();
}

struct AppConfig {
    std::string inner_interface;
    std::string outer_interface;
    std::string inner_gw_mac;
    std::string outer_gw_mac;
    std::vector<std::string> user_networks;
    std::vector<std::string> snat_public_networks;
    std::string filter_dir;
    std::string filter_anonymous;
    std::string uam_address;
    uint16_t uam_port = 0;
    std::string uam_secret;
    uint32_t thread_count = 0;
    bool forward_pool_enabled = false;
    bool profile_enabled = false;
    uint32_t profile_interval_ms = 2000;
    bool worker_epoll_enabled = true;
    bool forward_hash_balanced_enabled = false;
    uint32_t forward_hash_table_size = 1024;
    uint64_t forward_hash_seed = 0;
    bool loop_guard_enabled = false;
    uint8_t loop_guard_tos_mask = 0x04;
    std::optional<uint32_t> acct_interim_interval;
    std::string acct_detail_file;
};

class ConfigLoader {
  public:
    static AppConfig load(const std::filesystem::path& path) {
        AppConfig cfg;
        std::ifstream file(path);
        if (!file.is_open()) {
            throw std::runtime_error("Unable to open config: " + path.string());
        }

        std::string line;
        std::size_t line_no = 0;
        while (std::getline(file, line)) {
            ++line_no;
            auto trimmed = trim_copy(line);
            if (trimmed.empty() || trimmed[0] == '#') {
                continue;
            }

            std::istringstream iss(trimmed);
            std::string key;
            if (!(iss >> key)) {
                continue;
            }
            std::string rest;
            std::getline(iss, rest);
            rest = trim_copy(rest);
            std::vector<std::string> tokens = split_tokens(rest);

            auto lower_key = key;
            std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(),
                           [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });

            try {
                if (lower_key == "inner-interface") {
                    if (tokens.empty()) {
                        throw std::runtime_error("missing value");
                    }
                    cfg.inner_interface = tokens.front();
                } else if (lower_key == "outer-interface") {
                    if (tokens.empty()) {
                        throw std::runtime_error("missing value");
                    }
                    cfg.outer_interface = tokens.front();
                } else if (lower_key == "inner-gw-mac") {
                    cfg.inner_gw_mac = rest;
                } else if (lower_key == "outer-gw-mac") {
                    cfg.outer_gw_mac = rest;
                } else if (lower_key == "user-networks") {
                    if (tokens.empty()) {
                        throw std::runtime_error("missing value");
                    }
                    cfg.user_networks.insert(cfg.user_networks.end(), tokens.begin(), tokens.end());
                } else if (lower_key == "snat-public-networks") {
                    if (tokens.empty()) {
                        throw std::runtime_error("missing value");
                    }
                    cfg.snat_public_networks.insert(cfg.snat_public_networks.end(), tokens.begin(),
                                                    tokens.end());
                } else if (lower_key == "filter-dir") {
                    if (rest.empty()) {
                        throw std::runtime_error("missing value");
                    }
                    cfg.filter_dir = rest;
                } else if (lower_key == "acct-detail-file") {
                    if (rest.empty()) {
                        throw std::runtime_error("missing value");
                    }
                    cfg.acct_detail_file = rest;
                } else if (lower_key == "filter-anonymous") {
                    if (tokens.empty()) {
                        throw std::runtime_error("missing value");
                    }
                    cfg.filter_anonymous = tokens.front();
                } else if (lower_key == "uam-server-address") {
                    if (tokens.empty()) {
                        throw std::runtime_error("missing value");
                    }
                    cfg.uam_address = tokens.front();
                } else if (lower_key == "uam-server-port") {
                    if (tokens.empty()) {
                        throw std::runtime_error("missing value");
                    }
                    cfg.uam_port = static_cast<uint16_t>(std::stoul(tokens.front()));
                } else if (lower_key == "uam-secret") {
                    cfg.uam_secret = rest;
                } else if (lower_key == "acct-interim-interval") {
                    if (tokens.empty()) {
                        throw std::runtime_error("missing value");
                    }
                    cfg.acct_interim_interval = static_cast<uint32_t>(std::stoul(tokens.front()));
                } else if (lower_key == "thread_qnty") {
                    if (tokens.empty()) {
                        throw std::runtime_error("missing value");
                    }
                    cfg.thread_count = static_cast<uint32_t>(std::stoul(tokens.front()));
                } else if (lower_key == "forward-pool-enabled") {
                    if (tokens.empty()) {
                        throw std::runtime_error("missing value");
                    }
                    std::string v = tokens.front();
                    std::transform(v.begin(), v.end(), v.begin(),
                                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
                    cfg.forward_pool_enabled =
                        (v == "1" || v == "true" || v == "yes" || v == "on");
                } else if (lower_key == "profile-enabled") {
                    if (tokens.empty()) {
                        throw std::runtime_error("missing value");
                    }
                    std::string v = tokens.front();
                    std::transform(v.begin(), v.end(), v.begin(),
                                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
                    cfg.profile_enabled =
                        (v == "1" || v == "true" || v == "yes" || v == "on");
                } else if (lower_key == "profile-interval-ms") {
                    if (tokens.empty()) {
                        throw std::runtime_error("missing value");
                    }
                    cfg.profile_interval_ms = static_cast<uint32_t>(std::stoul(tokens.front()));
                } else if (lower_key == "worker-epoll-enabled") {
                    if (tokens.empty()) {
                        throw std::runtime_error("missing value");
                    }
                    std::string v = tokens.front();
                    std::transform(v.begin(), v.end(), v.begin(),
                                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
                    cfg.worker_epoll_enabled =
                        (v == "1" || v == "true" || v == "yes" || v == "on");
                } else if (lower_key == "forward-hash-balanced-enabled") {
                    if (tokens.empty()) {
                        throw std::runtime_error("missing value");
                    }
                    std::string v = tokens.front();
                    std::transform(v.begin(), v.end(), v.begin(),
                                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
                    cfg.forward_hash_balanced_enabled =
                        (v == "1" || v == "true" || v == "yes" || v == "on");
                } else if (lower_key == "forward-hash-table-size") {
                    if (tokens.empty()) {
                        throw std::runtime_error("missing value");
                    }
                    cfg.forward_hash_table_size = static_cast<uint32_t>(std::stoul(tokens.front()));
                } else if (lower_key == "forward-hash-seed") {
                    if (tokens.empty()) {
                        throw std::runtime_error("missing value");
                    }
                    cfg.forward_hash_seed = static_cast<uint64_t>(std::stoull(tokens.front()));
                } else if (lower_key == "loop-guard-enabled") {
                    if (tokens.empty()) {
                        throw std::runtime_error("missing value");
                    }
                    std::string v = tokens.front();
                    std::transform(v.begin(), v.end(), v.begin(),
                                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
                    cfg.loop_guard_enabled =
                        (v == "1" || v == "true" || v == "yes" || v == "on");
                } else if (lower_key == "loop-guard-tos-mask") {
                    if (tokens.empty()) {
                        throw std::runtime_error("missing value");
                    }
                    const auto parsed = std::stoul(tokens.front(), nullptr, 0);
                    if (parsed > 0xFFu) {
                        throw std::runtime_error("loop-guard-tos-mask must be <= 255");
                    }
                    cfg.loop_guard_tos_mask = static_cast<uint8_t>(parsed);
                } else {
                    // ignore unknown keys but log for visibility
                    LOG(DEBUG_SESSION, "Ignoring config key ", key, " at line ", line_no);
                }
            } catch (const std::exception& ex) {
                std::ostringstream oss;
                oss << "Config error at line " << line_no << ": " << key << " -> " << ex.what();
                throw std::runtime_error(oss.str());
            }
        }

        validate(cfg);
        return cfg;
    }

  private:
    static void validate(const AppConfig& cfg) {
        if (cfg.inner_interface.empty()) {
            throw std::runtime_error("inner-interface is required");
        }
        if (cfg.outer_interface.empty()) {
            throw std::runtime_error("outer-interface is required");
        }
        if (cfg.user_networks.empty()) {
            throw std::runtime_error("user-networks is required");
        }
        if (cfg.snat_public_networks.empty()) {
            throw std::runtime_error("snat-public-networks is required");
        }
        if (cfg.filter_dir.empty()) {
            throw std::runtime_error("filter-dir is required");
        }
        if (cfg.thread_count == 0) {
            throw std::runtime_error("thread_qnty must be greater than zero");
        }
        if ((cfg.thread_count % 2) != 0) {
            LOG(DEBUG_SESSION, "thread_qnty is not even, continuing with ", cfg.thread_count);
        }
        if (cfg.forward_hash_table_size == 0) {
            throw std::runtime_error("forward-hash-table-size must be greater than zero");
        }
    }
};

NatConfig build_nat_config(const AppConfig& cfg) {
    NatConfig nat_cfg;
    nat_cfg.private_netset = Netset::create(join_tokens(cfg.user_networks));
    nat_cfg.public_netset = Netset::create(join_tokens(cfg.snat_public_networks));
    if (!nat_cfg.is_valid()) {
        throw std::runtime_error("invalid NAT configuration");
    }
    return nat_cfg;
}

void configure_interface(af_packet_io::IoConfig& config, const std::string& rx_iface,
                         const std::string& tx_iface, uint16_t group) {
    af_packet_io::FanoutParams fanout{group, PACKET_FANOUT_CPU, 0};
    config.rx_interface = rx_iface;
    config.tx_interface = tx_iface;
    config.protocol = ETH_P_ALL;
    config.rx_ring.block_size = 1 << 19;
    config.rx_ring.block_count = 128;
    config.rx_ring.frame_size = 1 << 11;
    config.rx_ring.timeout_ns = 1ULL * 1000ULL * 1000ULL;
    config.tx_ring.block_size = 1 << 19;
    config.tx_ring.block_count = 32;
    config.tx_ring.frame_size = 1 << 11;
    config.tx_ring.frame_count = 0;
    config.tx_ring.timeout_ns = 1ULL * 1000ULL * 1000ULL;
    config.fanout = fanout;
}

} // namespace

int main(int argc, char** argv) {
    std::string config_path;
    std::string debug_spec = "all";
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: " << argv[0]
                      << " [--debug <modules|mask>] <config_path>\n"
                      << "  --debug, -d      Comma-separated modules or numeric mask\n"
                      << "  --debug-help     Show available debug module keywords\n";
            return 0;
        }
        if (arg == "--debug-help") {
            std::cout << Logger::debug_keywords() << std::endl;
            return 0;
        }
        if (arg == "--debug" || arg == "-d") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << arg << std::endl;
                return 1;
            }
            debug_spec = argv[++i];
            continue;
        }
        if (arg.rfind("--debug=", 0) == 0) {
            debug_spec = arg.substr(8);
            continue;
        }
        if (!arg.empty() && arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << std::endl;
            return 1;
        }
        if (!config_path.empty()) {
            std::cerr << "Unexpected positional argument: " << arg << std::endl;
            return 1;
        }
        config_path = arg;
    }

    if (config_path.empty()) {
        std::cerr << "Usage: " << argv[0] << " [--debug <modules|mask>] <config_path>"
                  << std::endl;
        return 1;
    }

    uint32_t debug_flags = 0;
    std::string parse_error;
    if (!Logger::parse_flags_spec(debug_spec, debug_flags, &parse_error)) {
        std::cerr << "Invalid --debug value '" << debug_spec << "': " << parse_error
                  << "\nAvailable: " << Logger::debug_keywords() << std::endl;
        return 1;
    }
    Logger::setFlags(debug_flags);

    AppConfig config;
    try {
        config = ConfigLoader::load(config_path);
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }

    NatConfig nat_cfg;
    try {
        nat_cfg = build_nat_config(config);
    } catch (const std::exception& ex) {
        std::cerr << "NAT configuration failed: " << ex.what() << std::endl;
        return 1;
    }

    try {
        filters::Engine::instance().load_directory(config.filter_dir, true);
        auto& manager = sessions::SessionManager::instance();
        manager.set_filters_directory(config.filter_dir, true);
        if (!config.filter_anonymous.empty()) {
            manager.set_default_filter(config.filter_anonymous);
        }
        manager.initialize_from_netset(nat_cfg.private_netset, config.filter_anonymous);
    } catch (const std::exception& ex) {
        std::cerr << "Filter/session initialization failed: " << ex.what() << std::endl;
        return 1;
    }

    accounting::Config acct_config;
    acct_config.detail_file = config.acct_detail_file.empty()
                                  ? std::string("/var/sweetspot/detail")
                                  : config.acct_detail_file;
    accounting::Manager::instance().configure(acct_config);

    uam::Server uam_server;
    if (!config.uam_address.empty() && config.uam_port != 0) {
        uam::ServerConfig uam_cfg;
        uam_cfg.listen_address = config.uam_address;
        uam_cfg.port = config.uam_port;
        if (!uam_server.start(uam_cfg)) {
            std::cerr << "Failed to start UAM server on " << config.uam_address << ':'
                      << config.uam_port << std::endl;
            return 1;
        }
    } else {
        std::cerr << "UAM configuration incomplete, server not started" << std::endl;
    }

    uint32_t worker_count = config.thread_count;
    uint32_t pid = static_cast<uint32_t>(getpid());
    uint16_t priv_group = static_cast<uint16_t>(pid & 0xffff);
    if (priv_group == 0) {
        priv_group = 1;
    }
    uint16_t pub_group = static_cast<uint16_t>((priv_group + 1) & 0xffff);
    if (pub_group == 0) {
        pub_group = 2;
    }

    af_packet_io::IoConfig io_priv;
    af_packet_io::IoConfig io_pub;
    configure_interface(io_priv, config.inner_interface, config.inner_interface, priv_group);
    configure_interface(io_pub, config.outer_interface, config.outer_interface, pub_group);

    std::vector<std::unique_ptr<Worker>> workers;
    workers.reserve(worker_count);

    for (uint32_t i = 0; i < worker_count; ++i) {
        WorkerPipelineConfig pipeline_cfg;
        pipeline_cfg.io_priv = io_priv;
        pipeline_cfg.io_pub = io_pub;
        pipeline_cfg.nat = nat_cfg;
        pipeline_cfg.thread_index = i;
        pipeline_cfg.thread_count = worker_count;
        pipeline_cfg.enable_io = true;
        pipeline_cfg.forward_pool_enabled = config.forward_pool_enabled;
        pipeline_cfg.profile_enabled = config.profile_enabled;
        pipeline_cfg.profile_interval_ms = config.profile_interval_ms;
        pipeline_cfg.worker_epoll_enabled = config.worker_epoll_enabled;
        pipeline_cfg.forward_hash_balanced_enabled = config.forward_hash_balanced_enabled;
        pipeline_cfg.forward_hash_table_size = config.forward_hash_table_size;
        pipeline_cfg.forward_hash_seed = config.forward_hash_seed;
        pipeline_cfg.loop_guard_enabled = config.loop_guard_enabled;
        pipeline_cfg.loop_guard_tos_mask = config.loop_guard_tos_mask;
        try {
            auto worker = std::make_unique<Worker>(pipeline_cfg);
            workers.push_back(std::move(worker));
        } catch (const std::exception& ex) {
            std::cerr << "Failed to initialize worker " << i << ": " << ex.what() << std::endl;
            g_stop.store(true);
            break;
        }
    }

    if (workers.empty()) {
        std::cerr << "No workers started" << std::endl;
        uam_server.stop();
        return 1;
    }

    auto forward = [&workers](uint32_t target, Worker::FramePayload&& frame) {
        if (target < workers.size()) {
            workers[target]->submit_remote_frame(std::move(frame));
        }
    };

    for (auto& worker : workers) {
        worker->set_forward_callback(forward);
        worker->start();
    }

    install_signal_handlers();
    std::cout << "sweetspot daemon ready: inner=" << config.inner_interface
              << " outer=" << config.outer_interface << " workers=" << workers.size()
              << " uam=" << config.uam_address << ':' << config.uam_port << std::endl;

    while (!g_stop.load()) {
        accounting::Manager::instance().commit(false);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    std::cout << "Stopping workers..." << std::endl;
    for (auto& worker : workers) {
        worker->stop();
    }
    workers.clear();

    uam_server.stop();

    accounting::Manager::instance().commit(true);

    std::cout << "Stopped" << std::endl;
    return 0;
}
