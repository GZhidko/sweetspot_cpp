#include <arpa/inet.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cctype>
#include <cerrno>
#include <cinttypes>
#include <csignal>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "common/logger.h"
#include "nat/endpoint_base.hpp"
#include "nat/nat_config.hpp"

namespace {

struct PubKey {
    uint32_t ip;
    uint16_t port;
    bool operator==(const PubKey& other) const noexcept {
        return ip == other.ip && port == other.port;
    }
};

struct PubKeyHash {
    std::size_t operator()(const PubKey& k) const noexcept {
        return (static_cast<std::size_t>(k.ip) << 16) ^ k.port;
    }
};

struct ExpectedRoute {
    uint32_t hash = 0;
    uint32_t queue = 0;
    int expected_cpu = -1;
};

struct RssConfig {
    std::vector<uint8_t> key;
    std::vector<uint32_t> indirection;

    bool valid() const { return !key.empty() && !indirection.empty(); }
};

struct Options {
    std::string ifname = "lo";
    std::optional<std::string> rss_key_hex;
    std::optional<std::string> rss_table_csv;
    std::optional<std::string> queue_cpu_csv;
};

std::mutex g_nat_mutex;
std::unordered_map<PubKey, ExpectedRoute, PubKeyHash> g_nat_table;
RssConfig g_rss_config;
std::unordered_map<uint32_t, int> g_queue_cpu_map;

[[noreturn]] void usage() {
    std::cerr << "Usage: test_fanout [options]\n"
              << "\nOptions:\n"
              << "  --ifname=<name>           Interface name (default: lo)\n"
              << "  --rss-key=<hex>          RSS key as hex string (optional fallback)\n"
              << "  --rss-table=<csv>        RSS indirection table as comma-separated integers\n"
              << "  --queue-cpu=<csv>        Queue to CPU map (e.g. 0:2,1:3)\n"
              << "  --help                   Show this message\n";
    std::exit(1);
}

Options parse_options(int argc, char** argv) {
    Options opts;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help") {
            usage();
        } else if (arg.rfind("--ifname=", 0) == 0) {
            opts.ifname = arg.substr(9);
        } else if (arg.rfind("--rss-key=", 0) == 0) {
            opts.rss_key_hex = arg.substr(10);
        } else if (arg.rfind("--rss-table=", 0) == 0) {
            opts.rss_table_csv = arg.substr(12);
        } else if (arg.rfind("--queue-cpu=", 0) == 0) {
            opts.queue_cpu_csv = arg.substr(12);
        } else if (arg[0] != '-') {
            opts.ifname = arg;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            usage();
        }
    }

    if (const char* env = std::getenv("RSS_KEY")) {
        if (!opts.rss_key_hex) opts.rss_key_hex = env;
    }
    if (const char* env = std::getenv("RSS_TABLE")) {
        if (!opts.rss_table_csv) opts.rss_table_csv = env;
    }
    if (const char* env = std::getenv("QUEUE_CPU_MAP")) {
        if (!opts.queue_cpu_csv) opts.queue_cpu_csv = env;
    }

    return opts;
}

std::vector<uint8_t> parse_hex_key(const std::string& hex) {
    std::vector<uint8_t> out;
    std::string filtered;
    filtered.reserve(hex.size());
    for (char ch : hex) {
        if (std::isxdigit(static_cast<unsigned char>(ch))) {
            filtered.push_back(static_cast<char>(std::tolower(ch)));
        }
    }
    if (filtered.size() % 2 != 0) {
        filtered.insert(filtered.begin(), '0');
    }
    out.reserve(filtered.size() / 2);
    for (std::size_t i = 0; i + 1 < filtered.size(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(std::stoul(filtered.substr(i, 2), nullptr, 16));
        out.push_back(byte);
    }
    return out;
}

std::vector<uint32_t> parse_indirection(const std::string& csv) {
    std::vector<uint32_t> table;
    std::stringstream ss(csv);
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (item.empty()) continue;
        table.push_back(static_cast<uint32_t>(std::stoul(item)));
    }
    return table;
}

std::unordered_map<uint32_t, int> parse_queue_cpu_map(const std::string& csv) {
    std::unordered_map<uint32_t, int> mapping;
    std::stringstream ss(csv);
    std::string pair;
    while (std::getline(ss, pair, ',')) {
        if (pair.empty()) continue;
        auto pos = pair.find(':');
        if (pos == std::string::npos) continue;
        uint32_t q = static_cast<uint32_t>(std::stoul(pair.substr(0, pos)));
        int cpu = static_cast<int>(std::stoi(pair.substr(pos + 1)));
        mapping[q] = cpu;
    }
    return mapping;
}

bool fetch_rss_via_ethtool(const std::string& ifname, RssConfig& rss) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return false;
    }

    struct ifreq ifr {};
    std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);

    struct ethtool_rxfh base{};
    base.cmd = ETHTOOL_GRSSH;
    base.rss_context = 0;
    base.indir_size = 0;
    base.key_size = 0;
    ifr.ifr_data = reinterpret_cast<char*>(&base);
    if (ioctl(fd, SIOCETHTOOL, &ifr) < 0) {
        close(fd);
        return false;
    }

    if (base.indir_size == 0 || base.key_size == 0) {
        close(fd);
        return false;
    }

    const size_t buf_size = sizeof(ethtool_rxfh) + base.indir_size * sizeof(uint32_t) + base.key_size;
    std::vector<uint8_t> buffer(buf_size);
    auto* req = reinterpret_cast<ethtool_rxfh*>(buffer.data());
    req->cmd = ETHTOOL_GRSSH;
    req->rss_context = 0;
    req->indir_size = base.indir_size;
    req->key_size = base.key_size;
    ifr.ifr_data = reinterpret_cast<char*>(req);
    if (ioctl(fd, SIOCETHTOOL, &ifr) < 0) {
        close(fd);
        return false;
    }

    rss.indirection.assign(req->rss_config, req->rss_config + req->indir_size);
    uint8_t* key_ptr = reinterpret_cast<uint8_t*>(req->rss_config + req->indir_size);
    rss.key.assign(key_ptr, key_ptr + req->key_size);

    close(fd);
    return rss.valid();
}

int parse_cpu_mask(const std::string& mask_str) {
    std::string filtered;
    filtered.reserve(mask_str.size());
    for (char ch : mask_str) {
        if (std::isxdigit(static_cast<unsigned char>(ch))) {
            filtered.push_back(static_cast<char>(std::tolower(ch)));
        }
    }
    int bit_index = 0;
    for (auto it = filtered.rbegin(); it != filtered.rend(); ++it) {
        int nibble = std::stoi(std::string(1, *it), nullptr, 16);
        for (int b = 0; b < 4; ++b) {
            if (nibble & (1 << b)) {
                return bit_index * 4 + b;
            }
        }
        ++bit_index;
    }
    return -1;
}

std::optional<int> read_irq_cpu(int irq) {
    std::ostringstream path;
    path << "/proc/irq/" << irq << "/smp_affinity";
    std::ifstream in(path.str());
    if (!in.is_open()) {
        return std::nullopt;
    }
    std::string mask;
    std::getline(in, mask);
    in.close();
    int cpu = parse_cpu_mask(mask);
    if (cpu < 0) {
        return std::nullopt;
    }
    return cpu;
}

std::unordered_map<uint32_t, int> build_queue_cpu_map_from_system(const std::string& ifname) {
    std::unordered_map<uint32_t, int> mapping;
    std::ifstream interrupts("/proc/interrupts");
    if (!interrupts.is_open()) {
        return mapping;
    }

    std::string line;
    while (std::getline(interrupts, line)) {
        if (line.find(ifname) == std::string::npos) {
            continue;
        }
        std::istringstream iss(line);
        std::string irq_token;
        if (!(iss >> irq_token)) {
            continue;
        }
        if (irq_token.back() == ':') {
            irq_token.pop_back();
        }
        int irq = std::stoi(irq_token);

        std::smatch match;
        std::regex queue_regex(ifname + R"([^0-9]*([0-9]+))");
        if (!std::regex_search(line, match, queue_regex)) {
            continue;
        }
        uint32_t queue = static_cast<uint32_t>(std::stoul(match[1]));
        auto cpu_opt = read_irq_cpu(irq);
        if (cpu_opt) {
            mapping[queue] = *cpu_opt;
        }
    }
    return mapping;
}

struct ToeplitzResult {
    uint32_t hash = 0;
};

uint32_t toeplitz_hash(const std::vector<uint8_t>& key, const uint8_t* data, std::size_t len) {
    if (key.size() < 4) {
        return 0;
    }
    uint32_t hash = 0;
    uint32_t key_window = 0;
    for (int i = 0; i < 4; ++i) {
        key_window = (key_window << 8) | key[i];
    }
    std::size_t key_bits_total = key.size() * 8;
    std::size_t key_bit_pos = 32;

    auto next_key_bit = [&](void) -> uint32_t {
        if (key_bit_pos >= key_bits_total) {
            ++key_bit_pos;
            return 0;
        }
        std::size_t byte_idx = key_bit_pos / 8;
        std::size_t bit_idx = 7 - (key_bit_pos % 8);
        ++key_bit_pos;
        return (key[byte_idx] >> bit_idx) & 0x1;
    };

    for (std::size_t i = 0; i < len; ++i) {
        uint8_t value = data[i];
        for (int bit = 7; bit >= 0; --bit) {
            if ((value >> bit) & 0x1) {
                hash ^= key_window;
            }
            key_window = ((key_window << 1) & 0xFFFFFFFFu) | next_key_bit();
        }
    }
    return hash;
}

std::array<uint8_t, 13> build_tuple_bytes(uint32_t src_ip_host, uint32_t dst_ip_host,
                                          uint16_t src_port_host, uint16_t dst_port_host,
                                          uint8_t proto) {
    std::array<uint8_t, 13> data{};
    uint32_t src_be = htonl(src_ip_host);
    uint32_t dst_be = htonl(dst_ip_host);
    uint16_t sport_be = htons(src_port_host);
    uint16_t dport_be = htons(dst_port_host);
    std::memcpy(data.data() + 0, &src_be, sizeof(src_be));
    std::memcpy(data.data() + 4, &dst_be, sizeof(dst_be));
    std::memcpy(data.data() + 8, &sport_be, sizeof(sport_be));
    std::memcpy(data.data() + 10, &dport_be, sizeof(dport_be));
    data[12] = proto;
    return data;
}

ExpectedRoute compute_expected_route(uint32_t src_ip_host, uint32_t dst_ip_host,
                                     uint16_t src_port_host, uint16_t dst_port_host,
                                     uint8_t proto) {
    ExpectedRoute route{};
    auto tuple_bytes = build_tuple_bytes(src_ip_host, dst_ip_host, src_port_host, dst_port_host, proto);
    route.hash = toeplitz_hash(g_rss_config.key, tuple_bytes.data(), tuple_bytes.size());
    if (!g_rss_config.indirection.empty()) {
        std::size_t slot = route.hash % g_rss_config.indirection.size();
        route.queue = g_rss_config.indirection[slot];
        auto it = g_queue_cpu_map.find(route.queue);
        if (it != g_queue_cpu_map.end()) {
            route.expected_cpu = it->second;
        }
    }
    return route;
}

class TestEndpoint : public EndpointBase {
  public:
    TestEndpoint(const NatConfig& cfg, uint32_t cpu_count)
        : EndpointBase(std::make_shared<NatConfig>(cfg), cpu_count) {}
    using EndpointBase::map_tcp_udp;
};

void pin_to_cpu(int cpu) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
        perror("pthread_setaffinity_np");
    }
}

struct WorkerContext {
    const NatConfig& cfg;
    uint32_t cpu_count;
    std::string ifname;
    int cpu;
    int fanout_group;
};

void log_expected(const ExpectedRoute& route, const std::string& prefix) {
    std::cout << prefix << " toeplitz=0x" << std::hex << route.hash << std::dec
              << " queue=" << route.queue
              << " cpu=" << route.expected_cpu << "\n";
}

void worker_thread(WorkerContext ctx) {
    pin_to_cpu(ctx.cpu);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return;
    }

    int ifindex = if_nametoindex(ctx.ifname.c_str());
    if (ifindex == 0) {
        perror("if_nametoindex");
        close(sock);
        return;
    }

    sockaddr_ll sll{};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if (bind(sock, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) < 0) {
        perror("bind");
        close(sock);
        return;
    }

    int fanout_arg = ctx.fanout_group | (PACKET_FANOUT_HASH << 16);
    if (setsockopt(sock, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg)) < 0) {
        perror("setsockopt PACKET_FANOUT");
        close(sock);
        return;
    }

    TestEndpoint ep(ctx.cfg, ctx.cpu_count);
    std::vector<uint8_t> buf(2048);

    while (true) {
        ssize_t n = recv(sock, buf.data(), buf.size(), 0);
        if (n <= 0) {
            continue;
        }

        auto* eth = reinterpret_cast<ethhdr*>(buf.data());
        if (ntohs(eth->h_proto) != ETH_P_IP) {
            continue;
        }

        auto* iph = reinterpret_cast<iphdr*>(buf.data() + sizeof(ethhdr));
        if (iph->protocol != IPPROTO_UDP) {
            continue;
        }

        auto* udph = reinterpret_cast<udphdr*>(reinterpret_cast<uint8_t*>(iph) + iph->ihl * 4);
        uint32_t src_ip_host = ntohl(iph->saddr);
        uint32_t dst_ip_host = ntohl(iph->daddr);
        uint16_t src_port_host = ntohs(udph->source);
        uint16_t dst_port_host = ntohs(udph->dest);

        int actual_cpu = sched_getcpu();

        if (ctx.cfg.private_netset->contains(src_ip_host)) {
            auto [pub_ip, pub_port] = ep.map_tcp_udp(src_ip_host, dst_ip_host, src_port_host,
                                                     dst_port_host, IPPROTO_UDP,
                                                     ctx.cfg.udp_port_min, ctx.cfg.udp_port_max);
            ExpectedRoute expected = compute_expected_route(pub_ip, dst_ip_host, pub_port,
                                                             dst_port_host, IPPROTO_UDP);
            {
                std::lock_guard<std::mutex> lock(g_nat_mutex);
                g_nat_table[{pub_ip, pub_port}] = expected;
            }
            log_expected(expected, "[nat] outbound expected:");
        } else if (ctx.cfg.public_netset->contains(dst_ip_host)) {
            PubKey key{dst_ip_host, dst_port_host};
            std::optional<ExpectedRoute> stored;
            {
                std::lock_guard<std::mutex> lock(g_nat_mutex);
                auto it = g_nat_table.find(key);
                if (it != g_nat_table.end()) {
                    stored = it->second;
                }
            }

            ExpectedRoute computed = compute_expected_route(src_ip_host, dst_ip_host,
                                                             src_port_host, dst_port_host,
                                                             IPPROTO_UDP);
            bool queue_match = false;
            bool cpu_match = false;
            if (stored) {
                queue_match = (stored->queue == computed.queue);
                cpu_match = (stored->expected_cpu < 0) || (stored->expected_cpu == actual_cpu);
            }

            std::ostringstream oss;
            oss << "[nat] inbound tuple=" << src_ip_host << ":" << src_port_host << " -> "
                << dst_ip_host << ":" << dst_port_host
                << " hash=0x" << std::hex << computed.hash << std::dec
                << " queue=" << computed.queue
                << " expected_cpu=" << (stored ? stored->expected_cpu : -1)
                << " actual_cpu=" << actual_cpu
                << " queue_match=" << (queue_match ? "yes" : "no")
                << " cpu_match=" << (cpu_match ? "yes" : "no");
            std::cout << oss.str() << "\n";
        }
    }
}

bool load_rss_configuration(const Options& opts, RssConfig& rss) {
    if (fetch_rss_via_ethtool(opts.ifname, rss)) {
        return true;
    }
    if (opts.rss_key_hex && opts.rss_table_csv) {
        rss.key = parse_hex_key(*opts.rss_key_hex);
        rss.indirection = parse_indirection(*opts.rss_table_csv);
        if (rss.valid()) {
            return true;
        }
    }
    std::cerr << "Failed to obtain RSS parameters. Provide --rss-key and --rss-table." << std::endl;
    return false;
}

void prepare_queue_cpu_map(const Options& opts) {
    g_queue_cpu_map = build_queue_cpu_map_from_system(opts.ifname);
    if (opts.queue_cpu_csv) {
        auto overrides = parse_queue_cpu_map(*opts.queue_cpu_csv);
        for (const auto& [queue, cpu] : overrides) {
            g_queue_cpu_map[queue] = cpu;
        }
    }
    if (g_queue_cpu_map.empty()) {
        std::cerr << "Queue -> CPU mapping not found; comparisons will skip CPU check." << std::endl;
    }
}

NatConfig make_nat_config() {
    auto prv = Netset::create("127.0.0.1/32");
    auto pub = Netset::create("203.0.113.0/24");

    NatConfig cfg;
    cfg.private_netset = prv;
    cfg.public_netset = pub;
    cfg.udp_port_min = 10000;
    cfg.udp_port_max = 20000;
    return cfg;
}

}  // namespace

int main(int argc, char** argv) {
    Options opts = parse_options(argc, argv);

    if (!load_rss_configuration(opts, g_rss_config)) {
        return 1;
    }
    prepare_queue_cpu_map(opts);

    NatConfig cfg = make_nat_config();

    uint32_t cpu_count = std::thread::hardware_concurrency();
    if (cpu_count == 0) {
        cpu_count = 1;
    }
    int fanout_group = getpid() & 0xffff;

    std::vector<std::thread> workers;
    workers.reserve(cpu_count);
    for (uint32_t cpu = 0; cpu < cpu_count; ++cpu) {
        WorkerContext ctx{cfg, cpu_count, opts.ifname, static_cast<int>(cpu), fanout_group};
        workers.emplace_back(worker_thread, ctx);
        usleep(100000);
    }

    for (auto& t : workers) {
        t.join();
    }

    return 0;
}
