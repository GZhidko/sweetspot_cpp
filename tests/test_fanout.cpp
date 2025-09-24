#include <arpa/inet.h>
#include <iostream>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <sched.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include <unordered_map>

#include "common/logger.h"
#include "nat/endpoint_base.hpp"
#include "nat/nat_config.hpp"

// ===============================
//  Ключ для таблицы: public ip + port
// ===============================
struct PubKey {
    uint32_t ip;
    uint16_t port;
    bool operator==(const PubKey& other) const {
        return ip == other.ip && port == other.port;
    }
};

struct PubKeyHash {
    std::size_t operator()(const PubKey& k) const noexcept {
        return (std::hash<uint64_t>()(((uint64_t)k.ip << 32) | k.port));
    }
};

// ===============================
//  Таблица маппингов: pub_ip/pub_port -> expected_slot
// ===============================
std::unordered_map<PubKey, uint32_t, PubKeyHash> nat_table;
std::mutex table_mtx;

// ===============================
//  Endpoint для теста NAT logic
// ===============================
class TestEndpoint : public EndpointBase {
  public:
    TestEndpoint(const NatConfig& cfg, uint32_t cpu_count) : EndpointBase(cfg, cpu_count) {}
    using EndpointBase::map_tcp_udp;

    // slot = hash % cpu_count
    uint32_t pick_slot(const std::tuple<uint32_t,uint32_t,uint16_t,uint16_t,uint8_t>& tuple) const {
        uint32_t h = CPUFanoutHash::hash_tuple(tuple);
        return h % cpu_count_;
    }
};

// ===============================
//  Utility: pin thread to CPU
// ===============================
void pin_to_cpu(int cpu) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
        perror("pthread_setaffinity_np");
    }
}

// ===============================
//  Worker thread
// ===============================
void worker_thread(const NatConfig& cfg, uint32_t cpu_count, const std::string& ifname,
                   int cpu, int fanout_group) {
    pin_to_cpu(cpu);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); return; }

    int ifindex = if_nametoindex(ifname.c_str());
    if (ifindex == 0) { perror("if_nametoindex"); close(sock); return; }

    struct sockaddr_ll sll {};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind"); close(sock); return;
    }

    int fanout_arg = (fanout_group | (PACKET_FANOUT_HASH << 16));
    if (setsockopt(sock, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg)) < 0) {
        perror("setsockopt PACKET_FANOUT"); close(sock); return;
    }

    TestEndpoint ep(cfg, cpu_count);
    std::vector<uint8_t> buf(2048);

    while (true) {
        ssize_t n = recv(sock, buf.data(), buf.size(), 0);
        if (n <= 0) continue;

        auto* eth = (struct ethhdr*)buf.data();
        if (ntohs(eth->h_proto) != ETH_P_IP) continue;

        auto* iph = (struct iphdr*)(buf.data() + sizeof(struct ethhdr));
        if (iph->protocol != IPPROTO_UDP) continue;

        auto* udph = (struct udphdr*)((uint8_t*)iph + iph->ihl * 4);
        uint32_t src_ip = ntohl(iph->saddr);
        uint32_t dst_ip = ntohl(iph->daddr);
        uint16_t src_port = ntohs(udph->source);
        uint16_t dst_port = ntohs(udph->dest);
        
        uint32_t src_ip_b = (iph->saddr);
        uint32_t dst_ip_b = (iph->daddr);
        uint16_t src_port_b = (udph->source);
        uint16_t dst_port_b = (udph->dest);


        // === 1. Приватные пакеты: строим NAT ===
        if (cfg.private_netset->contains(src_ip)) {
            auto pre_tuple = std::make_tuple(src_ip_b, dst_ip_b, src_port_b, dst_port_b, IPPROTO_UDP);
            uint32_t h = CPUFanoutHash::hash_tuple(pre_tuple);

            uint32_t pre_slot = ep.pick_cpu(h);

            auto [pub_ip, pub_port] =
                ep.map_tcp_udp(src_ip, dst_ip, src_port, dst_port, IPPROTO_UDP,
                               cfg.udp_port_min, cfg.udp_port_max);

            auto post_tuple = std::make_tuple(pub_ip, dst_ip, pub_port, dst_port, IPPROTO_UDP);

            h = CPUFanoutHash::hash_tuple(post_tuple);
            uint32_t post_slot = ep.pick_cpu(h);

            {
                std::lock_guard<std::mutex> lock(table_mtx);
                nat_table[{pub_ip, pub_port}] = pre_slot;
            }

            std::cout << "[thread " << cpu 
                      << "] Mapped " << src_ip << ":" << src_port
                      << " -> " << pub_ip << ":" << pub_port
                      << " pre_slot=" << pre_slot
                      << " post_slot=" << post_slot << std::endl;
            return;
        }

        // === 2. Пакеты на публичный IP (ответы) ===
        if (cfg.public_netset->contains(dst_ip)) {
            PubKey key{dst_ip, dst_port};
            std::lock_guard<std::mutex> lock(table_mtx);
            auto it = nat_table.find(key);
            if (it != nat_table.end()) {
                uint32_t expected_slot = it->second;

                auto reply_tuple = std::make_tuple(src_ip, dst_ip, src_port, dst_port, IPPROTO_UDP);
               
                uint32_t h = CPUFanoutHash::hash_tuple(reply_tuple);
                uint32_t reply_slot = ep.pick_cpu(h);

                if (reply_slot == expected_slot) {
                    std::cout << "[thread " << std::this_thread::get_id()
                              << "] Reply OK slot=" << reply_slot
                              << " (expected=" << expected_slot << ")"
                              << " pub_ip=" << dst_ip
                              << " pub_port=" << dst_port << std::endl;
                } else {
                    std::cerr << "[thread " << std::this_thread::get_id()
                              << "] Reply MISMATCH slot=" << reply_slot
                              << " expected=" << expected_slot
                              << " pub_ip=" << dst_ip
                              << " pub_port=" << dst_port << std::endl;
                }
            }
            return;
        }
    }
}

// ===============================
//  Main
// ===============================
int main(int argc, char** argv) {
    std::string ifname = (argc > 1) ? argv[1] : "lo";

    // Минимальная конфигурация NAT
    auto prv = Netset::create("127.0.0.1/32");
    auto pub = Netset::create("203.0.113.0/24");

    NatConfig cfg;
    cfg.private_netset = prv;
    cfg.public_netset  = pub;
    cfg.udp_port_min   = 10000;
    cfg.udp_port_max   = 20000;

    uint32_t cpu_count = std::thread::hardware_concurrency();
    int fanout_group   = getpid() & 0xffff;

    std::vector<std::thread> workers;
    for (uint32_t cpu = 0; cpu < cpu_count; ++cpu) {
        workers.emplace_back(worker_thread, std::ref(cfg), cpu_count, ifname, cpu, fanout_group);
        usleep(100000); // небольшая задержка для последовательного запуска
    }

    for (auto& t : workers) {
        t.join();
    }
    return 0;
}

