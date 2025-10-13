#pragma once
#include "jenkins_hash.hpp"
#include "logger.h"
#include "nat_config.hpp"
#include "../include/ipv4.h"

#include <arpa/inet.h>
#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>
#include <utility>
#include <limits>

class EndpointBase {
  protected:
    EndpointBase(std::shared_ptr<NatConfig> config, uint32_t cpu_count = 1)
        : config_(std::move(config)), cpu_count_(cpu_count) {
        if (!config_) {
            throw std::invalid_argument("EndpointBase requires non-null config");
        }
    }

    std::shared_ptr<NatConfig> config_;
    uint32_t cpu_count_;

    // ---------- УТИЛИТЫ ----------

    static std::string ip_to_string(uint32_t ip_host_order) {
        return IPv4Header::ip_to_string(htonl(ip_host_order));
    }

    static inline uint32_t full_range_size(uint16_t port_min, uint16_t port_max) {
        return static_cast<uint32_t>(port_max) - static_cast<uint32_t>(port_min) + 1u;
    }

    // ports_per_prv = max(1, pub_size * ports_total / prv_size)
    uint32_t ports_per_private(uint16_t port_min, uint16_t port_max) const {
        const uint32_t prv = config_->private_ip_count();
        const uint32_t pub = config_->public_ip_count();
        if (prv == 0 || pub == 0) {
            throw std::runtime_error("Netsets are not configured");
        }
        const uint32_t total = full_range_size(port_min, port_max);
        uint32_t per = (pub * total) / prv;
        if (per == 0)
            per = 1;
        LOG(DEBUG_NAT, "ports_per_private range=[", port_min, "-", port_max, "] prv_count=", prv,
            " pub_count=", pub, " total_ports=", total, " per=", per);
        return per;
    }

    // Поддиапазон для конкретного prv_ip
    std::pair<uint16_t, uint16_t> get_port_range(uint32_t prv_ip, uint16_t port_min,
                                                 uint16_t port_max) const {
        if (!config_->private_netset) {
            throw std::runtime_error("No private netset configured");
        }
        const uint32_t prv_idx = config_->private_netset->idx(prv_ip);
        const uint32_t total = full_range_size(port_min, port_max);
        const uint32_t per = ports_per_private(port_min, port_max);

        const uint32_t start_off = (static_cast<uint64_t>(prv_idx) * per) % total;
        uint16_t start = static_cast<uint16_t>(port_min + start_off);
        uint16_t end = static_cast<uint16_t>(port_min + ((start_off + per - 1) % total));

        if (end >= start) {
            LOG(DEBUG_NAT, "get_port_range prv=", ip_to_string(prv_ip), " -> [", start, "-",
                end, "] (per=", per, ")");
            return {start, end};
        } else {
            // wrap через верх
            LOG(DEBUG_NAT, "get_port_range prv=", ip_to_string(prv_ip), " -> [", start, "-",
                port_max, "] wrap (per=", per, ")");
            return {start, port_max};
        }
    }

    // Получить IP по индексу в netset
    static uint32_t netset_ip_at(const Netset& ns, uint32_t idx) {
        auto node = ns.get_head();
        while (node) {
            uint32_t count = node->ip_max - node->ip_min + 1;
            if (idx < count) {
                return node->ip_min + idx;
            }
            idx -= count;
            node = node->next;
        }
        throw std::out_of_range("netset_ip_at: index out of range");
    }

    // Выбор pub IP по хэшу
    uint32_t select_public_ip(uint32_t hash) const {
        const uint32_t pub_cnt = config_->public_ip_count();
        if (!config_->public_netset || pub_cnt == 0) {
            throw std::runtime_error("No public netset configured");
        }
        const uint32_t idx = hash % pub_cnt;
        uint32_t ip = netset_ip_at(*config_->public_netset, idx);
        LOG(DEBUG_NAT, "select_public_ip hash=", hash, " idx=", idx,
            " pub_ip=", ip_to_string(ip));
        return ip;
    }
  public:
    inline uint32_t pick_cpu(uint32_t hash) const {
        return CPUFanoutHash::select_cpu(hash, cpu_count_);
    }
  protected:
    // Поиск порта/ID внутри диапазона, который даёт нужный CPU
    template <typename TupleBuilder>
    uint16_t choose_port_for_cpu(uint32_t desired_cpu, uint16_t rmin, uint16_t rmax,
                                 uint32_t hash_seed, TupleBuilder build_tuple) const {
        const uint32_t span = static_cast<uint32_t>(rmax - rmin + 1);
        if (span == 0) {
            return rmin;
        }

        const uint32_t start_offset = hash_seed % span;
        for (uint32_t attempt = 0; attempt < span; ++attempt) {
            const uint32_t offset = (start_offset + attempt) % span;
            const uint16_t candidate = static_cast<uint16_t>(static_cast<uint32_t>(rmin) + offset);
            const uint32_t cpu = pick_cpu(CPUFanoutHash::hash_tuple(build_tuple(candidate)));
            if (cpu == desired_cpu) {
                LOG(DEBUG_NAT, "choose_port_for_cpu desired_cpu=", desired_cpu,
                    " range=[", rmin, "-", rmax, "] span=", span,
                    " attempt=", attempt, " candidate=", candidate, " hit_cpu=", cpu);
                return candidate;
            }
        }

        const uint16_t fallback = static_cast<uint16_t>(static_cast<uint32_t>(rmin) + start_offset);
        LOG(DEBUG_NAT, "choose_port_for_cpu fallback desired_cpu=", desired_cpu,
            " range=[", rmin, "-", rmax, "] span=", span,
            " fallback=", fallback);
        return fallback;
    }

    // ---------- TCP/UDP ----------

    std::pair<uint32_t, uint16_t> map_tcp_udp(uint32_t prv_ip, uint32_t dst_ip, uint16_t src_port,
                                              uint16_t dst_port, uint8_t protocol,
                                              uint16_t port_min, uint16_t port_max,
                                              uint32_t desired_cpu_hint =
                                                  std::numeric_limits<uint32_t>::max()) const {
        auto fwd_tuple = std::make_tuple(htonl(prv_ip), htonl(dst_ip), htons(src_port),
                                         htons(dst_port), protocol);
        uint32_t forward_hash = CPUFanoutHash::hash_tuple(fwd_tuple);
        uint32_t desired_cpu = desired_cpu_hint == std::numeric_limits<uint32_t>::max()
                                   ? pick_cpu(forward_hash)
                                   : desired_cpu_hint % cpu_count_;

        auto [rmin, rmax] = get_port_range(prv_ip, port_min, port_max);

        uint32_t pub_ip = select_public_ip(forward_hash);

        auto builder = [&](uint16_t pub_port) {
            return std::make_tuple(htonl(dst_ip), htonl(pub_ip), htons(dst_port),
                                   htons(pub_port), protocol);
        };
        uint16_t pub_port = choose_port_for_cpu(desired_cpu, rmin, rmax, forward_hash, builder);

        LOG(DEBUG_NETSET, "NAT map TCP/UDP: prv=", ip_to_string(prv_ip), " dst=",
            ip_to_string(dst_ip), " -> pub_ip=", ip_to_string(pub_ip), " pub_port=", pub_port,
            " cpu=", (int)desired_cpu, " range=[", rmin, "-", rmax, "]");
        return {pub_ip, pub_port};
    }

    // ---------- ICMP ----------
    std::pair<uint32_t, uint16_t> map_icmp(uint32_t prv_ip, uint32_t dst_ip, uint16_t icmp_id_val,
                                           uint16_t icmp_seq_val,
                                           uint32_t desired_cpu_hint =
                                               std::numeric_limits<uint32_t>::max()) const {
        uint16_t id_min = config_->icmp_id_min;
        uint16_t id_max = config_->icmp_id_max;

        auto fwd_tuple = std::make_tuple(htonl(prv_ip), htonl(dst_ip), htons(icmp_id_val),
                                         htons(icmp_seq_val), static_cast<uint8_t>(1));
        uint32_t forward_hash = CPUFanoutHash::hash_tuple(fwd_tuple);
        uint32_t desired_cpu = desired_cpu_hint == std::numeric_limits<uint32_t>::max()
                                   ? pick_cpu(forward_hash)
                                   : desired_cpu_hint % cpu_count_;

        auto [rmin, rmax] = get_port_range(prv_ip, id_min, id_max);

        uint32_t pub_ip = select_public_ip(forward_hash);

        auto builder = [&](uint16_t new_id) {
            return std::make_tuple(htonl(dst_ip), htonl(pub_ip), htons(new_id),
                                   htons(icmp_seq_val), static_cast<uint8_t>(1));
        };
        uint16_t new_id = choose_port_for_cpu(desired_cpu, rmin, rmax, forward_hash, builder);

        LOG(DEBUG_NETSET, "NAT map ICMP: prv=", ip_to_string(prv_ip), " dst=",
            ip_to_string(dst_ip), " -> pub_ip=", ip_to_string(pub_ip), " new_id=", new_id,
            " cpu=", (int)desired_cpu, " range=[", rmin, "-", rmax, "]");
        return {pub_ip, new_id};
    }
};
