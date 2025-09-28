#pragma once
#include "jenkins_hash.hpp"
#include "logger.h"
#include "nat_config.hpp"
#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>
#include <utility>

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
            return {start, end};
        } else {
            // wrap через верх
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
        return netset_ip_at(*config_->public_netset, idx);
    }
  public:
    inline uint32_t pick_cpu(uint32_t hash) const {
        return CPUFanoutHash::select_cpu(hash, cpu_count_);
    }
  protected:
    // Поиск порта/ID внутри диапазона, который даёт нужный CPU
    template <typename TupleBuilder>
    uint16_t choose_port_for_cpu(uint32_t desired_cpu, uint16_t rmin, uint16_t rmax,
                                 TupleBuilder build_tuple) const {
        uint32_t span = static_cast<uint32_t>(rmax - rmin + 1);
        uint32_t slots = (span + cpu_count_ - 1) / cpu_count_; // ceil(span / cpu_count)

        uint32_t h = CPUFanoutHash::hash_tuple(build_tuple(rmin));
        uint32_t offset = (h / cpu_count_) % slots;

        uint32_t candidate = static_cast<uint32_t>(rmin) + desired_cpu + offset * cpu_count_;
        if (candidate > rmax) {
            candidate = static_cast<uint32_t>(rmin) + (candidate - rmin) % span;
        }
        return static_cast<uint16_t>(candidate);
    }

    // ---------- TCP/UDP ----------

    std::pair<uint32_t, uint16_t> map_tcp_udp(uint32_t prv_ip, uint32_t dst_ip, uint16_t src_port,
                                              uint16_t dst_port, uint8_t protocol,
                                              uint16_t port_min, uint16_t port_max) const {
        auto fwd_tuple = std::make_tuple(prv_ip, dst_ip, src_port, dst_port, protocol);
        uint32_t desired_cpu = pick_cpu(CPUFanoutHash::hash_tuple(fwd_tuple));

        auto [rmin, rmax] = get_port_range(prv_ip, port_min, port_max);

        uint32_t pub_ip = select_public_ip(CPUFanoutHash::hash_tuple(fwd_tuple));

        auto builder = [&](uint16_t pub_port) {
            return std::make_tuple(dst_ip, pub_ip, dst_port, pub_port, protocol);
        };
        uint16_t pub_port = choose_port_for_cpu(desired_cpu, rmin, rmax, builder);

        LOG(DEBUG_NETSET, "NAT map TCP/UDP: prv=", prv_ip, " dst=", dst_ip, " -> pub_ip=", pub_ip,
            " pub_port=", pub_port, " cpu=", (int)desired_cpu, " range=[", rmin, "-", rmax, "]");
        return {pub_ip, pub_port};
    }

    // ---------- ICMP ----------
    std::pair<uint32_t, uint16_t> map_icmp(uint32_t prv_ip, uint32_t dst_ip, uint16_t icmp_id_val,
                                           uint16_t icmp_seq_val) const {
        uint16_t id_min = config_->icmp_id_min;
        uint16_t id_max = config_->icmp_id_max;

        auto fwd_tuple = std::make_tuple(prv_ip, dst_ip, icmp_id_val, icmp_seq_val, (uint8_t)1);
        uint32_t desired_cpu = pick_cpu(CPUFanoutHash::hash_tuple(fwd_tuple));

        auto [rmin, rmax] = get_port_range(prv_ip, id_min, id_max);

        uint32_t pub_ip = select_public_ip(CPUFanoutHash::hash_tuple(fwd_tuple));

        auto builder = [&](uint16_t new_id) {
            return std::make_tuple(pub_ip, dst_ip, new_id, icmp_seq_val, (uint8_t)1);
        };
        uint16_t new_id = choose_port_for_cpu(desired_cpu, rmin, rmax, builder);

        LOG(DEBUG_NETSET, "NAT map ICMP: prv=", prv_ip, " dst=", dst_ip, " -> pub_ip=", pub_ip,
            " new_id=", new_id, " cpu=", (int)desired_cpu, " range=[", rmin, "-", rmax, "]");
        return {pub_ip, new_id};
    }
};
