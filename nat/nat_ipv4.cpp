#include "nat.h"

#include "checksum_utils.hpp"
#include "../include/ipv4.h"

#include <arpa/inet.h>
#include <netinet/ip.h>

namespace {
std::string to_string_host(uint32_t host_ip) {
    return IPv4Header::ip_to_string(htonl(host_ip));
}
}

void Nat::process(IPv4Header& ip) {
    process(ip, Clock::now());
}

void Nat::process(IPv4Header& ip, Clock::time_point) {
    if (!ready_) {
        return;
    }

    const uint8_t proto = ip.iph.protocol;
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP || proto == IPPROTO_ICMP) {
        // These protocols are handled together with their L4 headers.
        return;
    }

    const uint32_t src_ip = ntohl(ip.iph.saddr);
    const uint32_t dst_ip = ntohl(ip.iph.daddr);

    if (is_private(src_ip) && !is_private(dst_ip)) {
        LOG(DEBUG_NAT, "IPv4 outbound before NAT src=", to_string_host(src_ip),
            " dst=", to_string_host(dst_ip), " proto=", static_cast<int>(proto));
        Translation tr = ensure_ip_mapping(src_ip, dst_ip, proto);
        const uint32_t new_ip = tr.pub.pub_ip;
        if (new_ip != src_ip) {
            LOG(DEBUG_NAT, "IPv4 outbound translating src ", to_string_host(src_ip), " -> ",
                to_string_host(new_ip));
            uint16_t checksum = ntohs(ip.iph.check);
            checksum = nat::detail::adjust_checksum32(checksum, src_ip, new_ip);
            ip.iph.saddr = htonl(new_ip);
            ip.iph.check = htons(checksum);
        }
    } else if (is_public(dst_ip)) {
        auto tr = find_ip_reply(dst_ip, src_ip, proto);
        if (tr) {
            const uint32_t new_ip = tr->flow.prv_ip;
            if (new_ip != dst_ip) {
                LOG(DEBUG_NAT, "IPv4 inbound translating dst ", to_string_host(dst_ip), " -> ",
                    to_string_host(new_ip));
                uint16_t checksum = ntohs(ip.iph.check);
                checksum = nat::detail::adjust_checksum32(checksum, dst_ip, new_ip);
                ip.iph.daddr = htonl(new_ip);
                ip.iph.check = htons(checksum);
            }
        }
    }
}
