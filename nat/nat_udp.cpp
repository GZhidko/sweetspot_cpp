#include "nat.h"

#include "checksum_utils.hpp"
#include "../include/udp.h"
#include "../include/ipv4.h"

#include <arpa/inet.h>

namespace {

auto checksum_after_ip_change(uint16_t checksum_net, uint32_t old_ip, uint32_t new_ip) {
    uint16_t host = ntohs(checksum_net);
    host = nat::detail::adjust_checksum32(host, old_ip, new_ip);
    return htons(host);
}

auto checksum_after_port_change(uint16_t checksum_net, uint16_t old_port, uint16_t new_port) {
    uint16_t host = ntohs(checksum_net);
    host = nat::detail::adjust_checksum16(host, old_port, new_port);
    return htons(host);
}

std::string to_string_host(uint32_t host_ip) {
    return IPv4Header::ip_to_string(htonl(host_ip));
}

} // namespace

void Nat::process(UDPHeader& udp) {
    process(udp, Clock::now());
}

void Nat::process(UDPHeader& udp, Clock::time_point) {
    if (!ready_ || udp.ip_header == nullptr) {
        return;
    }

    IPv4Header& ip = *udp.ip_header;
    const uint32_t src_ip = ntohl(ip.iph.saddr);
    const uint32_t dst_ip = ntohl(ip.iph.daddr);
    const uint16_t src_port = ntohs(udp.udph.source);
    const uint16_t dst_port = ntohs(udp.udph.dest);
    const bool checksum_present = udp.udph.check != 0;

    if (is_private(src_ip) && !is_private(dst_ip)) {
        LOG(DEBUG_NAT, "UDP outbound before NAT src=", to_string_host(src_ip), ":", src_port,
            " dst=", to_string_host(dst_ip), ":", dst_port);
        Translation tr = ensure_udp_mapping(src_ip, dst_ip, src_port, dst_port);
        const uint32_t new_ip = tr.pub.pub_ip;
        const uint16_t new_port = tr.pub.pub_port;

        if (new_ip != src_ip) {
            LOG(DEBUG_NAT, "UDP outbound IP translate ", to_string_host(src_ip), " -> ",
                to_string_host(new_ip));
            ip.iph.saddr = htonl(new_ip);
            ip.iph.check = checksum_after_ip_change(ip.iph.check, src_ip, new_ip);
        }

        if (new_port != src_port) {
            udp.udph.source = htons(new_port);
            if (checksum_present) {
                udp.udph.check = checksum_after_port_change(udp.udph.check, src_port, new_port);
            }
        }
        if (new_port != src_port) {
            LOG(DEBUG_NAT, "UDP outbound port translate ", src_port, " -> ", new_port);
        }

        if (checksum_present && new_ip != src_ip) {
            udp.udph.check = checksum_after_ip_change(udp.udph.check, src_ip, new_ip);
        }
    } else if (is_public(dst_ip)) {
        auto tr = find_udp_reply(dst_ip, src_ip, dst_port, src_port);
        if (!tr) {
            return;
        }

        const uint32_t new_ip = tr->flow.prv_ip;
        const uint16_t new_port = tr->flow.src_port;
        const uint16_t old_dest_port = dst_port;

        LOG(DEBUG_NAT, "UDP inbound before NAT src=", to_string_host(src_ip), ":", src_port,
            " dst=", to_string_host(dst_ip), ":", dst_port);

        if (new_ip != dst_ip) {
            LOG(DEBUG_NAT, "UDP inbound IP translate ", to_string_host(dst_ip), " -> ",
                to_string_host(new_ip));
            ip.iph.daddr = htonl(new_ip);
            ip.iph.check = checksum_after_ip_change(ip.iph.check, dst_ip, new_ip);
        }

        if (new_port != old_dest_port) {
            udp.udph.dest = htons(new_port);
            if (checksum_present) {
                udp.udph.check = checksum_after_port_change(udp.udph.check, old_dest_port, new_port);
            }
            LOG(DEBUG_NAT, "UDP inbound port translate ", old_dest_port, " -> ", new_port);
        }

        if (checksum_present && new_ip != dst_ip) {
            udp.udph.check = checksum_after_ip_change(udp.udph.check, dst_ip, new_ip);
        }
    }
}
