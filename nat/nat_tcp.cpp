#include "nat.h"

#include "checksum_utils.hpp"
#include "../include/tcp.h"
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

void Nat::process(TCPHeader& tcp) {
    process(tcp, Clock::now());
}

void Nat::process(TCPHeader& tcp, Clock::time_point) {
    if (!ready_ || tcp.ip_header == nullptr) {
        return;
    }

    IPv4Header& ip = *tcp.ip_header;
    const uint32_t src_ip = ntohl(ip.iph.saddr);
    const uint32_t dst_ip = ntohl(ip.iph.daddr);
    const uint16_t src_port = ntohs(tcp.tcph.source);
    const uint16_t dst_port = ntohs(tcp.tcph.dest);

    if (is_private(src_ip) && !is_private(dst_ip)) {
        LOG(DEBUG_NAT, "TCP outbound before NAT src=", to_string_host(src_ip), ":", src_port,
            " dst=", to_string_host(dst_ip), ":", dst_port);
        Translation tr = ensure_tcp_mapping(src_ip, dst_ip, src_port, dst_port);
        const uint32_t new_ip = tr.pub.pub_ip;
        const uint16_t new_port = tr.pub.pub_port;

        if (new_ip != src_ip) {
            LOG(DEBUG_NAT, "TCP outbound IP translate ", to_string_host(src_ip), " -> ",
                to_string_host(new_ip));
            ip.iph.saddr = htonl(new_ip);
            ip.iph.check = checksum_after_ip_change(ip.iph.check, src_ip, new_ip);
        }

        if (new_port != src_port) {
            tcp.tcph.source = htons(new_port);
            if (tcp.tcph.check != 0) {
                tcp.tcph.check = checksum_after_port_change(tcp.tcph.check, src_port, new_port);
            }
            LOG(DEBUG_NAT, "TCP outbound port translate ", src_port, " -> ", new_port);
        }

        if (tcp.tcph.check != 0 && new_ip != src_ip) {
            tcp.tcph.check = checksum_after_ip_change(tcp.tcph.check, src_ip, new_ip);
        }
    } else if (is_public(dst_ip)) {
        auto tr = find_tcp_reply(dst_ip, src_ip, dst_port, src_port);
        if (!tr) {
            return;
        }

        const uint32_t new_ip = tr->flow.prv_ip;
        const uint16_t new_port = tr->flow.src_port;
        const uint16_t old_dest_port = dst_port;

        LOG(DEBUG_NAT, "TCP inbound before NAT src=", to_string_host(src_ip), ":", src_port,
            " dst=", to_string_host(dst_ip), ":", dst_port);

        if (new_ip != dst_ip) {
            LOG(DEBUG_NAT, "TCP inbound IP translate ", to_string_host(dst_ip), " -> ",
                to_string_host(new_ip));
            ip.iph.daddr = htonl(new_ip);
            ip.iph.check = checksum_after_ip_change(ip.iph.check, dst_ip, new_ip);
        }

        if (new_port != old_dest_port) {
            tcp.tcph.dest = htons(new_port);
            if (tcp.tcph.check != 0) {
                tcp.tcph.check = checksum_after_port_change(tcp.tcph.check, old_dest_port, new_port);
            }
            LOG(DEBUG_NAT, "TCP inbound port translate ", old_dest_port, " -> ", new_port);
        }

        if (tcp.tcph.check != 0 && new_ip != dst_ip) {
            tcp.tcph.check = checksum_after_ip_change(tcp.tcph.check, dst_ip, new_ip);
        }
    }
}
