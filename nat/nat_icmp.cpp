#include "nat.h"

#include "checksum_utils.hpp"
#include "../include/icmp.h"
#include "../include/ipv4.h"

#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

namespace {

auto checksum_after_ip_change(uint16_t checksum_net, uint32_t old_ip, uint32_t new_ip) {
    uint16_t host = ntohs(checksum_net);
    host = nat::detail::adjust_checksum32(host, old_ip, new_ip);
    return htons(host);
}

auto checksum_after_id_change(uint16_t checksum_net, uint16_t old_id, uint16_t new_id) {
    uint16_t host = ntohs(checksum_net);
    host = nat::detail::adjust_checksum16(host, old_id, new_id);
    return htons(host);
}

bool supports_id_translation(const icmphdr& hdr) {
    return hdr.type == ICMP_ECHO || hdr.type == ICMP_ECHOREPLY || hdr.type == ICMP_TIMESTAMP ||
           hdr.type == ICMP_TIMESTAMPREPLY;
}

} // namespace

void Nat::process(ICMPHeader& icmp) {
    process(icmp, Clock::now());
}

void Nat::process(ICMPHeader& icmp, Clock::time_point) {
    if (!ready_ || icmp.ip_header == nullptr) {
        return;
    }

    if (!supports_id_translation(icmp.icmph)) {
        return;
    }

    IPv4Header& ip = *icmp.ip_header;
    const uint32_t src_ip = ntohl(ip.iph.saddr);
    const uint32_t dst_ip = ntohl(ip.iph.daddr);
    const uint16_t ident = ntohs(icmp.icmph.un.echo.id);
    const uint16_t seq = ntohs(icmp.icmph.un.echo.sequence);

    if (is_private(src_ip) && !is_private(dst_ip)) {
        Translation tr = ensure_icmp_mapping(src_ip, dst_ip, ident, seq);
        const uint32_t new_ip = tr.pub.pub_ip;
        const uint16_t new_id = tr.pub.pub_port;

        if (new_ip != src_ip) {
            ip.iph.saddr = htonl(new_ip);
            ip.iph.check = checksum_after_ip_change(ip.iph.check, src_ip, new_ip);
        }

        if (new_id != ident) {
            icmp.icmph.un.echo.id = htons(new_id);
            icmp.icmph.checksum = checksum_after_id_change(icmp.icmph.checksum, ident, new_id);
        }

        if (new_ip != src_ip) {
            icmp.icmph.checksum = checksum_after_ip_change(icmp.icmph.checksum, src_ip, new_ip);
        }
    } else if (is_public(dst_ip)) {
        auto tr = find_icmp_reply(dst_ip, src_ip, ident, seq);
        if (!tr) {
            return;
        }

        const uint32_t new_ip = tr->flow.prv_ip;
        const uint16_t new_id = tr->flow.src_port;
        const uint16_t old_id = ident;

        if (new_ip != dst_ip) {
            ip.iph.daddr = htonl(new_ip);
            ip.iph.check = checksum_after_ip_change(ip.iph.check, dst_ip, new_ip);
        }

        if (new_id != old_id) {
            icmp.icmph.un.echo.id = htons(new_id);
            icmp.icmph.checksum = checksum_after_id_change(icmp.icmph.checksum, old_id, new_id);
        }

        if (new_ip != dst_ip) {
            icmp.icmph.checksum = checksum_after_ip_change(icmp.icmph.checksum, dst_ip, new_ip);
        }
    }
}
