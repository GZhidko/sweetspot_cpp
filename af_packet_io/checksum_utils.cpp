#include "checksum_utils.h"

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

namespace af_packet_io {
namespace {
uint32_t ones_complement_sum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += (static_cast<uint32_t>(data[0]) << 8) | data[1];
        data += 2;
        len -= 2;
    }
    if (len) {
        sum += static_cast<uint32_t>(*data) << 8;
    }
    return sum;
}
}

uint16_t ip_checksum(const uint8_t* data, size_t len) {
    uint32_t sum = ones_complement_sum(data, len);
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

uint16_t l4_checksum(const iphdr* iph, const uint8_t* payload, size_t len, uint8_t proto) {
    uint32_t sum = 0;
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        struct PseudoHeader {
            uint32_t saddr;
            uint32_t daddr;
            uint8_t zero;
            uint8_t proto;
            uint16_t len;
        } __attribute__((packed));

        PseudoHeader pseudo{};
        pseudo.saddr = iph->saddr;
        pseudo.daddr = iph->daddr;
        pseudo.zero = 0;
        pseudo.proto = proto;
        pseudo.len = htons(static_cast<uint16_t>(len));
        sum += ones_complement_sum(reinterpret_cast<const uint8_t*>(&pseudo), sizeof(PseudoHeader));
    }

    sum += ones_complement_sum(payload, len);
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

} // namespace af_packet_io
