#include "checksum_utils.h"

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

namespace af_packet_io {
namespace {
uint16_t raw_checksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += (static_cast<uint32_t>(data[0]) << 8) | data[1];
        data += 2;
        len -= 2;
    }
    if (len) {
        sum += static_cast<uint32_t>(*data) << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}
}

uint16_t ip_checksum(const uint8_t* data, size_t len) {
    return raw_checksum(data, len);
}

uint16_t l4_checksum(const iphdr* iph, const uint8_t* payload, size_t len, uint8_t proto) {
    uint32_t sum = 0;
    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += iph->saddr & 0xFFFF;
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += iph->daddr & 0xFFFF;
    sum += htons(static_cast<uint16_t>(proto));
    sum += htons(static_cast<uint16_t>(len));

    while (len > 1) {
        sum += (static_cast<uint32_t>(payload[0]) << 8) | payload[1];
        payload += 2;
        len -= 2;
    }
    if (len) {
        sum += static_cast<uint32_t>(*payload) << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

} // namespace af_packet_io

