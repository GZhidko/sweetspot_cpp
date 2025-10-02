#include "checksum.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>

namespace checksum {
namespace {

inline uint32_t fold_sum(uint32_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return sum & 0xFFFFu;
}

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

} // namespace

bool checksum_block_decrement(uint16_t& partial, uint16_t checksum_host, bool initial,
                              const uint8_t* data, size_t length) {
    if (length & 1u) {
        return false;
    }
    int32_t x = checksum_host;
    if (initial) {
        x = ~x & 0xFFFF;
    }
    while (length) {
        int32_t old_value = (static_cast<int32_t>(data[0]) << 8) | data[1];
        data += 2;
        length -= 2;
        x -= old_value & 0xFFFF;
        if (x <= 0) {
            x -= 1;
            x &= 0xFFFF;
        }
    }
    partial = static_cast<uint16_t>(x & 0xFFFF);
    return true;
}

bool checksum_block_increment(uint16_t& checksum_host, uint16_t partial, bool final,
                              const uint8_t* data, size_t length) {
    if (length & 1u) {
        return false;
    }
    int32_t x = partial;
    while (length) {
        int32_t new_value = (static_cast<int32_t>(data[0]) << 8) | data[1];
        data += 2;
        length -= 2;
        x += new_value & 0xFFFF;
        if (x & 0x10000) {
            x += 1;
            x &= 0xFFFF;
        }
    }
    if (final) {
        x = ~x & 0xFFFF;
    }
    checksum_host = static_cast<uint16_t>(x & 0xFFFF);
    return true;
}

uint16_t adjust_checksum16(uint16_t checksum_net, uint16_t old_host, uint16_t new_host) {
    uint16_t partial = 0;
    uint16_t checksum_host = ntohs(checksum_net);
    uint16_t old_net = htons(old_host);
    uint16_t new_net = htons(new_host);
    if (!checksum_block_decrement(partial, checksum_host, true,
                                  reinterpret_cast<const uint8_t*>(&old_net), sizeof(old_net))) {
        return checksum_net;
    }
    if (!checksum_block_increment(checksum_host, partial, true,
                                  reinterpret_cast<const uint8_t*>(&new_net), sizeof(new_net))) {
        return checksum_net;
    }
    return htons(checksum_host);
}

uint16_t adjust_checksum32(uint16_t checksum_net, uint32_t old_host, uint32_t new_host) {
    uint16_t partial = 0;
    uint16_t checksum_host = ntohs(checksum_net);
    uint32_t old_net = htonl(old_host);
    uint32_t new_net = htonl(new_host);
    if (!checksum_block_decrement(partial, checksum_host, true,
                                  reinterpret_cast<const uint8_t*>(&old_net), sizeof(old_net))) {
        return checksum_net;
    }
    if (!checksum_block_increment(checksum_host, partial, true,
                                  reinterpret_cast<const uint8_t*>(&new_net), sizeof(new_net))) {
        return checksum_net;
    }
    return htons(checksum_host);
}

uint16_t ip_checksum(const uint8_t* data, size_t len) {
    uint32_t sum = ones_complement_sum(data, len);
    sum = fold_sum(sum);
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
    sum = fold_sum(sum);
    return static_cast<uint16_t>(~sum);
}

uint16_t recompute_ipv4_checksum(const iphdr& header) {
    iphdr copy = header;
    copy.check = 0;
    return ip_checksum(reinterpret_cast<const uint8_t*>(&copy), static_cast<size_t>(copy.ihl) * 4u);
}

} // namespace checksum
