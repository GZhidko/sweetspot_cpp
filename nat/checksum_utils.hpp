#pragma once

#include <arpa/inet.h>
#include <cstdint>
#include <netinet/ip.h>

namespace nat::detail {

inline uint32_t ones_complement_add(uint32_t sum) {
    sum = (sum & 0xFFFFu) + (sum >> 16);
    return (sum & 0xFFFFu) + (sum >> 16);
}

inline bool checksum_block_decrement(uint16_t& partial, uint16_t checksum_host, bool initial,
                                     const uint8_t* data, size_t length) {
    if (length & 1) {
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
            x--;
            x &= 0xFFFF;
        }
    }
    partial = static_cast<uint16_t>(x & 0xFFFF);
    return true;
}

inline bool checksum_block_increment(uint16_t& checksum_host, uint16_t partial, bool final,
                                     const uint8_t* data, size_t length) {
    if (length & 1) {
        return false;
    }
    int32_t x = partial;
    while (length) {
        int32_t new_value = (static_cast<int32_t>(data[0]) << 8) | data[1];
        data += 2;
        length -= 2;
        x += new_value & 0xFFFF;
        if (x & 0x10000) {
            x++;
            x &= 0xFFFF;
        }
    }
    if (final) {
        x = ~x & 0xFFFF;
    }
    checksum_host = static_cast<uint16_t>(x & 0xFFFF);
    return true;
}

inline uint16_t fold_sum(uint32_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return static_cast<uint16_t>(sum & 0xFFFFu);
}

inline uint16_t adjust_checksum16(uint16_t checksum_net, uint16_t old_host,
                                  uint16_t new_host) {
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

inline uint16_t adjust_checksum32(uint16_t checksum_net, uint32_t old_host,
                                  uint32_t new_host) {
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

inline uint16_t recompute_ipv4_checksum(const iphdr& ip_hdr) {
    iphdr tmp = ip_hdr;
    tmp.check = 0;
    const uint16_t* words = reinterpret_cast<const uint16_t*>(&tmp);
    const size_t word_count = static_cast<size_t>(tmp.ihl) * 2u;
    uint32_t sum = 0;
    for (size_t i = 0; i < word_count; ++i) {
        sum += ntohs(words[i]);
    }
    return htons(static_cast<uint16_t>(~fold_sum(sum)));
}

} // namespace nat::detail
