#pragma once

#include <arpa/inet.h>
#include <cstdint>
#include <netinet/ip.h>

namespace nat::detail {

inline uint16_t fold_sum(uint32_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return static_cast<uint16_t>(sum & 0xFFFFu);
}

inline uint16_t adjust_checksum16(uint16_t checksum_host, uint16_t old_host,
                                  uint16_t new_host) {
    uint32_t sum = (~checksum_host & 0xFFFFu) + (~old_host & 0xFFFFu) + new_host;
    return static_cast<uint16_t>(~fold_sum(sum));
}

inline uint16_t adjust_checksum32(uint16_t checksum_host, uint32_t old_host,
                                  uint32_t new_host) {
    checksum_host = adjust_checksum16(checksum_host, static_cast<uint16_t>(old_host >> 16),
                                      static_cast<uint16_t>(new_host >> 16));
    return adjust_checksum16(checksum_host, static_cast<uint16_t>(old_host & 0xFFFFu),
                             static_cast<uint16_t>(new_host & 0xFFFFu));
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
