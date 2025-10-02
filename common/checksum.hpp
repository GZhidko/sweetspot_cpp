#pragma once

#include <cstddef>
#include <cstdint>
#include <netinet/ip.h>

namespace checksum {

bool checksum_block_decrement(uint16_t& partial, uint16_t checksum_host, bool initial,
                              const uint8_t* data, size_t length);
bool checksum_block_increment(uint16_t& checksum_host, uint16_t partial, bool final,
                              const uint8_t* data, size_t length);

uint16_t adjust_checksum16(uint16_t checksum_net, uint16_t old_host, uint16_t new_host);
uint16_t adjust_checksum32(uint16_t checksum_net, uint32_t old_host, uint32_t new_host);

uint16_t ip_checksum(const uint8_t* data, size_t len);
uint16_t l4_checksum(const iphdr* iph, const uint8_t* payload, size_t len, uint8_t proto);
uint16_t recompute_ipv4_checksum(const iphdr& header);

} // namespace checksum
