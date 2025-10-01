#pragma once

#include <cstddef>
#include <cstdint>
#include <netinet/ip.h>

namespace af_packet_io {

uint16_t ip_checksum(const uint8_t* data, size_t len);
uint16_t l4_checksum(const iphdr* iph, const uint8_t* payload, size_t len, uint8_t proto);

} // namespace af_packet_io

