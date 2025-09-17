#pragma once
#include <cstdint>
struct IPv4Header { uint8_t ver_ihl, tos; uint16_t tot_len; uint32_t saddr, daddr; uint8_t protocol; };
