#pragma once
#include <cstdint>
struct ICMPHeader { uint8_t type, code; uint16_t checksum; };
