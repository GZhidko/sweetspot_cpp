#pragma once
#include <cstdint>
#include "jenkins_hash.hpp"
struct EthernetHeader { uint8_t dst[6]; uint8_t src[6]; uint16_t ethertype; };
