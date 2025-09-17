#include "parser.h"
#include "../include/udp.h"
#include <cstring>
template<>
struct Parser<UDPHeader> {
    bool operator()(UDPHeader* hdr, const uint8_t* data, size_t len) {
        if (len < sizeof(UDPHeader)) return false;
        std::memcpy(hdr, data, sizeof(UDPHeader));
        return true;
    }
};
static int _parser_udp_cpp_anchor = 0;
