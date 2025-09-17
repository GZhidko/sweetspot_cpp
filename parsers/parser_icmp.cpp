#include "parser.h"
#include "../include/icmp.h"
#include <cstring>
template<>
struct Parser<ICMPHeader> {
    bool operator()(ICMPHeader* hdr, const uint8_t* data, size_t len) {
        if (len < sizeof(ICMPHeader)) return false;
        std::memcpy(hdr, data, sizeof(ICMPHeader));
        return true;
    }
};
static int _parser_icmp_cpp_anchor = 0;
