#include "parser.h"
#include "../include/ipv4.h"
#include <cstring>
template<>
struct Parser<IPv4Header> {
    bool operator()(IPv4Header* hdr, const uint8_t* data, size_t len) {
        if (len < sizeof(IPv4Header)) return false;
        std::memcpy(hdr, data, sizeof(IPv4Header));
        return true;
    }
};
static int _parser_ipv4_cpp_anchor = 0;
