#include "parser.h"
#include "../include/tcp.h"
#include <cstring>
template<>
struct Parser<TCPHeader> {
    bool operator()(TCPHeader* hdr, const uint8_t* data, size_t len) {
        if (len < sizeof(TCPHeader)) return false;
        std::memcpy(hdr, data, sizeof(TCPHeader));
        return true;
    }
};
static int _parser_tcp_cpp_anchor = 0;
