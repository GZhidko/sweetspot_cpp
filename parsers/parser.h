#pragma once
#include <cstring>
#include <cstddef>
#include <stdint.h>
#include "ipv4.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
template<typename Header>
struct Parser {
    bool operator()(Header* hdr, const uint8_t* data, size_t len,
                    size_t& offset, IPv4Header* ip_hdr = nullptr) {
        printf("Generic parser called\n");
        return true;
    }
};

// IPv4
template<>
struct Parser<IPv4Header> {
    bool operator()(IPv4Header* hdr, const uint8_t* data, size_t len,
                    size_t& offset, IPv4Header* ip_hdr = nullptr);
};

// TCP
template<>
struct Parser<TCPHeader> {
    bool operator()(TCPHeader* hdr, const uint8_t* data, size_t len,
                    size_t& offset, IPv4Header* ip_hdr = nullptr);
};

// UDP
template<>
struct Parser<UDPHeader> {
    bool operator()(UDPHeader* hdr, const uint8_t* data, size_t len,
                    size_t& offset, IPv4Header* ip_hdr = nullptr);
};

// ICMP
template<>
struct Parser<ICMPHeader> {
    bool operator()(ICMPHeader* hdr, const uint8_t* data, size_t len,
                    size_t& offset, IPv4Header* ip_hdr = nullptr);
};

