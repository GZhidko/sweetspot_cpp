#pragma once

#include <cstddef>
#include <cstdint>

#include <cstddef>

struct IPv4Header;
struct TCPHeader;
struct UDPHeader;
struct ICMPHeader;

template <typename Header> struct Committer {
    bool operator()(const Header*, uint8_t*, size_t, size_t&, const IPv4Header* = nullptr) const {
        return true;
    }
};

template <> struct Committer<IPv4Header> {
    bool operator()(const IPv4Header* hdr, uint8_t* data, size_t len, size_t& offset,
                    const IPv4Header* = nullptr) const;
};

template <> struct Committer<TCPHeader> {
    bool operator()(const TCPHeader* hdr, uint8_t* data, size_t len, size_t& offset,
                    const IPv4Header* ip_hdr) const;
};

template <> struct Committer<UDPHeader> {
    bool operator()(const UDPHeader* hdr, uint8_t* data, size_t len, size_t& offset,
                    const IPv4Header* ip_hdr) const;
};

template <> struct Committer<ICMPHeader> {
    bool operator()(const ICMPHeader* hdr, uint8_t* data, size_t len, size_t& offset,
                    const IPv4Header* ip_hdr) const;
};
