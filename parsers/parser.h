#pragma once
#include <cstring>
#include <cstddef>
template<typename Header>
struct Parser {
    bool operator()(Header* hdr, const uint8_t* data, size_t len) {
        if (len < sizeof(Header)) return false;
        std::memcpy(hdr, data, sizeof(Header));
        return true;
    }
};
