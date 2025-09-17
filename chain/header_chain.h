#pragma once
#include <tuple>
#include <cstddef>
#include <utility>
#include <type_traits>
#include <cstdint>
#include <cstring>
#include "../parsers/parser.h"

template<typename... Headers>
class HeaderChainTuple {
public:
    HeaderChainTuple() = default;

    bool parse(const uint8_t* data, size_t len) {
        size_t offset = 0;
        return parse_all(data, len, offset);
    }

    template<typename T>
    T& get() { return *std::get<T*>(headers); }

    template<typename F>
    void for_each(F&& func) const {
        std::apply([&](auto*... hdrs) { (func(*hdrs), ...); }, headers);
    }

private:
    std::tuple<Headers*...> headers {};

    bool parse_all(const uint8_t* data, size_t len, size_t& offset) {
        return (parse_one<Headers>(data, len, offset) && ...);
    }

    template<typename T>
    bool parse_one(const uint8_t* data, size_t len, size_t& offset) {
        if (offset + sizeof(T) > len) return false;
        T* hdr = reinterpret_cast<T*>(const_cast<uint8_t*>(data + offset));
        std::get<T*>(headers) = hdr;
        Parser<T> parser;
        bool ok = parser(hdr, data + offset, len - offset);
        offset += sizeof(T);
        return ok;
    }
};
