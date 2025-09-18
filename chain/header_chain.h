#pragma once
#include "../include/forward_dec.h"
#include "../parsers/parser.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <tuple>
#include <type_traits>
#include <utility>

template <typename... Headers> class HeaderChainTuple {
  public:
    HeaderChainTuple() = default;

    bool parse(const uint8_t* data, size_t len) {
        size_t offset = 0;
        return parse_packet(data, len, offset);
    }

    template <typename T> T* get() {
        auto& ptr = std::get<std::unique_ptr<T>>(headers);
        return ptr ? ptr.get() : nullptr;
    }

    template <typename T> const T* get() const {
        auto& ptr = std::get<std::unique_ptr<T>>(headers);
        return ptr ? ptr.get() : nullptr;
    }

    template <typename F> void for_each(F&& func) const {
        std::apply([&](auto&... hdrs) { ((hdrs ? func(*hdrs) : void()), ...); }, headers);
    }

    // Получение Flow для NAT
    template <typename Proto> auto get_flow() const {
        if constexpr (std::is_same_v<Proto, IPv4Header>) {
            return get<IPv4Header>()->get_flow();
        } else if constexpr (std::is_same_v<Proto, UDPHeader>) {
            return get<UDPHeader>()->get_flow();
        } else if constexpr (std::is_same_v<Proto, TCPHeader>) {
            return get<TCPHeader>()->get_flow();
        } else if constexpr (std::is_same_v<Proto, ICMPHeader>) {
            return get<ICMPHeader>()->get_flow();
        }
    }

  private:
    std::tuple<std::unique_ptr<Headers>...> headers{};

    bool parse_packet(const uint8_t* data, size_t len, size_t& offset) {
        // IPv4 обязателен
        if (!parse_one<IPv4Header>(data, len, offset))
            return false;
        auto* ip = get<IPv4Header>();
        if (!ip)
            return false;

        // Ветка по протоколу
        switch (ip->iph.protocol) {
        case IPPROTO_TCP:
            return parse_one<TCPHeader>(data, len, offset, ip);
        case IPPROTO_UDP:
            return parse_one<UDPHeader>(data, len, offset, ip);
        case IPPROTO_ICMP:
            return parse_one<ICMPHeader>(data, len, offset, ip);
        default:
            return true; // оставляем только IP
        }
    }
    template <typename T>
    bool parse_one(const uint8_t* data, size_t len, size_t& offset,
                   IPv4Header* ip_hdr = nullptr) {
        Parser<T> parser;
        auto hdr = std::make_unique<T>();

        if constexpr (std::is_same_v<T, UDPHeader> ||
                      std::is_same_v<T, TCPHeader> ||
                      std::is_same_v<T, ICMPHeader>) {
            if (!parser(hdr.get(), data, len, offset, ip_hdr))
                return false;
            hdr->ip_header = ip_hdr;
        } else {
            if (!parser(hdr.get(), data, len, offset))
                return false;
        }

        std::get<std::unique_ptr<T>>(headers) = std::move(hdr);
        return true;
    }

};

