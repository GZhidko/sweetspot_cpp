#pragma once

#include "filter_runtime.hpp"

template <typename Header> struct Filter {
    bool operator()(const Header&) { return true; }
};

struct IPv4Header;
struct TCPHeader;
struct UDPHeader;
struct ICMPHeader;

template <> struct Filter<IPv4Header> {
    bool operator()(const IPv4Header& ip) { return filters::apply_ipv4(ip); }
};

template <> struct Filter<TCPHeader> {
    bool operator()(const TCPHeader& tcp) { return filters::apply_tcp(tcp); }
};

template <> struct Filter<UDPHeader> {
    bool operator()(const UDPHeader& udp) { return filters::apply_udp(udp); }
};

template <> struct Filter<ICMPHeader> {
    bool operator()(const ICMPHeader& icmp) { return filters::apply_icmp(icmp); }
};
