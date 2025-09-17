#include <iostream>
#include <type_traits>
#include <arpa/inet.h>

#include "chain/header_chain.h"
#include "filters/filter.h"
#include "nat/nat.h"
#include "include/ethernet.h"
#include "include/ipv4.h"
#include "include/tcp.h"
#include "include/udp.h"
#include "include/icmp.h"

template<typename Chain>
bool apply_filters(const Chain& chain) {
    bool ok = true;
    chain.for_each([&](auto& hdr) {
        if (!Filter<std::decay_t<decltype(hdr)>>{}(hdr)) ok = false;
    });
    return ok;
}

template<typename Chain>
void apply_nat(Chain& chain) {
    chain.for_each([&](auto& hdr) {
        Nat<std::decay_t<decltype(hdr)>>{}(hdr);
    });
}

using MyChain = HeaderChainTuple<EthernetHeader, IPv4Header, TCPHeader, UDPHeader, ICMPHeader>;

int main() {
    uint8_t packet[sizeof(EthernetHeader) + sizeof(IPv4Header) + sizeof(TCPHeader)] = {};
    auto eth = reinterpret_cast<EthernetHeader*>(packet); eth->ethertype = htons(0x0800);
    auto ip = reinterpret_cast<IPv4Header*>(packet + sizeof(EthernetHeader)); ip->protocol = 6;
    auto tcp = reinterpret_cast<TCPHeader*>(packet + sizeof(EthernetHeader) + sizeof(IPv4Header)); tcp->dst_port = htons(80);

    MyChain chain;
    if (!chain.parse(packet, sizeof(packet))) { std::cout << "Parse failed\n"; return 1; }
    if (!apply_filters(chain)) { std::cout << "Packet blocked\n"; return 0; }

    apply_nat(chain);
    std::cout << "Packet processed, new src ip = " << ntohl(chain.get<IPv4Header>().saddr) << "\\n";
}
