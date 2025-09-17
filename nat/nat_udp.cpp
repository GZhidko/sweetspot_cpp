#include "nat.h"
#include "../include/udp.h"
#include <arpa/inet.h>
template<>
struct Nat<UDPHeader> {
    void operator()(UDPHeader& udp) { if (ntohs(udp.src_port) == 0) udp.src_port = htons(40000); }
};
static int _nat_udp_cpp_anchor = 0;
