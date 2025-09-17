#include "nat.h"
#include "../include/ipv4.h"
#include <arpa/inet.h>
template<>
struct Nat<IPv4Header> {
    void operator()(IPv4Header& ip) { ip.saddr = htonl(0x0A000001); }
};
static int _nat_ipv4_cpp_anchor = 0;
