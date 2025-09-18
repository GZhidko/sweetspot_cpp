#include "nat.h"
#include "../include/udp.h"
#include <arpa/inet.h>
template<>
struct Nat<UDPHeader> {
    void operator()(UDPHeader& udp) { };
};
static int _nat_udp_cpp_anchor = 0;
