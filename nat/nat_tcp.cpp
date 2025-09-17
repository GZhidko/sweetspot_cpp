#include "nat.h"
#include "../include/tcp.h"
#include <arpa/inet.h>
template<>
struct Nat<TCPHeader> {
    void operator()(TCPHeader& tcp) { if (ntohs(tcp.src_port) == 0) tcp.src_port = htons(40000); }
};
static int _nat_tcp_cpp_anchor = 0;
