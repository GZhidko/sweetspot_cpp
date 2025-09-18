#include "nat.h"
#include "../include/tcp.h"
#include <arpa/inet.h>
template<>
struct Nat<TCPHeader> {
    void operator()(TCPHeader& tcp) { 
}
};
static int _nat_tcp_cpp_anchor = 0;
