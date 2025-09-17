#include "filter.h"
#include "../include/tcp.h"
#include <arpa/inet.h>
template<>
struct Filter<TCPHeader> {
    bool operator()(const TCPHeader& tcp) { return ntohs(tcp.dst_port) != 22; }
};
static int _filter_tcp_cpp_anchor = 0;
