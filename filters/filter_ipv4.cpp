#include "filter.h"
#include "../include/ipv4.h"
template<>
struct Filter<IPv4Header> {
    bool operator()(const IPv4Header& ip) { return (ip.protocol == 1 || ip.protocol == 6 || ip.protocol == 17); }
};
static int _filter_ipv4_cpp_anchor = 0;
