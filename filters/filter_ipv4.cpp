#include "filter.h"
#include "../include/ipv4.h"
template<>
struct Filter<IPv4Header> {
    bool operator()(const IPv4Header& ip) {
        // Example filter: allow only packets with protocol TCP (6)
        return true;
    }
};
static int _filter_ipv4_cpp_anchor = 0;
