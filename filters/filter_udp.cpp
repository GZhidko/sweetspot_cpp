#include "filter.h"
#include "../include/udp.h"
template<>
struct Filter<UDPHeader> {
    bool operator()(const UDPHeader&) { return true; }
};
static int _filter_udp_cpp_anchor = 0;
