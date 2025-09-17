#include "filter.h"
#include "../include/icmp.h"
template<>
struct Filter<ICMPHeader> {
    bool operator()(const ICMPHeader& icmp) { return (icmp.type == 0 || icmp.type == 8); }
};
static int _filter_icmp_cpp_anchor = 0;
