#include "nat.h"
#include "../include/icmp.h"
template<>
struct Nat<ICMPHeader> { void operator()(ICMPHeader&) {} };
static int _nat_icmp_cpp_anchor = 0;
