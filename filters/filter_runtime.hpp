#pragma once

#include "filter_engine.hpp"

#include <string>

struct IPv4Header;
struct TCPHeader;
struct UDPHeader;
struct ICMPHeader;

namespace filters {

class ScopedPacket {
  public:
    explicit ScopedPacket(Direction dir);
    ~ScopedPacket();
    ScopedPacket(const ScopedPacket&) = delete;
    ScopedPacket& operator=(const ScopedPacket&) = delete;
    ScopedPacket(ScopedPacket&&) = delete;
    ScopedPacket& operator=(ScopedPacket&&) = delete;
};

void begin_packet(Direction dir);
void end_packet();

bool apply_ipv4(const IPv4Header& ip);
bool apply_tcp(const TCPHeader& tcp);
bool apply_udp(const UDPHeader& udp);
bool apply_icmp(const ICMPHeader& icmp);

void set_filter_path(const std::string& path);
void reload_filters();

const Decision& current_decision();
void set_current_filter(const std::string& name);
const std::string& current_filter_name();

} // namespace filters
