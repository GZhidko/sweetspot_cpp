#include "committer.h"

#include "logger.h"
#include "tcp.h"
#include "checksum.hpp"

#include <algorithm>
#include <cstring>

bool Committer<TCPHeader>::operator()(const TCPHeader* hdr, uint8_t* data, size_t len,
                                      size_t& offset, const IPv4Header* ip_hdr) const {
    if (!hdr || !data || !ip_hdr) {
        return false;
    }
    size_t header_len = static_cast<size_t>(hdr->tcph.doff) * 4;
    if (header_len < sizeof(tcphdr)) {
        header_len = sizeof(tcphdr);
    }
    if (offset + header_len > len) {
        LOG(DEBUG_ERROR, "Commit TCP: insufficient space header_len=", header_len,
            " offset=", offset, " len=", len);
        return false;
    }
    const size_t header_start = offset;
    std::memcpy(data + offset, &hdr->tcph, sizeof(tcphdr));
    offset += header_len;

    auto* tcp_data = reinterpret_cast<tcphdr*>(data + header_start);
#ifdef NAT_FULL_CHECKSUM
    if (!ip_hdr || ntohs(ip_hdr->iph.tot_len) < static_cast<uint16_t>(ip_hdr->iph.ihl) * 4u + sizeof(tcphdr)) {
        tcp_data->check = 0;
        return true;
    }

    uint16_t tcp_length = static_cast<uint16_t>(ntohs(ip_hdr->iph.tot_len) -
                                                static_cast<uint16_t>(ip_hdr->iph.ihl) * 4u);
    if (header_start + tcp_length > len) {
        LOG(DEBUG_ERROR, "Commit TCP: segment length overflow tcp_length=", tcp_length,
            " header_start=", header_start, " len=", len);
        tcp_data->check = 0;
        return false;
    }
    tcp_data->check = 0;
    uint16_t checksum = checksum::l4_checksum(&ip_hdr->iph,
                                              reinterpret_cast<const uint8_t*>(tcp_data),
                                              tcp_length,
                                              IPPROTO_TCP);
    tcp_data->check = htons(checksum);
#else
    (void)ip_hdr;
    (void)len;
    tcp_data->check = hdr->tcph.check;
#endif
    return true;
}
