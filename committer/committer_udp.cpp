#include "committer.h"

#include "logger.h"
#include "udp.h"

#include <cstring>

bool Committer<UDPHeader>::operator()(const UDPHeader* hdr, uint8_t* data, size_t len,
                                      size_t& offset, const IPv4Header* ip_hdr) const {
    if (!hdr || !data || !ip_hdr) {
        return false;
    }
    constexpr size_t header_len = sizeof(udphdr);
    if (offset + header_len > len) {
        LOG(DEBUG_ERROR, "Commit UDP: insufficient space offset=", offset, " len=", len);
        return false;
    }
    std::memcpy(data + offset, &hdr->udph, sizeof(udphdr));
    offset += header_len;
    return true;
}

