#include "committer.h"

#include "icmp.h"
#include "logger.h"

#include <cstring>

bool Committer<ICMPHeader>::operator()(const ICMPHeader* hdr, uint8_t* data, size_t len,
                                       size_t& offset, const IPv4Header* ip_hdr) const {
    if (!hdr || !data || !ip_hdr) {
        return false;
    }
    constexpr size_t header_len = sizeof(icmphdr);
    if (offset + header_len > len) {
        LOG(DEBUG_ERROR, "Commit ICMP: insufficient space offset=", offset, " len=", len);
        return false;
    }
    std::memcpy(data + offset, &hdr->icmph, sizeof(icmphdr));
    offset += header_len;
    return true;
}

