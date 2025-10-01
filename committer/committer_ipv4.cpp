#include "committer.h"

#include "ipv4.h"
#include "logger.h"

#include <cstring>

bool Committer<IPv4Header>::operator()(const IPv4Header* hdr, uint8_t* data, size_t len,
                                       size_t& offset, const IPv4Header*) const {
    if (!hdr || !data) {
        return false;
    }
    size_t header_len = static_cast<size_t>(hdr->iph.ihl) * 4;
    if (header_len < sizeof(iphdr)) {
        header_len = sizeof(iphdr);
    }
    if (offset + header_len > len) {
        LOG(DEBUG_ERROR, "Commit IPv4: insufficient space header_len=", header_len,
            " offset=", offset, " len=", len);
        return false;
    }
    std::memcpy(data + offset, &hdr->iph, sizeof(iphdr));
    offset += header_len;
    return true;
}

