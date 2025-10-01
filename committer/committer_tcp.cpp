#include "committer.h"

#include "logger.h"
#include "tcp.h"

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
    std::memcpy(data + offset, &hdr->tcph, sizeof(tcphdr));
    offset += header_len;
    return true;
}

