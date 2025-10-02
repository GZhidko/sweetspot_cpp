#include "committer.h"

#include "logger.h"
#include "udp.h"
#include "../af_packet_io/checksum_utils.h"

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
    size_t header_start = offset;
    std::memcpy(data + offset, &hdr->udph, sizeof(udphdr));
    offset += header_len;

    auto* udp_data = reinterpret_cast<udphdr*>(data + header_start);
    uint16_t udp_length = ntohs(udp_data->len);
#ifdef NAT_FULL_CHECKSUM
    if (!ip_hdr || udp_length < sizeof(udphdr)) {
        udp_data->check = 0;
        return true;
    }

    if (header_start + udp_length > len) {
        LOG(DEBUG_ERROR, "Commit UDP: segment length overflow udp_length=", udp_length,
            " header_start=", header_start, " len=", len);
        udp_data->check = 0;
        return false;
    }

    if (udp_data->check != 0) {
        udp_data->check = 0;
        uint16_t checksum = af_packet_io::l4_checksum(&ip_hdr->iph,
                                                      reinterpret_cast<const uint8_t*>(udp_data),
                                                      udp_length,
                                                      IPPROTO_UDP);
        udp_data->check = htons(checksum);
    }
#else
    (void)ip_hdr;
    (void)udp_length;
    (void)len;
#endif
    return true;
}
