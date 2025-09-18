// parser_udp.cpp
#include "ipv4.h"
#include "logger.h"
#include "parser.h"
#include "udp.h"

bool Parser<UDPHeader>::operator()(UDPHeader* hdr, const uint8_t* data, size_t len, size_t& offset,
                                   IPv4Header* ip_hdr) {
    if (len - offset < sizeof(struct udphdr)) {
        LOG(DEBUG_PARSER, "UDP parser: not enough data for UDP header");
        return false;
    }

    // Копируем udphdr из данных пакета
    std::memcpy(&hdr->udph, data + offset, sizeof(struct udphdr));

    // Устанавливаем ссылку на IP заголовок
    hdr->ip_header = ip_hdr;

    offset += sizeof(struct udphdr);

    if (ip_hdr) {
        LOG(DEBUG_PARSER, "UDP parsed: ", IPv4Header::ip_to_string(ip_hdr->iph.saddr), ":",
            ntohs(hdr->udph.source), " -> ", IPv4Header::ip_to_string(ip_hdr->iph.daddr), ":",
            ntohs(hdr->udph.dest), " length ", ntohs(hdr->udph.len));
    } else {
        LOG(DEBUG_PARSER, "UDP parsed: no IP header available");
    }

    return true;
};
