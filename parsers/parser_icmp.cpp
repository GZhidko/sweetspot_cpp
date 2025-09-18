// parser_icmp.cpp
#include "icmp.h"
#include "ipv4.h"
#include "logger.h"
#include "parser.h"

bool Parser<ICMPHeader>::operator()(ICMPHeader* hdr, const uint8_t* data, size_t len,
                                    size_t& offset, IPv4Header* ip_hdr ) {
    if (len - offset < sizeof(struct icmphdr)) {
        LOG(DEBUG_PARSER, "ICMP parser: not enough data for ICMP header");
        return false;
    }

    // Копируем icmphdr из данных пакета
    std::memcpy(&hdr->icmph, data + offset, sizeof(struct icmphdr));

    // Устанавливаем ссылку на IP заголовок
    hdr->ip_header = ip_hdr;

    offset += sizeof(struct icmphdr);

    if (ip_hdr) {
        LOG(DEBUG_PARSER, "ICMP parsed: ", IPv4Header::ip_to_string(ip_hdr->iph.saddr), " -> ",
            IPv4Header::ip_to_string(ip_hdr->iph.daddr), " type ", (int)hdr->icmph.type, " code ",
            (int)hdr->icmph.code);
    } else {
        LOG(DEBUG_PARSER, "ICMP parsed: no IP header available");
    }

    return true;
};
