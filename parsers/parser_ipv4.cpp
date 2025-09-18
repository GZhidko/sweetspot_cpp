// parser_ipv4.cpp
#include "ipv4.h"
#include "logger.h"
#include "parser.h"

bool Parser<IPv4Header>::operator()(IPv4Header* hdr, const uint8_t* data, size_t len,
                                    size_t& offset, IPv4Header* ip_hdr ) {
    if (len - offset < sizeof(struct iphdr)) {
        LOG(DEBUG_PARSER, "IPv4 parser: not enough data for IP header");
        return false;
    }

    // Копируем iphdr из данных пакета
    std::memcpy(&hdr->iph, data + offset, sizeof(struct iphdr));

    // Проверяем корректность заголовка
    if (hdr->iph.ihl < 5) {
        LOG(DEBUG_PARSER, "IPv4 parser: invalid IHL ", static_cast<int>(hdr->iph.ihl));
        return false;
    }

    size_t ip_header_len = hdr->iph.ihl * 4;
    if (ip_header_len < sizeof(struct iphdr) || offset + ip_header_len > len) {
        LOG(DEBUG_PARSER, "IPv4 parser: invalid IP header length ", ip_header_len);
        return false;
    }

    offset += ip_header_len;

    LOG(DEBUG_PARSER, "IPv4 parsed: ", IPv4Header::ip_to_string(hdr->iph.saddr), " -> ",
        IPv4Header::ip_to_string(hdr->iph.daddr), " protocol ", (int)hdr->iph.protocol, " length ",
        ip_header_len);

    return true;
};
