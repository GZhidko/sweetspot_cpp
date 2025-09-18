// parser_tcp.cpp
#include "ipv4.h"
#include "logger.h"
#include "parser.h"
#include "tcp.h"

bool Parser<TCPHeader>::operator()(TCPHeader* hdr, const uint8_t* data, size_t len, size_t& offset,
                                   IPv4Header* ip_hdr) {

    if (len - offset < sizeof(struct tcphdr)) {
        LOG(DEBUG_PARSER, "TCP parser: not enough data for TCP header");
        return false;
    }

    // Копируем tcphdr из данных пакета
    std::memcpy(&hdr->tcph, data + offset, sizeof(struct tcphdr));

    // Устанавливаем ссылку на IP заголовок
    hdr->ip_header = ip_hdr;

    // Вычисляем размер TCP заголовка
    size_t tcp_header_len = hdr->tcph.doff * 4;
    if (tcp_header_len < sizeof(struct tcphdr) || offset + tcp_header_len > len) {
        LOG(DEBUG_PARSER, "TCP parser: invalid TCP header length ", tcp_header_len);
        return false;
    }

    offset += tcp_header_len;

    if (ip_hdr) {
        LOG(DEBUG_PARSER, "TCP parsed: ", IPv4Header::ip_to_string(ip_hdr->iph.saddr), ":",
            ntohs(hdr->tcph.source), " -> ", IPv4Header::ip_to_string(ip_hdr->iph.daddr), ":",
            ntohs(hdr->tcph.dest), " length ", tcp_header_len);
    } else {
        LOG(DEBUG_PARSER, "TCP parsed: no IP header available");
    }

    return true;
};
