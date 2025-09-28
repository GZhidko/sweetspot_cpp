#include <iostream>
#include <type_traits>
#include <arpa/inet.h>

#include "chain/header_chain.h"
#include "filters/filter.h"
#include "common/logger.h"
#include "include/ethernet.h"
#include "include/ipv4.h"
#include "include/tcp.h"
#include "include/udp.h"
#include "include/icmp.h"

template<typename Chain>
bool apply_filters(const Chain& chain) {
    bool ok = true;
    chain.for_each([&](auto& hdr) {
        if (!Filter<std::decay_t<decltype(hdr)>>{}(hdr)) ok = false;
    });
    return ok;
}

using MyChain = HeaderChainTuple< IPv4Header, TCPHeader, UDPHeader, ICMPHeader >;

int main() {
    Logger::setFlags(DEBUG_ALL);
//    Logger::setOutputFile("my.log");

    // Создаем пакет с реальными заголовками
    uint8_t packet[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {};
    
    // Заполняем IP заголовок
    struct iphdr* ip = reinterpret_cast<struct iphdr*>(packet);
    ip->version = 4;
    ip->ihl = 5; // 5 * 4 = 20 байт
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->protocol = IPPROTO_TCP; // TCP
    ip->saddr = htonl(0xC0A80101); // 192.168.1.1
    ip->daddr = htonl(0x08080808); // 8.8.8.8
    
    // Заполняем TCP заголовок
    struct tcphdr* tcp = reinterpret_cast<struct tcphdr*>(packet + sizeof(struct iphdr));
    tcp->source = htons(12345);
    tcp->dest = htons(80);
    tcp->doff = 5; // 5 * 4 = 20 байт

    LOG(DEBUG_PARSER, "Created test packet:");
    LOG(DEBUG_PARSER, "  IP: ", IPv4Header::ip_to_string(ntohl(ip->saddr)), 
        " -> ", IPv4Header::ip_to_string(ntohl(ip->daddr)));
    LOG(DEBUG_PARSER, "  TCP: ", ntohs(tcp->source), " -> ", ntohs(tcp->dest));

    // Парсим пакет
    MyChain chain;
    if (!chain.parse(packet, sizeof(packet))) { 
        LOG(DEBUG_ERROR, "Parse failed");
        std::cout << "Parse failed\n"; 
        return 1; 
    }

    // Получаем заголовки для проверки
    try {
        IPv4Header * ip_hdr = chain.get<IPv4Header>();
        TCPHeader * tcp_hdr = chain.get<TCPHeader>();
        
        LOG(DEBUG_PARSER, "Parsing successful:");
        LOG(DEBUG_PARSER, "  IP src: ", IPv4Header::ip_to_string(ip_hdr->iph.saddr));
        LOG(DEBUG_PARSER, "  IP dst: ", IPv4Header::ip_to_string(ip_hdr->iph.daddr));
        LOG(DEBUG_PARSER, "  TCP src port: ", ntohs(tcp_hdr->tcph.source));
        LOG(DEBUG_PARSER, "  TCP dst port: ", ntohs(tcp_hdr->tcph.dest));
        
        // Проверяем связь между заголовками
        if (tcp_hdr->ip_header == ip_hdr) {
            LOG(DEBUG_PARSER, "IP-TCP linkage: OK");
        } else {
            LOG(DEBUG_ERROR, "IP-TCP linkage: FAILED");
        }
        
        // Получаем flow info
        auto flow = tcp_hdr->get_flow();
        LOG(DEBUG_PARSER, "Flow info:");
        LOG(DEBUG_PARSER, "  Src: ", IPv4Header::ip_to_string(flow.src_ip), ":", flow.src_port);
        LOG(DEBUG_PARSER, "  Dst: ", IPv4Header::ip_to_string(flow.dst_ip), ":", flow.dst_port);
        LOG(DEBUG_PARSER, "  Protocol: ", (int)flow.protocol);
        
    } catch (const std::exception& e) {
        LOG(DEBUG_ERROR, "Error accessing headers: ", e.what());
        return 1;
    }

    LOG(DEBUG_PARSER, "All workers completed");
    Logger::shutdown();
    
    std::cout << "Packet parsing completed successfully!\n";
    return 0;
}
