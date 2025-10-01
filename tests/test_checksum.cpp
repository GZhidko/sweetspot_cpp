#include "../af_packet_io/checksum_utils.h"

#include <arpa/inet.h>
#include <cassert>
#include <cstdint>
#include <random>
#include <vector>
#include <iostream>

namespace {

int sw_tuple_checksum_decrement(uint16_t* partial_csum, uint16_t csum,
                                int initial_flag, unsigned char* packet, int length) {
    int32_t x = csum, old;
    if (length % 2) {
        return -1;
    }
    if (initial_flag)
        x = ~x & 0xffff;
    while (length) {
        old = packet[0] * 256 + packet[1];
        packet += 2;
        x -= old & 0xffff;
        if (x <= 0) {
            x--;
            x &= 0xffff;
        }
        length -= 2;
    }
    *partial_csum = static_cast<uint16_t>(x & 0xffff);
    return 0;
}

int sw_tuple_checksum_increment(uint16_t* csum, uint16_t partial_csum,
                                int final_flag, unsigned char* packet, int length) {
    uint32_t x = partial_csum;
    uint16_t value;
    while (length > 1) {
        value = static_cast<uint16_t>((packet[0] << 8) | packet[1]);
        packet += 2;
        x += value;
        if (x >> 16) {
            x = (x & 0xFFFF) + 1;
        }
        length -= 2;
    }
    if (length == 1) {
        value = static_cast<uint16_t>(packet[0] << 8);
        x += value;
        if (x >> 16) {
            x = (x & 0xFFFF) + 1;
        }
    }
    if (final_flag) {
        x = ~x & 0xFFFF;
    }
    *csum = static_cast<uint16_t>(x & 0xffff);
    return 0;
}

uint16_t sw_checksum(const std::vector<uint8_t>& data) {
    uint16_t partial = 0;
    std::vector<uint8_t> tmp(data);
    if (sw_tuple_checksum_decrement(&partial, 0, 1, tmp.data(), static_cast<int>(tmp.size())) != 0) {
        std::abort();
    }
    uint16_t cs = 0;
    if (sw_tuple_checksum_increment(&cs, partial, 1, tmp.data(), static_cast<int>(tmp.size())) != 0) {
        std::abort();
    }
    return cs;
}

uint16_t sw_l4_checksum(const iphdr* iph, const std::vector<uint8_t>& payload, uint8_t proto) {
    std::vector<uint8_t> buffer;
    buffer.reserve(12 + payload.size() + (payload.size() & 1));
    buffer.push_back((iph->saddr >> 24) & 0xFF);
    buffer.push_back((iph->saddr >> 16) & 0xFF);
    buffer.push_back((iph->saddr >> 8) & 0xFF);
    buffer.push_back(iph->saddr & 0xFF);
    buffer.push_back((iph->daddr >> 24) & 0xFF);
    buffer.push_back((iph->daddr >> 16) & 0xFF);
    buffer.push_back((iph->daddr >> 8) & 0xFF);
    buffer.push_back(iph->daddr & 0xFF);
    buffer.push_back(0);
    buffer.push_back(proto);
    uint16_t len = static_cast<uint16_t>(payload.size());
    buffer.push_back(len >> 8);
    buffer.push_back(len & 0xFF);
    buffer.insert(buffer.end(), payload.begin(), payload.end());
    if (buffer.size() & 1) {
        buffer.push_back(0);
    }
    uint16_t cs = 0;
    sw_tuple_checksum_increment(&cs, 0, 1, buffer.data(), static_cast<int>(buffer.size()));
    return cs;
}

} // namespace

int main() {
    std::mt19937 rng(12345);
    std::uniform_int_distribution<int> len_dist(2, 20);
    std::uniform_int_distribution<int> byte_dist(0, 255);
    std::uniform_int_distribution<uint32_t> ip_dist;
    for (int i = 0; i < 1000; ++i) {
        iphdr iph{};
        iph.version = 4;
        iph.ihl = 5;
        iph.ttl = 64;
        iph.protocol = IPPROTO_TCP;
        iph.tot_len = htons(static_cast<uint16_t>(iph.ihl * 4 + 4));
        iph.saddr = htonl(ip_dist(rng));
        iph.daddr = htonl(ip_dist(rng));

        iph.check = 0;
        uint16_t orig = af_packet_io::ip_checksum(reinterpret_cast<const uint8_t*>(&iph), iph.ihl * 4);
        iph.check = htons(orig);

        uint32_t new_src = htonl(ip_dist(rng));
        uint32_t new_dst = htonl(ip_dist(rng));

        uint16_t partial = 0;
        unsigned char* addr_ptr = reinterpret_cast<unsigned char*>(&iph.saddr);
        sw_tuple_checksum_decrement(&partial, ntohs(iph.check), 1, addr_ptr, 8);
        iph.saddr = new_src;
        iph.daddr = new_dst;
        uint16_t sw_new = 0;
        sw_tuple_checksum_increment(&sw_new, partial, 1, addr_ptr, 8);
        iph.check = htons(sw_new);

        iph.check = 0;
        uint16_t ours = af_packet_io::ip_checksum(reinterpret_cast<const uint8_t*>(&iph), iph.ihl * 4);
        if (sw_new != ours) {
            std::cerr << "Mismatch IP csum sw=" << std::hex << sw_new << " ours=" << ours << std::dec << std::endl;
            return 1;
        }
        iph.check = htons(ours);
    }

    std::cout << "Checksum tests passed" << std::endl;
    return 0;
}
