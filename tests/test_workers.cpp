#include "../common/worker.hpp"
#include "../common/netset.hpp"
#include "jenkins_hash.hpp"
#include <array>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <cassert>
#include <iostream>
#include <vector>

namespace {

std::vector<uint8_t> make_tcp_packet(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip,
                                     uint16_t dst_port) {
    std::vector<uint8_t> pkt(sizeof(iphdr) + sizeof(tcphdr), 0);
    auto* ip = reinterpret_cast<iphdr*>(pkt.data());
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->tot_len = htons(static_cast<uint16_t>(pkt.size()));
    ip->saddr = htonl(src_ip);
    ip->daddr = htonl(dst_ip);

    auto* tcp = reinterpret_cast<tcphdr*>(pkt.data() + sizeof(iphdr));
    tcp->source = htons(src_port);
    tcp->dest = htons(dst_port);
    tcp->doff = 5;
    tcp->seq = htonl(1);
    tcp->ack_seq = htonl(1);
    tcp->syn = 1;
    tcp->ack = 1;

    return pkt;
}

uint32_t hash_thread(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port,
                     uint8_t proto, uint32_t thread_count) {
    auto tuple = std::make_tuple(htonl(src_ip), htonl(dst_ip), htons(src_port), htons(dst_port),
                                 proto);
    uint32_t hash = CPUFanoutHash::hash_tuple(tuple);
    return CPUFanoutHash::select_cpu(hash, thread_count);
}

uint32_t parse_ip32(const char* ip) {
    in_addr addr{};
    if (::inet_aton(ip, &addr) != 1) {
        throw std::runtime_error(std::string("Invalid IP: ") + ip);
    }
    return ntohl(addr.s_addr);
}

} // namespace

int main() {
    WorkerPipelineConfig cfgA;
    cfgA.thread_index = 0;
    cfgA.thread_count = 2;
    cfgA.enable_io = false;
    cfgA.nat.private_netset = Netset::create("10.0.0.0/24");
    cfgA.nat.public_netset = Netset::create("198.51.100.0/24");

    WorkerPipelineConfig cfgB = cfgA;
    cfgB.thread_index = 1;

    Worker workerA(cfgA);
    Worker workerB(cfgB);

    std::array<Worker*, 2> workers{&workerA, &workerB};
    std::array<size_t, 2> forwarded_count{0, 0};

    auto forward_cb = [&](uint32_t target, Worker::FramePayload&& frame) {
        if (target < workers.size()) {
            ++forwarded_count[target];
            workers[target]->submit_remote_frame(std::move(frame));
        }
    };

    workerA.set_forward_callback(forward_cb);
    workerB.set_forward_callback(forward_cb);

    uint32_t priv_ip = parse_ip32("10.0.0.10");
    uint32_t remote_ip = parse_ip32("203.0.113.50");

    uint32_t owner_thread = hash_thread(priv_ip, 12345, remote_ip, 443, IPPROTO_TCP, cfgA.thread_count);
    Worker* owner = workers[owner_thread];
    Worker* other = workers[1 - owner_thread];

    auto outbound = make_tcp_packet(priv_ip, 12345, remote_ip, 443);
    owner->process_frame_for_tests(outbound);
    auto out_frames = owner->collect_tx_frames();
    assert(!out_frames.empty());

    auto mapping = owner->nat_for_tests().lookup_tcp_outbound(priv_ip, remote_ip, 12345, 443);
    assert(mapping.has_value());
    uint32_t pub_ip = mapping->pub.pub_ip;
    uint16_t pub_port = mapping->pub.pub_port;

    uint16_t remote_port = 1;
    while (remote_port < 65000) {
        if (hash_thread(remote_ip, remote_port, pub_ip, pub_port, IPPROTO_TCP,
                        cfgA.thread_count) == owner_thread) {
            break;
        }
        ++remote_port;
    }
    assert(remote_port < 65000);

    auto reply = make_tcp_packet(remote_ip, remote_port, pub_ip, pub_port);
    other->process_frame_for_tests(reply);

    assert(forwarded_count[owner_thread] == 1);
    assert(other->collect_tx_frames().empty());

    owner->process_remote_frames_for_tests();
    owner->collect_tx_frames();

    std::cout << "Worker forwarding test passed" << std::endl;
    return 0;
}
