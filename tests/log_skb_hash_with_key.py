#!/usr/bin/env python3
from bcc import BPF
import ctypes
import socket
import struct



prog = r"""
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

struct event_t {
    __u32 saddr_be;
    __u32 daddr_be;
    __u16 sport_be;
    __u16 dport_be;
    __u8  proto;
    __u32 hash;
    __u64 k0;
    __u64 k1;
};

BPF_HASH(skbs, u64, struct sk_buff *);
BPF_PERF_OUTPUT(events);

static int parse_ipv4(struct sk_buff *skb, struct event_t *ev)
{
    void *head = NULL;
    __u16 nhoff = 0, thoff = 0;
    struct iphdr iph = {};

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head))
        return -1;
    if (bpf_probe_read_kernel(&nhoff, sizeof(nhoff), &skb->network_header))
        return -1;
    if (bpf_probe_read_kernel(&thoff, sizeof(thoff), &skb->transport_header))
        return -1;

    void *ip_ptr = head + nhoff;
    if (bpf_probe_read_kernel(&iph, sizeof(iph), ip_ptr))
        return -1;
    if (iph.version != 4)
        return -1;

    ev->saddr_be = iph.saddr;
    ev->daddr_be = iph.daddr;
    ev->proto = iph.protocol;

    if (iph.protocol == IPPROTO_UDP) {
        struct udphdr udph = {};
        if (bpf_probe_read_kernel(&udph, sizeof(udph), head + thoff))
            return -1;
        ev->sport_be = udph.source;
        ev->dport_be = udph.dest;
    } else if (iph.protocol == IPPROTO_TCP) {
        struct tcphdr tcph = {};
        if (bpf_probe_read_kernel(&tcph, sizeof(tcph), head + thoff))
            return -1;
        ev->sport_be = tcph.source;
        ev->dport_be = tcph.dest;
    } else {
        ev->sport_be = 0;
        ev->dport_be = 0;
    }
    return 0;
}

int kprobe____skb_get_hash(struct pt_regs *ctx, struct sk_buff *skb)
{
    u64 id = bpf_get_current_pid_tgid();
    skbs.update(&id, &skb);
    return 0;
}

int kretprobe____skb_get_hash(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct sk_buff **pskb = skbs.lookup(&id);
    if (!pskb)
        return 0;

    struct sk_buff *skb = *pskb;
    skbs.delete(&id);

    struct event_t ev = {};
    if (parse_ipv4(skb, &ev) < 0)
        return 0;

    bpf_probe_read_kernel(&ev.hash, sizeof(ev.hash), &skb->hash);

    // Чтение hashrnd из net/core/flow_dissector.c
    __u64 *rnd = (__u64 *)0xffffffff83a54c70; // Замените на реальный адрес
    bpf_probe_read_kernel(&ev.k0, sizeof(ev.k0), rnd);
    bpf_probe_read_kernel(&ev.k1, sizeof(ev.k1), rnd + 1);

    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}
"""
b = BPF(text=prog)
class Ev(ctypes.Structure):
    _fields_ = [
        ("saddr_be", ctypes.c_uint32),
        ("daddr_be", ctypes.c_uint32),
        ("sport_be", ctypes.c_uint16),
        ("dport_be", ctypes.c_uint16),
        ("proto",    ctypes.c_ubyte),
        ("hash",     ctypes.c_uint32),
        ("k0",       ctypes.c_uint64),
        ("k1",       ctypes.c_uint64),
    ]
def ip_str(be32):
    return socket.inet_ntoa(struct.pack("!I", be32))

def port_num(be16):
    return struct.unpack("!H", struct.pack("H", be16))[0]


def print_event(cpu, data, size):
    ev = ctypes.cast(data, ctypes.POINTER(Ev)).contents
    saddr = ip_str(ev.saddr_be)
    daddr = ip_str(ev.daddr_be)

    if ev.proto in (6, 17):  # TCP=6, UDP=17
        sport = port_num(ev.sport_be)
        dport = port_num(ev.dport_be)
        human = f"{saddr}:{sport} -> {daddr}:{dport} proto={ev.proto} hash=0x{ev.hash:08x} k0=0x{ev.k0:016x} k1=0x{ev.k1:016x}"
    else:  # ICMP и другие
        human = f"{saddr} -> {daddr} proto={ev.proto} hash=0x{ev.hash:08x} k0=0x{ev.k0:016x} k1=0x{ev.k1:016x}"

    print(human)

    with open("/tmp/flowhash.csv", "a") as f:
        f.write(f"{ev.saddr_be},{ev.daddr_be},{ev.sport_be},{ev.dport_be},{ev.proto},{ev.hash},{ev.k0},{ev.k1}\n")

b["events"].open_perf_buffer(print_event)

with open("/tmp/flowhash.csv", "w") as f:
    f.write("saddr_be,daddr_be,sport_be,dport_be,proto,hash,k0,k1\n")

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    pass
