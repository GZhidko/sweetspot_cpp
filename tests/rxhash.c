#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <cstring>

struct tpacket_auxdata_compat {
    uint32_t tp_status;
    uint32_t tp_len;
    uint32_t tp_snaplen;
    uint16_t tp_mac;
    uint16_t tp_net;
    uint32_t tp_rxhash;   // расширение
};

int main() {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); return 1; }

    int one = 1;
    if (setsockopt(sock, SOL_PACKET, PACKET_AUXDATA, &one, sizeof(one)) < 0) {
        perror("setsockopt PACKET_AUXDATA");
    }

    char buf[2048];
    char cbuf[256];
    struct iovec iov { buf, sizeof(buf) };
    struct msghdr msg {};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    while (true) {
        ssize_t n = recvmsg(sock, &msg, 0);
        if (n <= 0) continue;

        for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
             cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_PACKET &&
                cmsg->cmsg_type == PACKET_AUXDATA) {
                auto* aux = reinterpret_cast<tpacket_auxdata_compat*>(CMSG_DATA(cmsg));
                std::cout << "rxhash=" << aux->tp_rxhash << std::endl;
            }
        }
    }
}

