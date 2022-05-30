#include "inline.h"
#include "log.h"
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>

int inline_run(const char *in_ifname, const char *out_ifname, const uint8_t *ether_dst, const hop_t *hops, size_t nhops) {
    int rfd, wfd, retval = 0;

    rfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));

    if (rfd < 0) {
        log_fatal("input socket: %s\n", strerror(errno));
        return rfd;
    }

    wfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);

    if (wfd < 0) {
        log_fatal("output socket: %s\n", strerror(errno));
        close(rfd);
        return wfd;
    }

    uint8_t rbuf[0xffff + sizeof(struct ether_header)], wbuf[0xffff + sizeof(struct ether_header)];

    //  bind to interface to scope the sniffing.
    int inindex = ifname2index(in_ifname);

    if (inindex < 0) {
        log_fatal("invalid input interface: %s\n", in_ifname);
        retval = inindex;
        goto end;
    }

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(struct sockaddr_ll));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = inindex;
    addr.sll_protocol = htons(ETH_P_IP);

    if (bind(rfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_ll)) < 0) {
        log_fatal("bind input socket: %s\n", strerror(errno));
        retval = -1;
        goto end;
    }

    // pre-fill the outgoing sockaddr_ll.
    int outindex = ifname2index(out_ifname);
    if (outindex < 0) {
        log_fatal("invalid output interface: %s\n", in_ifname);
        retval = outindex;
        goto end;
    }

    struct sockaddr_ll dst_addr;
    memset(&dst_addr, 0, sizeof(struct sockaddr_ll));

    dst_addr.sll_ifindex = outindex;
    dst_addr.sll_halen = ETH_ALEN;
    memcpy(dst_addr.sll_addr, ether_dst, ETH_ALEN);

    // pre-fill the outgoing ether header.
    struct ether_header *oethhdr = (struct ether_header *) wbuf;
    memcpy(oethhdr->ether_dhost, ether_dst, ETH_ALEN);
    get_eth_addr(outindex, oethhdr->ether_shost);
    oethhdr->ether_type = htons(ETH_P_IP);
    uint8_t *wptr = wbuf + sizeof(struct ether_header);

    // enable promiscuous mode on input interface.
    struct packet_mreq mr;
    memset(&mr, 0, sizeof(struct packet_mreq));
    mr.mr_ifindex = inindex;
    mr.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(rfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
        log_fatal("setsockopt(): %s\n", strerror(errno));
        retval = -1;
        goto end;
    }

    // get scatter/gather ready.
    struct sockaddr_ll src_addr;

    struct iovec iov[1];
    iov[0].iov_base = rbuf;
    iov[0].iov_len = sizeof(rbuf);

    struct msghdr message;
    message.msg_name = &src_addr;
    message.msg_namelen = sizeof(src_addr);
    message.msg_iov = iov;
    message.msg_iovlen = 1;
    message.msg_control = 0;
    message.msg_controllen = 0;

    log_debug("listening on '%s', sending on '%s'...\n", in_ifname, out_ifname);

    while (1) {
        ssize_t len = recvmsg(rfd, &message, 0);

        if (len < 0) {
            log_fatal("recvmsg(): %s\n", strerror(errno));
            retval = -1;
            goto end;
        }

        struct ether_header *iethhdr = (struct ether_header *) rbuf;

        if (iethhdr->ether_type != htons(ETH_P_IP)) {
            continue;
        }


        uint8_t *rptr = (uint8_t *) (rbuf + sizeof(struct ether_header));

        len = build_reply(hops, nhops, rptr, (size_t) len, wptr, 0xffff);

        if (len <= 0) {
            continue;
        }
        
        len = sendto(wfd, wbuf, (size_t) len + sizeof(struct ether_header), 0, (struct sockaddr *) &dst_addr, sizeof(dst_addr));

        if (len < 0) {
            log_error("error sending reply: %s\n", strerror(errno));
        }
    }

end:
    close(wfd);
    close(rfd);
    return retval;
}

int ifname2index(const char *ifname) {
    struct ifreq ifr;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0) {
        log_fatal("socket: %s\n", strerror(errno));
        return fd;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        log_fatal("ioctl: %s\n", strerror(errno));
        return -1;
    }

    close(fd);

    return ifr.ifr_ifindex;
}

int get_eth_addr(int ifindex, uint8_t *addr) {
    struct ifreq ifr;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0) {
        log_fatal("socket: %s\n", strerror(errno));
        return fd;
    }

    ifr.ifr_ifindex = ifindex;

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        log_fatal("ioctl: %s\n", strerror(errno));
        return -1;
    }

    close(fd);

    memcpy(addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    return 0;
}