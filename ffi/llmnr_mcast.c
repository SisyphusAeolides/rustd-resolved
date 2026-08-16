/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* LLMNR multicast membership helpers. */
#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

static int llmnr_membership_v4(int fd, int ifindex, int join) {
    struct ip_mreqn membership = {0};

    if (fd < 0 || ifindex <= 0) {
        errno = EINVAL;
        return -1;
    }
    membership.imr_multiaddr.s_addr = htonl(0xE00000FC); /* 224.0.0.252 */
    membership.imr_ifindex = ifindex;
    return setsockopt(fd, IPPROTO_IP,
                      join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP,
                      &membership, sizeof(membership));
}

static int llmnr_membership_v6(int fd, int ifindex, int join) {
    struct ipv6_mreq membership = {0};

    if (fd < 0 || ifindex <= 0) {
        errno = EINVAL;
        return -1;
    }
    if (inet_pton(AF_INET6, "ff02::1:3", &membership.ipv6mr_multiaddr) != 1) {
        errno = EINVAL;
        return -1;
    }
    membership.ipv6mr_interface = (unsigned)ifindex;
    return setsockopt(fd, IPPROTO_IPV6,
                      join ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP,
                      &membership, sizeof(membership));
}

int llmnr_join_v4(int fd, int ifindex) {
    return llmnr_membership_v4(fd, ifindex, 1);
}

int llmnr_join_v6(int fd, int ifindex) {
    return llmnr_membership_v6(fd, ifindex, 1);
}

int llmnr_leave_v4(int fd, int ifindex) {
    return llmnr_membership_v4(fd, ifindex, 0);
}

int llmnr_leave_v6(int fd, int ifindex) {
    return llmnr_membership_v6(fd, ifindex, 0);
}

int llmnr_set_out_if_v4(int fd, int ifindex) {
    if (fd < 0 || ifindex <= 0) {
        errno = EINVAL;
        return -1;
    }
    return setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF,
                      &(struct ip_mreqn){ .imr_ifindex = ifindex },
                      sizeof(struct ip_mreqn));
}
