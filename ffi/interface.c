/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "native.h"

#include <errno.h>
#include <limits.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* IFLA_ALT_IFNAME is Linux rtnetlink attribute 53.  Keep the UAPI number
 * local so builds do not depend on the age of the installed kernel headers. */
#define RESOLVED_IFLA_ALT_IFNAME 53U

static int alternative_ifindex(const char *name) {
    size_t name_length = strlen(name) + 1U;
    if (name_length > 256U) {
        return 0;
    }

    int descriptor = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (descriptor < 0) {
        return 0;
    }
    const struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
    if (setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0 ||
        setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) < 0) {
        close(descriptor);
        return 0;
    }

    struct {
        struct nlmsghdr header;
        struct ifinfomsg link;
        uint8_t attribute[RTA_SPACE(256)];
    } request;
    memset(&request, 0, sizeof request);
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof request.link);
    request.header.nlmsg_type = RTM_GETLINK;
    request.header.nlmsg_flags = NLM_F_REQUEST;
    request.header.nlmsg_seq = 1;
    request.link.ifi_family = AF_UNSPEC;
    struct rtattr *attribute = (struct rtattr *)(void *)
        ((uint8_t *)&request + NLMSG_ALIGN(request.header.nlmsg_len));
    attribute->rta_type = RESOLVED_IFLA_ALT_IFNAME;
    attribute->rta_len = RTA_LENGTH(name_length);
    memcpy(RTA_DATA(attribute), name, name_length);
    request.header.nlmsg_len = NLMSG_ALIGN(request.header.nlmsg_len) + attribute->rta_len;

    const struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
    ssize_t sent = sendto(descriptor, &request, request.header.nlmsg_len, MSG_NOSIGNAL,
                          (const struct sockaddr *)(const void *)&kernel, sizeof kernel);
    if (sent != (ssize_t)request.header.nlmsg_len) {
        close(descriptor);
        return 0;
    }

    int result = 0;
    uint8_t reply[8192];
    for (;;) {
        ssize_t received = recv(descriptor, reply, sizeof reply, 0);
        if (received <= 0) {
            break;
        }
        int remaining = (int)received;
        for (struct nlmsghdr *message = (struct nlmsghdr *)(void *)reply;
             NLMSG_OK(message, (unsigned int)remaining);
             message = NLMSG_NEXT(message, remaining)) {
            if (message->nlmsg_seq != request.header.nlmsg_seq) {
                continue;
            }
            if (message->nlmsg_type == NLMSG_ERROR || message->nlmsg_type == NLMSG_DONE) {
                goto finish;
            }
            if (message->nlmsg_type != RTM_NEWLINK ||
                message->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg))) {
                continue;
            }
            const struct ifinfomsg *link = NLMSG_DATA(message);
            if (link->ifi_index > 0) {
                result = link->ifi_index;
            }
            goto finish;
        }
    }

finish:
    close(descriptor);
    return result;
}

int resolved_ifindex_from_name(const char *name) {
    unsigned int ifindex;

    if (name == NULL || name[0] == '\0') {
        return -EINVAL;
    }

    errno = 0;
    ifindex = if_nametoindex(name);
    if (ifindex > 0U) {
        if (ifindex > (unsigned int)INT32_MAX) {
            return -EOVERFLOW;
        }
        return (int)ifindex;
    }

    int alternative = alternative_ifindex(name);
    if (alternative > 0) {
        return alternative;
    }

    errno = 0;
    char *end = NULL;
    long number = strtol(name, &end, 10);
    if (errno == 0 && end != name && *end == '\0' && number > 0 && number <= INT32_MAX) {
        char ifname[IF_NAMESIZE];
        if (if_indextoname((unsigned int)number, ifname) != NULL) {
            return (int)number;
        }
    }
    return -ENODEV;
}

int resolved_ifname_from_index(int ifindex, char *name_buffer) {
    if (ifindex <= 0 || name_buffer == NULL) {
        return -EINVAL;
    }
    if (if_indextoname((unsigned int)ifindex, name_buffer) != NULL) {
        return 0;
    }
    return -ENODEV;
}
