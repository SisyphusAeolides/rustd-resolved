/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include "native.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <limits.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

_Static_assert(IF_NAMESIZE == RESOLVED_IFNAME_MAX, "interface name ABI size mismatch");

static int find_snapshot(resolved_link_info *entries, size_t length, unsigned int ifindex) {
    size_t index;

    for (index = 0; index < length; index++) {
        if ((unsigned int)entries[index].ifindex == ifindex) {
            return (int)index;
        }
    }
    return -1;
}

static bool ipv4_is_link_local(const struct in_addr *address) {
    const uint32_t value = ntohl(address->s_addr);
    return (value & 0xffff0000U) == 0xa9fe0000U;
}

static bool ipv4_is_usable_global(const struct in_addr *address) {
    const uint32_t value = ntohl(address->s_addr);
    if (value == 0U || (value >> 24U) == 127U || (value & 0xf0000000U) == 0xe0000000U) {
        return false;
    }
    return !ipv4_is_link_local(address);
}

static void collect_addresses(resolved_link_info *entries, size_t length) {
    struct ifaddrs *addresses = NULL;
    struct ifaddrs *entry;

    if (entries == NULL || length == 0 || getifaddrs(&addresses) < 0) {
        return;
    }

    for (entry = addresses; entry != NULL; entry = entry->ifa_next) {
        unsigned int ifindex;
        int index;

        if (entry->ifa_addr == NULL || entry->ifa_name == NULL) {
            continue;
        }
        ifindex = if_nametoindex(entry->ifa_name);
        if (ifindex == 0U) {
            continue;
        }
        index = find_snapshot(entries, length, ifindex);
        if (index < 0) {
            continue;
        }

        if (entry->ifa_addr->sa_family == AF_INET) {
            const struct sockaddr_in *address = (const struct sockaddr_in *)entry->ifa_addr;
            if (ipv4_is_link_local(&address->sin_addr)) {
                entries[index].has_ipv4_link_local = 1;
            } else if (ipv4_is_usable_global(&address->sin_addr)) {
                entries[index].has_ipv4_global = 1;
            }
        } else if (entry->ifa_addr->sa_family == AF_INET6) {
            const struct sockaddr_in6 *address = (const struct sockaddr_in6 *)entry->ifa_addr;
            if (IN6_IS_ADDR_LINKLOCAL(&address->sin6_addr)) {
                entries[index].has_ipv6_link_local = 1;
            } else if (!IN6_IS_ADDR_UNSPECIFIED(&address->sin6_addr) &&
                       !IN6_IS_ADDR_LOOPBACK(&address->sin6_addr) &&
                       !IN6_IS_ADDR_MULTICAST(&address->sin6_addr)) {
                entries[index].has_ipv6_global = 1;
            }
        }
    }

    freeifaddrs(addresses);
}

static int request_link_dump(int fd) {
    struct {
        struct nlmsghdr header;
        struct ifinfomsg link;
    } request;
    struct sockaddr_nl kernel;
    ssize_t sent;

    memset(&request, 0, sizeof(request));
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(request.link));
    request.header.nlmsg_type = RTM_GETLINK;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = 1;
    request.link.ifi_family = AF_UNSPEC;
    memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;

    sent = sendto(fd,
                  &request,
                  request.header.nlmsg_len,
                  0,
                  (const struct sockaddr *)&kernel,
                  sizeof(kernel));
    if (sent < 0) {
        return -errno;
    }
    if ((size_t)sent != request.header.nlmsg_len) {
        return -EIO;
    }
    return 0;
}

static int parse_link_message(const struct nlmsghdr *message, resolved_link_info *entry) {
    const struct ifinfomsg *link;
    const struct rtattr *attribute;
    int remaining;
    bool have_name = false;

    if (message->nlmsg_len < NLMSG_LENGTH(sizeof(*link))) {
        return -EBADMSG;
    }
    link = NLMSG_DATA(message);
    if (entry != NULL) {
        memset(entry, 0, sizeof(*entry));
        entry->ifindex = link->ifi_index;
        entry->flags = link->ifi_flags;
    }

    remaining = IFLA_PAYLOAD(message);
    for (attribute = IFLA_RTA(link);
         RTA_OK(attribute, remaining);
         attribute = RTA_NEXT(attribute, remaining)) {
        switch (attribute->rta_type) {
        case IFLA_IFNAME:
            if (RTA_PAYLOAD(attribute) == 0 ||
                memchr(RTA_DATA(attribute), '\0', RTA_PAYLOAD(attribute)) == NULL) {
                return -EBADMSG;
            }
            have_name = true;
            if (entry != NULL) {
                (void)snprintf(
                    entry->ifname,
                    sizeof(entry->ifname),
                    "%s",
                    (const char *)RTA_DATA(attribute));
            }
            break;
        case IFLA_MTU:
            if (entry != NULL && RTA_PAYLOAD(attribute) >= sizeof(entry->mtu)) {
                memcpy(&entry->mtu, RTA_DATA(attribute), sizeof(entry->mtu));
            }
            break;
        case IFLA_OPERSTATE:
            if (entry != NULL && RTA_PAYLOAD(attribute) >= sizeof(entry->operstate)) {
                memcpy(&entry->operstate, RTA_DATA(attribute), sizeof(entry->operstate));
            }
            break;
        default:
            break;
        }
    }
    if (remaining != 0) {
        return -EBADMSG;
    }
    return have_name ? 1 : 0;
}

int64_t resolved_link_snapshot(resolved_link_info *entries, size_t capacity) {
    struct sockaddr_nl local;
    char buffer[64 * 1024];
    size_t count = 0;
    size_t filled = 0;
    int fd;
    int result;

    if (entries == NULL && capacity != 0) {
        return -EINVAL;
    }
    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        return -errno;
    }
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    if (bind(fd, (const struct sockaddr *)&local, sizeof(local)) < 0) {
        result = -errno;
        (void)close(fd);
        return result;
    }
    result = request_link_dump(fd);
    if (result < 0) {
        (void)close(fd);
        return result;
    }
    if (entries != NULL && capacity > 0) {
        memset(entries, 0, capacity * sizeof(*entries));
    }

    for (;;) {
        ssize_t length;
        struct nlmsghdr *message;
        int remaining;

        do {
            length = recv(fd, buffer, sizeof(buffer), 0);
        } while (length < 0 && errno == EINTR);
        if (length < 0) {
            result = -errno;
            break;
        }
        if (length == 0) {
            result = -EIO;
            break;
        }
        remaining = (int)length;
        for (message = (struct nlmsghdr *)buffer;
             NLMSG_OK(message, (unsigned int)remaining);
             message = NLMSG_NEXT(message, remaining)) {
            if (message->nlmsg_seq != 1) {
                continue;
            }
            if (message->nlmsg_type == NLMSG_DONE) {
                result = 0;
                goto complete;
            }
            if (message->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *error;
                if (message->nlmsg_len < NLMSG_LENGTH(sizeof(*error))) {
                    result = -EBADMSG;
                } else {
                    error = NLMSG_DATA(message);
                    result = error->error == 0 ? 0 : error->error;
                }
                goto complete;
            }
            if (message->nlmsg_type != RTM_NEWLINK) {
                continue;
            }
            result = parse_link_message(
                message,
                entries != NULL && filled < capacity ? &entries[filled] : NULL);
            if (result < 0) {
                goto complete;
            }
            if (result == 0) {
                continue;
            }
            count++;
            if (entries != NULL && filled < capacity) {
                filled++;
            }
        }
        if (remaining != 0) {
            result = -EBADMSG;
            break;
        }
    }

complete:
    (void)close(fd);
    if (result < 0) {
        return result;
    }
    collect_addresses(entries, filled);
    return (int64_t)count;
}

int resolved_rtnl_open(void) {
    struct sockaddr_nl address;
    int fd;

    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (fd < 0) {
        return -errno;
    }

    memset(&address, 0, sizeof(address));
    address.nl_family = AF_NETLINK;
    address.nl_groups = RTMGRP_LINK |
                        RTMGRP_IPV4_IFADDR |
                        RTMGRP_IPV6_IFADDR |
                        RTMGRP_IPV4_ROUTE |
                        RTMGRP_IPV6_ROUTE;
    if (bind(fd, (const struct sockaddr *)&address, sizeof(address)) < 0) {
        const int error = errno;
        (void)close(fd);
        return -error;
    }
    return fd;
}

int resolved_rtnl_wait(int fd, uint32_t timeout_msec) {
    struct pollfd descriptor;
    char buffer[16384];
    int timeout;
    int result;
    bool changed = false;

    if (fd < 0) {
        return -EBADF;
    }
    timeout = timeout_msec > (uint32_t)INT_MAX ? INT_MAX : (int)timeout_msec;
    descriptor.fd = fd;
    descriptor.events = POLLIN;
    descriptor.revents = 0;

    do {
        result = poll(&descriptor, 1, timeout);
    } while (result < 0 && errno == EINTR);
    if (result < 0) {
        return -errno;
    }
    if (result == 0) {
        return 0;
    }
    if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        return -EIO;
    }

    for (;;) {
        ssize_t length = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);
        if (length > 0) {
            changed = true;
            continue;
        }
        if (length == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        }
        return -errno;
    }
    return changed ? 1 : 0;
}
