/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include "native.h"
#include "mdns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define RESOLVED_MDNS_PORT 5353U
#define RESOLVED_MDNS_CONTROL_SIZE 256U
#define RESOLVED_NETLINK_BUFFER_SIZE 65536U

_Static_assert(sizeof(resolved_mdns_packet_info) == 48, "unexpected mDNS packet ABI layout");
_Static_assert(sizeof(resolved_address_info) == 32, "unexpected address ABI layout");

static int family_from_abi(int family) {
    if (family == 4 || family == AF_INET) {
        return AF_INET;
    }
    if (family == 6 || family == AF_INET6) {
        return AF_INET6;
    }
    return -EAFNOSUPPORT;
}

static int set_socket_integer(int fd, int level, int option, int value) {
    if (setsockopt(fd, level, option, &value, sizeof(value)) < 0) {
        return -errno;
    }
    return 0;
}

int resolved_mdns_open(int family, uint16_t port) {
    const int address_family = family_from_abi(family);
    struct timeval timeout = { .tv_sec = 0, .tv_usec = 50000 };
    int fd;
    int one = 1;

    if (address_family < 0) {
        return address_family;
    }

    fd = socket(address_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -errno;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        const int error = errno;
        (void)close(fd);
        return -error;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        const int error = errno;
        (void)close(fd);
        return -error;
    }

    if (address_family == AF_INET) {
        struct sockaddr_in address;
        unsigned char ttl = 255;
        unsigned char loop = 1;
#ifdef IP_MULTICAST_ALL
        int multicast_all = 0;
#endif

        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        address.sin_addr.s_addr = htonl(INADDR_ANY);

        if (set_socket_integer(fd, IPPROTO_IP, IP_PKTINFO, one) < 0 ||
            set_socket_integer(fd, IPPROTO_IP, IP_RECVTTL, one) < 0 ||
            set_socket_integer(fd, IPPROTO_IP, IP_TTL, 255) < 0 ||
#ifdef IP_MULTICAST_ALL
            set_socket_integer(fd, IPPROTO_IP, IP_MULTICAST_ALL, multicast_all) < 0 ||
#endif
            setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0 ||
            setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0 ||
            bind(fd, (const struct sockaddr *)&address, sizeof(address)) < 0) {
            const int error = errno;
            (void)close(fd);
            return -error;
        }
    } else {
        struct sockaddr_in6 address;
        int hops = 255;
#ifdef IPV6_MULTICAST_ALL
        int multicast_all = 0;
#endif

        memset(&address, 0, sizeof(address));
        address.sin6_family = AF_INET6;
        address.sin6_port = htons(port);
        address.sin6_addr = in6addr_any;

        if (set_socket_integer(fd, IPPROTO_IPV6, IPV6_V6ONLY, one) < 0 ||
            set_socket_integer(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, one) < 0 ||
            set_socket_integer(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, one) < 0 ||
            set_socket_integer(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, hops) < 0 ||
#ifdef IPV6_MULTICAST_ALL
            set_socket_integer(fd, IPPROTO_IPV6, IPV6_MULTICAST_ALL, multicast_all) < 0 ||
#endif
            set_socket_integer(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, hops) < 0 ||
            set_socket_integer(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, one) < 0 ||
            bind(fd, (const struct sockaddr *)&address, sizeof(address)) < 0) {
            const int error = errno;
            (void)close(fd);
            return -error;
        }
    }

    return fd;
}

int resolved_mdns_join(int fd, int family, int ifindex, int join) {
    const int address_family = family_from_abi(family);
    int option;

    if (fd < 0) {
        return -EBADF;
    }
    if (address_family < 0) {
        return address_family;
    }
    if (ifindex <= 0) {
        return -EINVAL;
    }

    if (address_family == AF_INET) {
        struct ip_mreqn membership;

        memset(&membership, 0, sizeof(membership));
        if (inet_pton(AF_INET, "224.0.0.251", &membership.imr_multiaddr) != 1) {
            return -EINVAL;
        }
        membership.imr_ifindex = ifindex;
        option = join != 0 ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP;
        if (setsockopt(fd, IPPROTO_IP, option, &membership, sizeof(membership)) < 0) {
            if ((join != 0 && errno == EADDRINUSE) ||
                (join == 0 && (errno == EADDRNOTAVAIL || errno == ENOENT))) {
                return 0;
            }
            return -errno;
        }
        if (join != 0 &&
            setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &membership, sizeof(membership)) < 0) {
            return -errno;
        }
    } else {
        struct ipv6_mreq membership;
        unsigned int interface_index = (unsigned int)ifindex;

        memset(&membership, 0, sizeof(membership));
        if (inet_pton(AF_INET6, "ff02::fb", &membership.ipv6mr_multiaddr) != 1) {
            return -EINVAL;
        }
        membership.ipv6mr_interface = interface_index;
        option = join != 0 ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP;
        if (setsockopt(fd, IPPROTO_IPV6, option, &membership, sizeof(membership)) < 0) {
            if ((join != 0 && errno == EADDRINUSE) ||
                (join == 0 && (errno == EADDRNOTAVAIL || errno == ENOENT))) {
                return 0;
            }
            return -errno;
        }
        if (join != 0 &&
            setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                       &interface_index, sizeof(interface_index)) < 0) {
            return -errno;
        }
    }

    return 0;
}

static bool ipv4_multicast(const uint8_t address[16]) {
    uint32_t value;

    memcpy(&value, address, sizeof(value));
    return IN_MULTICAST(ntohl(value));
}

static bool ipv6_multicast(const uint8_t address[16]) {
    struct in6_addr value;

    memcpy(&value, address, sizeof(value));
    return IN6_IS_ADDR_MULTICAST(&value);
}

int64_t resolved_mdns_recv(
    int fd,
    void *buffer,
    size_t capacity,
    resolved_mdns_packet_info *packet_info
) {
    struct sockaddr_storage source;
    struct iovec iov;
    struct msghdr message;
    unsigned char control[RESOLVED_MDNS_CONTROL_SIZE];
    struct cmsghdr *cmsg;
    ssize_t length;
    bool found_destination = false;
    bool found_hop_limit = false;

    if (fd < 0 || buffer == NULL || capacity == 0 || packet_info == NULL) {
        return -EINVAL;
    }

    memset(&source, 0, sizeof(source));
    memset(&message, 0, sizeof(message));
    memset(packet_info, 0, sizeof(*packet_info));
    packet_info->hop_limit = -1;

    iov.iov_base = buffer;
    iov.iov_len = capacity;
    message.msg_name = &source;
    message.msg_namelen = sizeof(source);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);

    do {
        length = recvmsg(fd, &message, 0);
    } while (length < 0 && errno == EINTR);
    if (length < 0) {
        return -errno;
    }
    if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0) {
        return -EMSGSIZE;
    }

    if (source.ss_family == AF_INET) {
        const struct sockaddr_in *address = (const struct sockaddr_in *)&source;

        packet_info->family = 4;
        packet_info->source_port = ntohs(address->sin_port);
        memcpy(packet_info->source, &address->sin_addr, sizeof(address->sin_addr));
    } else if (source.ss_family == AF_INET6) {
        const struct sockaddr_in6 *address = (const struct sockaddr_in6 *)&source;

        packet_info->family = 6;
        packet_info->source_port = ntohs(address->sin6_port);
        packet_info->scope_id = address->sin6_scope_id;
        memcpy(packet_info->source, &address->sin6_addr, sizeof(address->sin6_addr));
    } else {
        return -EAFNOSUPPORT;
    }

    for (cmsg = CMSG_FIRSTHDR(&message); cmsg != NULL; cmsg = CMSG_NXTHDR(&message, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO &&
            cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in_pktinfo))) {
            const struct in_pktinfo *info = (const struct in_pktinfo *)CMSG_DATA(cmsg);

            packet_info->ifindex = info->ipi_ifindex;
            memcpy(packet_info->destination, &info->ipi_addr, sizeof(info->ipi_addr));
            found_destination = true;
        } else if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL &&
                   cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
            memcpy(&packet_info->hop_limit, CMSG_DATA(cmsg), sizeof(int));
            found_hop_limit = true;
        } else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO &&
                   cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo))) {
            const struct in6_pktinfo *info = (const struct in6_pktinfo *)CMSG_DATA(cmsg);

            packet_info->ifindex = (int32_t)info->ipi6_ifindex;
            memcpy(packet_info->destination, &info->ipi6_addr, sizeof(info->ipi6_addr));
            found_destination = true;
        } else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT &&
                   cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
            memcpy(&packet_info->hop_limit, CMSG_DATA(cmsg), sizeof(int));
            found_hop_limit = true;
        }
    }

    if (packet_info->ifindex <= 0 || !found_destination || !found_hop_limit) {
        return -ENODATA;
    }
    packet_info->destination_multicast =
        packet_info->family == 4 ? ipv4_multicast(packet_info->destination)
                                 : ipv6_multicast(packet_info->destination);
    return (int64_t)length;
}

int64_t resolved_mdns_send(
    int fd,
    const void *buffer,
    size_t length,
    int family,
    int ifindex,
    const uint8_t destination[16],
    uint16_t port,
    uint32_t scope_id
) {
    const int address_family = family_from_abi(family);
    struct sockaddr_storage target;
    struct iovec iov;
    struct msghdr message;
    unsigned char control[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    struct cmsghdr *cmsg;
    ssize_t sent;

    if (fd < 0 || buffer == NULL || length == 0 || destination == NULL) {
        return -EINVAL;
    }
    if (address_family < 0) {
        return address_family;
    }
    if (ifindex < 0) {
        return -EINVAL;
    }
    if (port == 0) {
        port = RESOLVED_MDNS_PORT;
    }

    memset(&target, 0, sizeof(target));
    memset(&message, 0, sizeof(message));
    memset(control, 0, sizeof(control));

    if (address_family == AF_INET) {
        struct sockaddr_in *address = (struct sockaddr_in *)&target;

        address->sin_family = AF_INET;
        address->sin_port = htons(port);
        memcpy(&address->sin_addr, destination, sizeof(address->sin_addr));
        message.msg_namelen = sizeof(*address);
    } else {
        struct sockaddr_in6 *address = (struct sockaddr_in6 *)&target;

        address->sin6_family = AF_INET6;
        address->sin6_port = htons(port);
        address->sin6_scope_id = scope_id != 0 ? scope_id : (uint32_t)ifindex;
        memcpy(&address->sin6_addr, destination, sizeof(address->sin6_addr));
        message.msg_namelen = sizeof(*address);
    }

    iov.iov_base = (void *)buffer;
    iov.iov_len = length;
    message.msg_name = &target;
    message.msg_iov = &iov;
    message.msg_iovlen = 1;

    if (ifindex > 0) {
        message.msg_control = control;
        if (address_family == AF_INET) {
            struct in_pktinfo *info;

            message.msg_controllen = CMSG_SPACE(sizeof(*info));
            cmsg = CMSG_FIRSTHDR(&message);
            cmsg->cmsg_level = IPPROTO_IP;
            cmsg->cmsg_type = IP_PKTINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof(*info));
            info = (struct in_pktinfo *)CMSG_DATA(cmsg);
            memset(info, 0, sizeof(*info));
            info->ipi_ifindex = ifindex;
        } else {
            struct in6_pktinfo *info;

            message.msg_controllen = CMSG_SPACE(sizeof(*info));
            cmsg = CMSG_FIRSTHDR(&message);
            cmsg->cmsg_level = IPPROTO_IPV6;
            cmsg->cmsg_type = IPV6_PKTINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof(*info));
            info = (struct in6_pktinfo *)CMSG_DATA(cmsg);
            memset(info, 0, sizeof(*info));
            info->ipi6_ifindex = (unsigned int)ifindex;
        }
    }

    do {
        sent = sendmsg(fd, &message, MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent < 0) {
        return -errno;
    }
    return (int64_t)sent;
}

static int address_dump_socket(void) {
    struct sockaddr_nl local;
    int fd;

    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        return -errno;
    }
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    if (bind(fd, (const struct sockaddr *)&local, sizeof(local)) < 0) {
        const int error = errno;
        (void)close(fd);
        return -error;
    }
    return fd;
}

static int send_address_dump_request(int fd, uint32_t sequence) {
    struct {
        struct nlmsghdr header;
        struct ifaddrmsg address;
    } request;
    struct sockaddr_nl kernel;

    memset(&request, 0, sizeof(request));
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(request.address));
    request.header.nlmsg_type = RTM_GETADDR;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = sequence;
    request.address.ifa_family = AF_UNSPEC;

    memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;
    if (sendto(fd, &request, request.header.nlmsg_len, 0,
               (const struct sockaddr *)&kernel, sizeof(kernel)) < 0) {
        return -errno;
    }
    return 0;
}

static bool parse_address_message(
    const struct nlmsghdr *header,
    resolved_address_info *output
) {
    const struct ifaddrmsg *address = (const struct ifaddrmsg *)NLMSG_DATA(header);
    int attribute_length = IFA_PAYLOAD(header);
    const struct rtattr *attribute;
    const void *primary = NULL;
    const void *fallback = NULL;
    uint32_t flags = address->ifa_flags;
    size_t address_length;

    if (address->ifa_family == AF_INET) {
        address_length = 4;
    } else if (address->ifa_family == AF_INET6) {
        address_length = 16;
    } else {
        return false;
    }

    for (attribute = IFA_RTA(address); RTA_OK(attribute, attribute_length);
         attribute = RTA_NEXT(attribute, attribute_length)) {
        if (attribute->rta_type == IFA_LOCAL && RTA_PAYLOAD(attribute) >= address_length) {
            primary = RTA_DATA(attribute);
        } else if (attribute->rta_type == IFA_ADDRESS && RTA_PAYLOAD(attribute) >= address_length) {
            fallback = RTA_DATA(attribute);
        } else if (attribute->rta_type == IFA_FLAGS &&
                   RTA_PAYLOAD(attribute) >= sizeof(uint32_t)) {
            memcpy(&flags, RTA_DATA(attribute), sizeof(flags));
        }
    }
    if (primary == NULL) {
        primary = fallback;
    }
    if (primary == NULL || address->ifa_index == 0U) {
        return false;
    }

    memset(output, 0, sizeof(*output));
    output->ifindex = (int32_t)address->ifa_index;
    output->flags = flags;
    output->family = address->ifa_family == AF_INET ? 4 : 6;
    output->prefix_length = address->ifa_prefixlen;
    output->scope = address->ifa_scope;
    output->scope_id = output->family == 6 ? address->ifa_index : 0U;
    memcpy(output->address, primary, address_length);
    return true;
}

int64_t resolved_address_snapshot(resolved_address_info *entries, size_t capacity) {
    const uint32_t sequence = 0x52534d44U;
    unsigned char buffer[RESOLVED_NETLINK_BUFFER_SIZE];
    size_t count = 0;
    int fd;
    int request_result;
    bool complete = false;

    if (entries == NULL && capacity != 0) {
        return -EINVAL;
    }

    fd = address_dump_socket();
    if (fd < 0) {
        return fd;
    }
    request_result = send_address_dump_request(fd, sequence);
    if (request_result < 0) {
        (void)close(fd);
        return request_result;
    }

    while (!complete) {
        ssize_t length;
        struct nlmsghdr *header;
        int remaining;

        do {
            length = recv(fd, buffer, sizeof(buffer), 0);
        } while (length < 0 && errno == EINTR);
        if (length < 0) {
            const int error = errno;
            (void)close(fd);
            return -error;
        }
        if (length == 0) {
            (void)close(fd);
            return -EIO;
        }

        remaining = (int)length;
        for (header = (struct nlmsghdr *)buffer;
             NLMSG_OK(header, (unsigned int)remaining);
             header = NLMSG_NEXT(header, remaining)) {
            if (header->nlmsg_seq != sequence) {
                continue;
            }
            if (header->nlmsg_type == NLMSG_DONE) {
                complete = true;
                break;
            }
            if (header->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *error = (const struct nlmsgerr *)NLMSG_DATA(header);
                const int result = error->error;
                (void)close(fd);
                return result == 0 ? (int64_t)count : result;
            }
            if (header->nlmsg_type == RTM_NEWADDR) {
                resolved_address_info parsed;

                if (!parse_address_message(header, &parsed)) {
                    continue;
                }
                if (entries != NULL && count < capacity) {
                    entries[count] = parsed;
                }
                count++;
            }
        }
    }

    (void)close(fd);
    return (int64_t)count;
}

static int legacy_error(int result) {
    errno = result < 0 ? -result : EIO;
    return -1;
}

ssize_t rustd_resolved_mdns_interfaces(
    struct rustd_resolved_mdns_interface *output,
    size_t capacity
) {
    resolved_address_info *addresses = NULL;
    int64_t count;
    size_t written = 0;

    if (output == NULL && capacity != 0) {
        errno = EINVAL;
        return -1;
    }
    count = resolved_address_snapshot(NULL, 0);
    if (count < 0) {
        return legacy_error((int)count);
    }
    if (count == 0 || output == NULL) {
        return (ssize_t)count;
    }
    addresses = calloc((size_t)count, sizeof(*addresses));
    if (addresses == NULL) {
        errno = ENOMEM;
        return -1;
    }
    count = resolved_address_snapshot(addresses, (size_t)count);
    if (count < 0) {
        const int error = (int)count;
        free(addresses);
        return legacy_error(error);
    }
    for (size_t index = 0; index < (size_t)count && written < capacity; index++) {
        const resolved_address_info *source = &addresses[index];
        struct rustd_resolved_mdns_interface *destination = &output[written];

        if (source->ifindex <= 0 || (source->family != 4 && source->family != 6)) {
            continue;
        }
        memset(destination, 0, sizeof(*destination));
        destination->family = source->family == 4 ? AF_INET : AF_INET6;
        destination->ifindex = (uint32_t)source->ifindex;
        destination->scope_id = source->scope_id;
        destination->flags = source->flags;
        memcpy(destination->address, source->address, source->family == 4 ? 4U : 16U);
        written++;
    }
    free(addresses);
    return (ssize_t)written;
}

int rustd_resolved_mdns_open(int family, uint32_t ifindex, uint16_t port) {
    int fd;
    int result;

    if ((family != AF_INET && family != AF_INET6) || ifindex == 0U ||
        ifindex > (uint32_t)INT32_MAX || port == 0U) {
        errno = family != AF_INET && family != AF_INET6 ? EAFNOSUPPORT : EINVAL;
        return -1;
    }
    fd = resolved_mdns_open(family, port);
    if (fd < 0) {
        return legacy_error(fd);
    }
    result = resolved_mdns_join(fd, family, (int)ifindex, 1);
    if (result < 0) {
        (void)close(fd);
        return legacy_error(result);
    }
    return fd;
}

ssize_t rustd_resolved_mdns_recv(
    int fd,
    void *buffer,
    size_t capacity,
    struct rustd_resolved_mdns_meta *metadata
) {
    resolved_mdns_packet_info packet_info;
    int64_t length;

    if (fd < 0 || buffer == NULL || capacity == 0 || metadata == NULL) {
        errno = EINVAL;
        return -1;
    }
    length = resolved_mdns_recv(fd, buffer, capacity, &packet_info);
    if (length < 0) {
        return legacy_error((int)length);
    }
    memset(metadata, 0, sizeof(*metadata));
    metadata->family = packet_info.family == 4 ? AF_INET : AF_INET6;
    metadata->port = packet_info.source_port;
    memcpy(metadata->source, packet_info.source, packet_info.family == 4 ? 4U : 16U);
    memcpy(
        metadata->destination,
        packet_info.destination,
        packet_info.family == 4 ? 4U : 16U
    );
    metadata->ifindex = (uint32_t)packet_info.ifindex;
    metadata->hop_limit = packet_info.hop_limit < 0 ? 0U : (uint32_t)packet_info.hop_limit;
    return (ssize_t)length;
}
