// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef RUSTD_RESOLVED_MDNS_H
#define RUSTD_RESOLVED_MDNS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rustd_resolved_mdns_interface {
    int32_t family;
    uint32_t ifindex;
    uint8_t address[16];
    uint32_t scope_id;
    uint32_t flags;
};

struct rustd_resolved_mdns_meta {
    int32_t family;
    uint16_t port;
    uint16_t reserved;
    uint8_t source[16];
    uint8_t destination[16];
    uint32_t ifindex;
    uint32_t hop_limit;
};

ssize_t rustd_resolved_mdns_interfaces(struct rustd_resolved_mdns_interface *output,
                                    size_t capacity);

int rustd_resolved_mdns_open(int family, uint32_t ifindex, uint16_t port);

ssize_t rustd_resolved_mdns_recv(int fd, void *buffer, size_t capacity,
                              struct rustd_resolved_mdns_meta *metadata);

#ifdef __cplusplus
}
#endif

#endif
