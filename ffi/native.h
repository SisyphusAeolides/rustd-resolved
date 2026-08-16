/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef RESOLVED_NATIVE_H
#define RESOLVED_NATIVE_H

#include <stddef.h>
#include <stdint.h>

#define RESOLVED_IFNAME_MAX 16

typedef struct resolved_link_info {
    int32_t ifindex;
    uint32_t flags;
    uint32_t mtu;
    uint8_t operstate;
    uint8_t has_ipv4_global;
    uint8_t has_ipv4_link_local;
    uint8_t has_ipv6_global;
    uint8_t has_ipv6_link_local;
    char ifname[RESOLVED_IFNAME_MAX];
} resolved_link_info;

typedef struct resolved_mdns_packet_info {
    int32_t ifindex;
    uint16_t source_port;
    uint8_t family;
    uint8_t destination_multicast;
    int32_t hop_limit;
    uint32_t scope_id;
    uint8_t source[16];
    uint8_t destination[16];
} resolved_mdns_packet_info;

typedef struct resolved_address_info {
    int32_t ifindex;
    uint32_t flags;
    uint8_t family;
    uint8_t prefix_length;
    uint8_t scope;
    uint8_t _pad;
    uint32_t scope_id;
    uint8_t address[16];
} resolved_address_info;

typedef struct resolved_tls_stream resolved_tls_stream;

int resolved_notify(const char *state);
int resolved_monotonic_usec(uint64_t *result);
int resolved_listen_fds(void);
int resolved_socket_accepting(int fd);
int resolved_socket_disconnected(int fd);
int resolved_install_signal_handlers(void);
int resolved_take_reload(void);
int resolved_should_stop(void);
uint32_t resolved_uid(void);
char **resolved_environment(void);
uint64_t resolved_environment_max_length(void);
int resolved_peer_credentials(int fd, uint32_t *pid, uint32_t *uid, uint32_t *gid);
int resolved_pidfd_open(uint32_t pid);
int resolved_ifindex_from_name(const char *name);
int resolved_drop_privileges(const char *user, const char *runtime_directory);
int64_t resolved_kernel_hostname(char *buffer, size_t capacity);

int resolved_mdns_open(int family, uint16_t port);
int resolved_mdns_join(int fd, int family, int ifindex, int join);
int64_t resolved_mdns_recv(
    int fd,
    void *buffer,
    size_t capacity,
    resolved_mdns_packet_info *packet_info
);
int64_t resolved_mdns_send(
    int fd,
    const void *buffer,
    size_t length,
    int family,
    int ifindex,
    const uint8_t destination[16],
    uint16_t port,
    uint32_t scope_id
);
int64_t resolved_address_snapshot(resolved_address_info *entries, size_t capacity);

int resolved_udp_connect(
    const char *address,
    uint16_t port,
    uint32_t scope_id,
    int ifindex,
    uint32_t firewall_mark
);
int resolved_tcp_connect(
    const char *address,
    uint16_t port,
    uint32_t scope_id,
    int ifindex,
    uint32_t firewall_mark,
    uint32_t timeout_msec
);
int resolved_udp_path_mtu(int fd, int ipv6);
int resolved_udp_enable_recvfragsize(int fd, int ipv6);
int64_t resolved_udp_recv(int fd, void *buffer, size_t capacity, uint32_t *fragment_size);
uint16_t resolved_dns_udp_payload_size(
    uint32_t path_mtu,
    int ipv6,
    int loopback,
    int fragmented,
    uint32_t received_udp_fragment_max
);

int resolved_tls_connect(
    const char *address,
    uint16_t port,
    uint32_t scope_id,
    int ifindex,
    uint32_t firewall_mark,
    const char *server_name,
    int strict,
    uint32_t timeout_msec,
    resolved_tls_stream **ret
);
int resolved_tls_set_timeout(resolved_tls_stream *stream, uint32_t timeout_msec);
int64_t resolved_tls_read(resolved_tls_stream *stream, void *buffer, size_t capacity);
int64_t resolved_tls_write(resolved_tls_stream *stream, const void *buffer, size_t length);
void resolved_tls_free(resolved_tls_stream *stream);

int resolved_dnssec_digest(
    uint8_t digest_type,
    const void *data,
    size_t length,
    uint8_t *output,
    size_t capacity
);
int resolved_dnssec_verify(
    uint8_t algorithm,
    const uint8_t *key,
    size_t key_length,
    const uint8_t *data,
    size_t data_length,
    const uint8_t *signature,
    size_t signature_length
);

int64_t resolved_link_snapshot(resolved_link_info *entries, size_t capacity);
int resolved_rtnl_open(void);
int resolved_rtnl_wait(int fd, uint32_t timeout_msec);

int resolved_networkd_open(void);
int resolved_networkd_wait(int fd, uint32_t timeout_msec);

int64_t resolved_route_score(
    const char *name,
    size_t name_len,
    const char *domain,
    size_t domain_len,
    int route_only,
    int default_route,
    int ifindex
);

#endif
