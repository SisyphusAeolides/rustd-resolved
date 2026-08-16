#define _GNU_SOURCE
#include "nss_resolve_shm.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>

#define DNS_HEADER_SIZE 12u
#define DNS_MAX_NAME 255u
#define DNS_MAX_PACKET 65535u
#define DNS_TYPE_A 1u
#define DNS_TYPE_CNAME 5u
#define DNS_TYPE_PTR 12u
#define DNS_TYPE_OPT 41u
#define DNS_TYPE_AAAA 28u
#define DNS_CLASS_IN 1u

static _Atomic uint32_t query_counter = 1;

static uint16_t read_u16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static int write_all(int fd, const void *buffer, size_t length)
{
    const uint8_t *p = buffer;
    while (length > 0) {
        ssize_t written = write(fd, p, length);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (written == 0) {
            errno = EPIPE;
            return -1;
        }
        p += (size_t)written;
        length -= (size_t)written;
    }
    return 0;
}

static int read_all(int fd, void *buffer, size_t length)
{
    uint8_t *p = buffer;
    while (length > 0) {
        ssize_t n = read(fd, p, length);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            errno = ECONNRESET;
            return -1;
        }
        p += (size_t)n;
        length -= (size_t)n;
    }
    return 0;
}

static int set_timeouts(int fd)
{
    const struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0)
        return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) < 0)
        return -1;
    return 0;
}

static int parse_port(const char *text, uint16_t *ret)
{
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || value == 0 || value > 65535) {
        errno = EINVAL;
        return -1;
    }
    *ret = (uint16_t)value;
    return 0;
}

static int copy_part(char *out, size_t capacity, const char *start, size_t length)
{
    if (length == 0 || length >= capacity) {
        errno = EINVAL;
        return -1;
    }
    memcpy(out, start, length);
    out[length] = '\0';
    return 0;
}

static int parse_ifindex(const char *ifname, uint32_t *scope_id)
{
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(ifname, &end, 10);
    if (errno != 0 || end == ifname || *end != '\0') {
        unsigned int numeric = if_nametoindex(ifname);
        if (numeric == 0) {
            errno = EINVAL;
            return -1;
        }
        *scope_id = numeric;
        return 0;
    }
    if (value > UINT32_MAX) {
        errno = ERANGE;
        return -1;
    }
    if (value == 0) {
        errno = EINVAL;
        return -1;
    }
    *scope_id = (uint32_t)value;
    return 0;
}

static int stub_endpoint(struct sockaddr_storage *storage, socklen_t *length)
{
    const char *value = secure_getenv("RUSTD_NSS_RESOLVE_STUB");
    char host[100];
    uint16_t port = 53;
    uint32_t scope_id = 0;

    if (!value || !*value)
        value = "127.0.0.53";

    if (value[0] == '[') {
        const char *close = strchr(value + 1, ']');
        if (!close || copy_part(host, sizeof host, value + 1, (size_t)(close - value - 1)) < 0)
            return -1;
        if (close[1] != '\0') {
            if (close[1] != ':' || parse_port(close + 2, &port) < 0)
                return -1;
        }
    } else {
        const char *first_colon = strchr(value, ':');
        const char *last_colon = strrchr(value, ':');
        if (last_colon && first_colon == last_colon) {
            if (copy_part(host, sizeof host, value, (size_t)(last_colon - value)) < 0)
                return -1;
            if (parse_port(last_colon + 1, &port) < 0)
                return -1;
        } else {
            if (copy_part(host, sizeof host, value, strlen(value)) < 0)
                return -1;
        }
    }

    char *percent = strchr(host, '%');
    if (percent) {
        *percent = '\0';
        const char *ifname = percent + 1;
        if (*ifname == '\0' || parse_ifindex(ifname, &scope_id) < 0) {
            return -1;
        }
    }

    memset(storage, 0, sizeof *storage);
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)storage;
    if (inet_pton(AF_INET, host, &ipv4->sin_addr) == 1) {
        if (percent) {
            errno = EINVAL;
            return -1;
        }
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons(port);
        *length = sizeof *ipv4;
        return 0;
    }

    struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)storage;
    if (inet_pton(AF_INET6, host, &ipv6->sin6_addr) == 1) {
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons(port);
        ipv6->sin6_scope_id = scope_id;
        *length = sizeof *ipv6;
        return 0;
    }

    errno = EINVAL;
    return -1;
}

static uint16_t next_query_id(void)
{
    struct timespec now = { 0 };
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    uint32_t counter = atomic_fetch_add_explicit(&query_counter, 1, memory_order_relaxed);
    uint32_t mixed = counter ^ (uint32_t)getpid() ^ (uint32_t)now.tv_nsec ^ (uint32_t)now.tv_sec;
    mixed ^= mixed >> 16;
    uint16_t id = (uint16_t)mixed;
    return id == 0 ? 1 : id;
}

static int build_query(const char *name, uint16_t qtype, uint16_t id,
                       uint8_t *packet, size_t capacity, size_t *length)
{
    if (!name || !packet || !length || capacity < DNS_HEADER_SIZE) {
        errno = EINVAL;
        return -1;
    }

    memset(packet, 0, capacity);
    packet[0] = (uint8_t)(id >> 8);
    packet[1] = (uint8_t)id;
    packet[2] = 0x01; /* RD */
    packet[5] = 1;

    size_t offset = DNS_HEADER_SIZE;
    size_t wire_length = 0;
    if (sr_encode_name(name, packet + offset, capacity - offset, &wire_length) < 0) {
        errno = EINVAL;
        return -1;
    }
    offset += wire_length;
    if (offset + 4 > capacity) {
        errno = EMSGSIZE;
        return -1;
    }
    packet[offset++] = (uint8_t)(qtype >> 8);
    packet[offset++] = (uint8_t)qtype;
    packet[offset++] = 0;
    packet[offset++] = DNS_CLASS_IN;
    *length = offset;
    return 0;
}

static int tcp_query(const struct sockaddr *destination, socklen_t destination_length,
                     const uint8_t *query, size_t query_length,
                     uint8_t *response, size_t response_capacity, size_t *response_length)
{
    int fd = socket(destination->sa_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (set_timeouts(fd) < 0 || connect(fd, destination, destination_length) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    uint8_t frame_length[2] = {
        (uint8_t)(query_length >> 8),
        (uint8_t)query_length,
    };
    if (write_all(fd, frame_length, sizeof frame_length) < 0 ||
        write_all(fd, query, query_length) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    if (read_all(fd, frame_length, sizeof frame_length) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    size_t length = read_u16(frame_length);
    if (length < DNS_HEADER_SIZE || length > response_capacity) {
        close(fd);
        errno = EMSGSIZE;
        return -1;
    }
    if (read_all(fd, response, length) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    close(fd);
    *response_length = length;
    return 0;
}

static int dns_expand_name(const uint8_t *packet, size_t packet_length, size_t *offset,
                           char *out, size_t out_capacity)
{
    if (!packet || !offset || !out || out_capacity < 2 || *offset >= packet_length) {
        errno = EPROTO;
        return -1;
    }

    size_t position = *offset;
    size_t next = position;
    size_t output_length = 0;
    unsigned jumps = 0;
    int jumped = 0;

    for (;;) {
        if (position >= packet_length) {
            errno = EPROTO;
            return -1;
        }
        uint8_t label_length = packet[position];
        if ((label_length & 0xC0u) == 0xC0u) {
            if (position + 1 >= packet_length) {
                errno = EPROTO;
                return -1;
            }
            size_t pointer = ((size_t)(label_length & 0x3Fu) << 8) | packet[position + 1];
            if (pointer >= position || pointer >= packet_length || ++jumps > 128) {
                errno = EPROTO;
                return -1;
            }
            if (!jumped)
                next = position + 2;
            position = pointer;
            jumped = 1;
            continue;
        }
        if ((label_length & 0xC0u) != 0 || label_length > 63) {
            errno = EPROTO;
            return -1;
        }
        position++;
        if (label_length == 0) {
            if (!jumped)
                next = position;
            if (output_length == 0) {
                out[0] = '.';
                output_length = 1;
            }
            out[output_length] = '\0';
            *offset = next;
            return 0;
        }
        if (position + label_length > packet_length) {
            errno = EPROTO;
            return -1;
        }
        size_t additional = label_length + (output_length > 0 ? 1u : 0u);
        if (output_length + additional >= out_capacity || output_length + additional > DNS_MAX_NAME) {
            errno = EMSGSIZE;
            return -1;
        }
        if (output_length > 0)
            out[output_length++] = '.';
        memcpy(out + output_length, packet + position, label_length);
        output_length += label_length;
        position += label_length;
        if (!jumped)
            next = position;
    }
}

static int validate_response(const uint8_t *response, size_t response_length,
                             uint16_t id, const char *name, uint16_t qtype)
{
    if (response_length < DNS_HEADER_SIZE || read_u16(response) != id ||
        (response[2] & 0x80u) == 0 || read_u16(response + 4) != 1) {
        errno = EPROTO;
        return -1;
    }

    size_t offset = DNS_HEADER_SIZE;
    char response_name[DNS_MAX_NAME + 1];
    if (dns_expand_name(response, response_length, &offset, response_name, sizeof response_name) < 0)
        return -1;
    if (offset + 4 > response_length || strcasecmp(response_name, name) != 0 ||
        read_u16(response + offset) != qtype || read_u16(response + offset + 2) != DNS_CLASS_IN) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

static int dns_query(const char *name, uint16_t qtype,
                     uint8_t *response, size_t response_capacity, size_t *response_length)
{
    uint16_t id = next_query_id();
    uint8_t query[512];
    size_t query_length = 0;
    if (build_query(name, qtype, id, query, sizeof query, &query_length) < 0)
        return -1;

    struct sockaddr_storage destination;
    socklen_t destination_length = 0;
    if (stub_endpoint(&destination, &destination_length) < 0)
        return -1;

    int fd = socket(destination.ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (set_timeouts(fd) < 0 || connect(fd, (const struct sockaddr *)&destination, destination_length) < 0 ||
        write_all(fd, query, query_length) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    ssize_t n;
    do {
        n = recv(fd, response, response_capacity, 0);
    } while (n < 0 && errno == EINTR);
    if (n < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    close(fd);
    if ((size_t)n < DNS_HEADER_SIZE) {
        errno = EPROTO;
        return -1;
    }
    *response_length = (size_t)n;

    if (validate_response(response, *response_length, id, name, qtype) < 0)
        return -1;
    if ((response[2] & 0x02u) != 0) {
        if (tcp_query((const struct sockaddr *)&destination, destination_length,
                      query, query_length, response, response_capacity, response_length) < 0)
            return -1;
        if (validate_response(response, *response_length, id, name, qtype) < 0)
            return -1;
    }
    return 0;
}

static int response_rcode(const uint8_t *response, size_t response_length)
{
    if (response_length < DNS_HEADER_SIZE) {
        errno = EPROTO;
        return -1;
    }
    const uint16_t header_rcode = response[3] & 0x0Fu;
    uint16_t full_rcode = header_rcode;
    uint16_t question_count = read_u16(response + 4);
    uint16_t answer_count = read_u16(response + 6);
    uint16_t authority_count = read_u16(response + 8);
    uint16_t additional_count = read_u16(response + 10);
    size_t offset = DNS_HEADER_SIZE;
    size_t sections;

    for (uint16_t q = 0; q < question_count; q++) {
        char ignored[DNS_MAX_NAME + 1];
        if (dns_expand_name(response, response_length, &offset, ignored, sizeof ignored) < 0) {
            errno = EPROTO;
            return -1;
        }
        if (offset + 4 > response_length) {
            errno = EPROTO;
            return -1;
        }
        offset += 4;
    }

    sections = answer_count;
    while (sections--) {
        char ignored[DNS_MAX_NAME + 1];
        if (dns_expand_name(response, response_length, &offset, ignored, sizeof ignored) < 0) {
            errno = EPROTO;
            return -1;
        }
        if (offset + 10 > response_length) {
            errno = EPROTO;
            return -1;
        }
        uint16_t type = read_u16(response + offset);
        uint16_t data_length = read_u16(response + offset + 8);
        offset += 10;
        if (offset + data_length > response_length) {
            errno = EPROTO;
            return -1;
        }
        if (type == DNS_TYPE_OPT) {
            full_rcode = (uint16_t)(response[offset - 6] << 4) | full_rcode;
        }
        offset += data_length;
    }

    sections = authority_count;
    while (sections--) {
        char ignored[DNS_MAX_NAME + 1];
        if (dns_expand_name(response, response_length, &offset, ignored, sizeof ignored) < 0) {
            errno = EPROTO;
            return -1;
        }
        if (offset + 10 > response_length) {
            errno = EPROTO;
            return -1;
        }
        uint16_t type = read_u16(response + offset);
        uint16_t data_length = read_u16(response + offset + 8);
        offset += 10;
        if (offset + data_length > response_length) {
            errno = EPROTO;
            return -1;
        }
        if (type == DNS_TYPE_OPT) {
            full_rcode = (uint16_t)(response[offset - 6] << 4) | header_rcode;
        }
        offset += data_length;
    }

    sections = additional_count;
    while (sections--) {
        char ignored[DNS_MAX_NAME + 1];
        if (dns_expand_name(response, response_length, &offset, ignored, sizeof ignored) < 0) {
            errno = EPROTO;
            return -1;
        }
        if (offset + 10 > response_length) {
            errno = EPROTO;
            return -1;
        }
        uint16_t type = read_u16(response + offset);
        uint16_t data_length = read_u16(response + offset + 8);
        offset += 10;
        if (offset + data_length > response_length) {
            errno = EPROTO;
            return -1;
        }
        if (type == DNS_TYPE_OPT) {
            full_rcode = (uint16_t)(response[offset - 6] << 4) | header_rcode;
        }
        offset += data_length;
    }

    if (full_rcode == 0)
        return 0;
    if (full_rcode == 2)
        errno = EAGAIN;
    else if (full_rcode == 3)
        errno = ENOENT;
    else if (full_rcode == 4)
        errno = ECOMM;
    else
        errno = EIO;
    return -1;
}

static int skip_questions(const uint8_t *response, size_t response_length, size_t *offset)
{
    uint16_t questions = read_u16(response + 4);
    for (uint16_t i = 0; i < questions; i++) {
        char ignored[DNS_MAX_NAME + 1];
        if (dns_expand_name(response, response_length, offset, ignored, sizeof ignored) < 0)
            return -1;
        if (*offset + 4 > response_length) {
            errno = EPROTO;
            return -1;
        }
        *offset += 4;
    }
    return 0;
}

static int append_unique(char out[][64], int max, int *count, const char *address)
{
    for (int i = 0; i < *count; i++) {
        if (strcmp(out[i], address) == 0)
            return 0;
    }
    if (*count >= max)
        return 0;
    int written = snprintf(out[*count], 64, "%s", address);
    if (written < 0 || written >= 64) {
        errno = EMSGSIZE;
        return -1;
    }
    (*count)++;
    return 0;
}

static int parse_addresses(const uint8_t *response, size_t response_length,
                           char out[][64], int max, int *count,
                           char canonical[256])
{
    if (response_rcode(response, response_length) < 0)
        return -1;

    size_t offset = DNS_HEADER_SIZE;
    if (skip_questions(response, response_length, &offset) < 0)
        return -1;
    uint16_t answers = read_u16(response + 6);

    for (uint16_t i = 0; i < answers; i++) {
        char owner[DNS_MAX_NAME + 1];
        if (dns_expand_name(response, response_length, &offset, owner, sizeof owner) < 0)
            return -1;
        if (offset + 10 > response_length) {
            errno = EPROTO;
            return -1;
        }
        uint16_t type = read_u16(response + offset);
        uint16_t class = read_u16(response + offset + 2);
        uint16_t data_length = read_u16(response + offset + 8);
        offset += 10;
        if (offset + data_length > response_length) {
            errno = EPROTO;
            return -1;
        }

        char text[INET6_ADDRSTRLEN];
        const void *address = response + offset;
        int family = AF_UNSPEC;
        if (class == DNS_CLASS_IN && type == DNS_TYPE_A && data_length == 4)
            family = AF_INET;
        else if (class == DNS_CLASS_IN && type == DNS_TYPE_AAAA && data_length == 16)
            family = AF_INET6;

        if (class == DNS_CLASS_IN && type == DNS_TYPE_CNAME && canonical && !canonical[0]) {
            size_t name_offset = offset;
            char target[DNS_MAX_NAME + 1];
            if (dns_expand_name(response, response_length, &name_offset,
                                target, sizeof target) < 0 ||
                name_offset > offset + data_length) {
                errno = EPROTO;
                return -1;
            }
            int written = snprintf(canonical, 256, "%s", target);
            if (written < 0 || written >= 256) {
                errno = EMSGSIZE;
                return -1;
            }
        }

        if (family != AF_UNSPEC) {
            if (!inet_ntop(family, address, text, sizeof text))
                return -1;
            if (append_unique(out, max, count, text) < 0)
                return -1;
        }
        offset += data_length;
    }

    if (*count == 0) {
        errno = ENODATA;
        return -1;
    }
    return 0;
}

static int append_unique_name(char out[][256], int max, int *count, const char *name)
{
    for (int i = 0; i < *count; i++) {
        if (strcasecmp(out[i], name) == 0)
            return 0;
    }
    if (*count >= max)
        return 0;
    int written = snprintf(out[*count], 256, "%s", name);
    if (written < 0 || written >= 256) {
        errno = EMSGSIZE;
        return -1;
    }
    (*count)++;
    return 0;
}

static int parse_ptr_names(const uint8_t *response, size_t response_length,
                           char out[][256], int max, int *count)
{
    if (response_rcode(response, response_length) < 0)
        return -1;

    size_t offset = DNS_HEADER_SIZE;
    if (skip_questions(response, response_length, &offset) < 0)
        return -1;
    uint16_t answers = read_u16(response + 6);

    for (uint16_t i = 0; i < answers; i++) {
        char owner[DNS_MAX_NAME + 1];
        if (dns_expand_name(response, response_length, &offset, owner, sizeof owner) < 0)
            return -1;
        if (offset + 10 > response_length) {
            errno = EPROTO;
            return -1;
        }
        uint16_t type = read_u16(response + offset);
        uint16_t class = read_u16(response + offset + 2);
        uint16_t data_length = read_u16(response + offset + 8);
        offset += 10;
        if (offset + data_length > response_length) {
            errno = EPROTO;
            return -1;
        }

        if (class == DNS_CLASS_IN && type == DNS_TYPE_PTR) {
            size_t name_offset = offset;
            char name[DNS_MAX_NAME + 1];
            if (dns_expand_name(response, response_length, &name_offset, name, sizeof name) < 0)
                return -1;
            if (name_offset > offset + data_length) {
                errno = EPROTO;
                return -1;
            }
            if (append_unique_name(out, max, count, name) < 0)
                return -1;
        }
        offset += data_length;
    }

    if (*count == 0) {
        errno = ENODATA;
        return -1;
    }
    return 0;
}

static int resolve_type(const char *name, uint16_t qtype, char out[][64], int max,
                        int *count, char canonical[256])
{
    uint8_t *response = malloc(DNS_MAX_PACKET);
    if (!response) {
        errno = ENOMEM;
        return -1;
    }
    size_t response_length = 0;
    int result = dns_query(name, qtype, response, DNS_MAX_PACKET, &response_length);
    if (result == 0)
        result = parse_addresses(response, response_length, out, max, count, canonical);
    int saved = errno;
    free(response);
    errno = saved;
    return result;
}

int sr_stub_resolve_hostname(const char *name, char out[][64], int max, int *n_out,
                             char canonical[256])
{
    if (!name || !*name || !out || !n_out || max <= 0) {
        errno = EINVAL;
        return -1;
    }

    *n_out = 0;
    if (canonical)
        canonical[0] = '\0';
    int first_error = 0;
    if (resolve_type(name, DNS_TYPE_A, out, max, n_out, canonical) < 0)
        first_error = errno;
    if (*n_out < max &&
        resolve_type(name, DNS_TYPE_AAAA, out, max, n_out, canonical) < 0 &&
        first_error == 0)
        first_error = errno;

    if (*n_out == 0) {
        errno = first_error != 0 ? first_error : ENODATA;
        if (errno == ENOENT)
            errno = ESRCH;
        else if (errno == EPROTO)
            errno = EINVAL;
        return -1;
    }
    return 0;
}

static int reverse_name(const void *address, socklen_t length, int family,
                        char *out, size_t capacity)
{
    if (!address || !out) {
        errno = EINVAL;
        return -1;
    }

    if (family == AF_INET && length == sizeof(struct in_addr)) {
        const uint8_t *bytes = address;
        int written = snprintf(out, capacity, "%u.%u.%u.%u.in-addr.arpa",
                               bytes[3], bytes[2], bytes[1], bytes[0]);
        if (written < 0 || (size_t)written >= capacity) {
            errno = EMSGSIZE;
            return -1;
        }
        return 0;
    }

    if (family == AF_INET6 && length == sizeof(struct in6_addr)) {
        const uint8_t *bytes = address;
        size_t offset = 0;
        static const char hex[] = "0123456789abcdef";
        for (int i = 15; i >= 0; i--) {
            if (offset + 4 >= capacity) {
                errno = EMSGSIZE;
                return -1;
            }
            out[offset++] = hex[bytes[i] & 0x0Fu];
            out[offset++] = '.';
            out[offset++] = hex[bytes[i] >> 4];
            out[offset++] = '.';
        }
        const char suffix[] = "ip6.arpa";
        if (offset + sizeof suffix > capacity) {
            errno = EMSGSIZE;
            return -1;
        }
        memcpy(out + offset, suffix, sizeof suffix);
        return 0;
    }

    errno = family == AF_INET || family == AF_INET6 ? EINVAL : EAFNOSUPPORT;
    return -1;
}

int sr_stub_resolve_address(const void *address, socklen_t length, int family,
                            char out[][256], int max, int *n_out)
{
    if (!out || !n_out || max <= 0) {
        errno = EINVAL;
        return -1;
    }

    char name[DNS_MAX_NAME + 1];
    if (reverse_name(address, length, family, name, sizeof name) < 0)
        return -1;

    uint8_t *response = malloc(DNS_MAX_PACKET);
    if (!response) {
        errno = ENOMEM;
        return -1;
    }
    size_t response_length = 0;
    *n_out = 0;
    int result = dns_query(name, DNS_TYPE_PTR, response, DNS_MAX_PACKET, &response_length);
    if (result == 0)
        result = parse_ptr_names(response, response_length, out, max, n_out);
    int saved = errno;
    if (saved == ENOENT)
        saved = ESRCH;
    else if (saved == EPROTO)
        saved = EINVAL;
    free(response);
    errno = saved;
    return result;
}
