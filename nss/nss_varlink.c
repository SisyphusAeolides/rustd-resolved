#define _GNU_SOURCE
#include "nss_resolve_shm.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define VARLINK_SOCKET_PATH "/run/rustd/resolve/io.rustd.Resolve"
#define VARLINK_MAX_REPLY (1024u * 1024u)

static int parse_boolean(const char *value)
{
    if (!value)
        return -1;
    if (strcmp(value, "1") == 0 || strcasecmp(value, "yes") == 0 ||
        strcasecmp(value, "y") == 0 || strcasecmp(value, "true") == 0 ||
        strcasecmp(value, "t") == 0 || strcasecmp(value, "on") == 0)
        return 1;
    if (strcmp(value, "0") == 0 || strcasecmp(value, "no") == 0 ||
        strcasecmp(value, "n") == 0 || strcasecmp(value, "false") == 0 ||
        strcasecmp(value, "f") == 0 || strcasecmp(value, "off") == 0)
        return 0;
    return -1;
}

static uint64_t disabled_query_flag(const char *name, uint64_t flag)
{
    const char *value = secure_getenv(name);
    return parse_boolean(value) == 0 ? flag : 0;
}

static int resolve_alternative_ifname(const char *name)
{
    size_t name_length = strlen(name) + 1u;
    if (name_length > 256u)
        return 0;

    int descriptor = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (descriptor < 0)
        return 0;
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
    attribute->rta_type = IFLA_ALT_IFNAME;
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
        if (received <= 0)
            break;
        int remaining = (int)received;
        for (struct nlmsghdr *message = (struct nlmsghdr *)(void *)reply;
             NLMSG_OK(message, (unsigned int)remaining);
             message = NLMSG_NEXT(message, remaining)) {
            if (message->nlmsg_seq != request.header.nlmsg_seq)
                continue;
            if (message->nlmsg_type == NLMSG_ERROR || message->nlmsg_type == NLMSG_DONE)
                goto finish;
            if (message->nlmsg_type != RTM_NEWLINK ||
                message->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg)))
                continue;
            const struct ifinfomsg *link = NLMSG_DATA(message);
            if (link->ifi_index > 0)
                result = link->ifi_index;
            goto finish;
        }
    }

finish:
    close(descriptor);
    return result;
}

uint64_t sr_nss_query_flags(void)
{
    return disabled_query_flag("RUSTD_NSS_DNS_VALIDATE", SR_RESOLVED_NO_VALIDATE) |
           disabled_query_flag("RUSTD_NSS_DNS_SYNTHESIZE", SR_RESOLVED_NO_SYNTHESIZE) |
           disabled_query_flag("RUSTD_NSS_DNS_CACHE", SR_RESOLVED_NO_CACHE) |
           disabled_query_flag("RUSTD_NSS_DNS_ZONE", SR_RESOLVED_NO_ZONE) |
           disabled_query_flag("RUSTD_NSS_DNS_TRUST_ANCHOR", SR_RESOLVED_NO_TRUST_ANCHOR) |
           disabled_query_flag("RUSTD_NSS_DNS_NETWORK", SR_RESOLVED_NO_NETWORK);
}

int sr_nss_query_ifindex(void)
{
    const char *value = secure_getenv("RUSTD_NSS_DNS_INTERFACE");
    if (!value || !*value)
        return 0;

    int saved_errno = errno;
    unsigned int index = if_nametoindex(value);
    if (index > 0 && index <= INT_MAX) {
        errno = saved_errno;
        return (int)index;
    }

    int alternative = resolve_alternative_ifname(value);
    if (alternative > 0) {
        errno = saved_errno;
        return alternative;
    }

    errno = 0;
    char *end = NULL;
    long number = strtol(value, &end, 10);
    if (errno == 0 && end != value && *end == '\0' && number > 0 && number <= INT_MAX) {
        char ifname[IF_NAMESIZE];
        if (if_indextoname((unsigned int)number, ifname)) {
            errno = saved_errno;
            return (int)number;
        }
    }
    errno = saved_errno;
    return 0;
}

static int set_timeouts(int fd)
{
    const struct timeval timeout = { .tv_sec = 120, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0)
        return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) < 0)
        return -1;
    return 0;
}

static const char *varlink_socket_path(void)
{
    const char *value = secure_getenv("RUSTD_NSS_DNS_VARLINK");
    if (!value || !*value)
        return VARLINK_SOCKET_PATH;
    if (strcmp(value, "0") == 0 || strcasecmp(value, "no") == 0 ||
        strcasecmp(value, "false") == 0 || strcasecmp(value, "off") == 0) {
        errno = ENOENT;
        return NULL;
    }
    return value;
}

static int send_all_no_signal(int fd, const void *buffer, size_t length)
{
    const uint8_t *p = buffer;
    while (length > 0) {
        ssize_t written = send(fd, p, length, MSG_NOSIGNAL);
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

static int json_escape(const char *input, char **ret)
{
    if (!input || !ret) {
        errno = EINVAL;
        return -1;
    }
    size_t length = strlen(input);
    if (length > 4096) {
        errno = EMSGSIZE;
        return -1;
    }
    size_t capacity = length * 6u + 1u;
    char *output = malloc(capacity);
    if (!output) {
        errno = ENOMEM;
        return -1;
    }
    size_t used = 0;
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < length; i++) {
        unsigned char byte = (unsigned char)input[i];
        if (byte == '"' || byte == '\\') {
            output[used++] = '\\';
            output[used++] = (char)byte;
        } else if (byte == '\b') {
            output[used++] = '\\';
            output[used++] = 'b';
        } else if (byte == '\f') {
            output[used++] = '\\';
            output[used++] = 'f';
        } else if (byte == '\n') {
            output[used++] = '\\';
            output[used++] = 'n';
        } else if (byte == '\r') {
            output[used++] = '\\';
            output[used++] = 'r';
        } else if (byte == '\t') {
            output[used++] = '\\';
            output[used++] = 't';
        } else if (byte < 0x20u) {
            output[used++] = '\\';
            output[used++] = 'u';
            output[used++] = '0';
            output[used++] = '0';
            output[used++] = hex[byte >> 4];
            output[used++] = hex[byte & 0x0fu];
        } else {
            output[used++] = (char)byte;
        }
    }
    output[used] = '\0';
    *ret = output;
    return 0;
}

static int varlink_call(const char *request, char **reply_out, size_t *reply_length_out)
{
    if (!request || !reply_out || !reply_length_out) {
        errno = EINVAL;
        return -1;
    }
    const char *path = varlink_socket_path();
    if (!path)
        return -1;
    size_t path_length = strlen(path);
    if (path_length == 0 || path_length >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (set_timeouts(fd) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    struct sockaddr_un address;
    memset(&address, 0, sizeof address);
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, path_length + 1u);
    if (connect(fd, (const struct sockaddr *)&address, sizeof address) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    size_t request_length = strlen(request);
    if (send_all_no_signal(fd, request, request_length) < 0 ||
        send_all_no_signal(fd, "\0", 1) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    size_t capacity = 8192;
    size_t used = 0;
    char *reply = malloc(capacity + 1u);
    if (!reply) {
        close(fd);
        errno = ENOMEM;
        return -1;
    }

    for (;;) {
        if (used == capacity) {
            if (capacity >= VARLINK_MAX_REPLY) {
                free(reply);
                close(fd);
                errno = EMSGSIZE;
                return -1;
            }
            size_t next = capacity * 2u;
            if (next > VARLINK_MAX_REPLY)
                next = VARLINK_MAX_REPLY;
            char *grown = realloc(reply, next + 1u);
            if (!grown) {
                int saved = errno;
                free(reply);
                close(fd);
                errno = saved;
                return -1;
            }
            reply = grown;
            capacity = next;
        }
        ssize_t received = recv(fd, reply + used, capacity - used, 0);
        if (received < 0) {
            if (errno == EINTR)
                continue;
            int saved = errno;
            free(reply);
            close(fd);
            errno = saved;
            return -1;
        }
        if (received == 0) {
            free(reply);
            close(fd);
            errno = ECONNRESET;
            return -1;
        }
        char *terminator = memchr(reply + used, '\0', (size_t)received);
        used += (size_t)received;
        if (terminator) {
            used = (size_t)(terminator - reply);
            break;
        }
    }
    close(fd);
    reply[used] = '\0';
    *reply_out = reply;
    *reply_length_out = used;
    return 0;
}

static const char *json_string_end(const char *start, const char *end)
{
    if (!start || start >= end || *start != '"')
        return NULL;
    for (const char *cursor = start + 1; cursor < end; cursor++) {
        unsigned char byte = (unsigned char)*cursor;
        if (byte == '"')
            return cursor + 1;
        if (byte < 0x20u)
            return NULL;
        if (byte != '\\')
            continue;
        cursor++;
        if (cursor >= end || !strchr("\"\\/bfnrtu", *cursor))
            return NULL;
        if (*cursor == 'u') {
            if (end - cursor < 5)
                return NULL;
            for (int i = 1; i <= 4; i++) {
                if (!((cursor[i] >= '0' && cursor[i] <= '9') ||
                      (cursor[i] >= 'a' && cursor[i] <= 'f') ||
                      (cursor[i] >= 'A' && cursor[i] <= 'F')))
                    return NULL;
            }
            cursor += 4;
        }
    }
    return NULL;
}

static const char *json_compound_end(const char *start, const char *end)
{
    if (!start || start >= end || (*start != '{' && *start != '['))
        return NULL;
    char stack[64];
    size_t depth = 0;
    for (const char *cursor = start; cursor < end; cursor++) {
        if (*cursor == '"') {
            cursor = json_string_end(cursor, end);
            if (!cursor)
                return NULL;
            cursor--;
            continue;
        }
        if (*cursor == '{' || *cursor == '[') {
            if (depth == sizeof stack)
                return NULL;
            stack[depth++] = *cursor;
            continue;
        }
        if (*cursor != '}' && *cursor != ']')
            continue;
        if (depth == 0 || (stack[depth - 1] == '{' && *cursor != '}') ||
            (stack[depth - 1] == '[' && *cursor != ']'))
            return NULL;
        depth--;
        if (depth == 0)
            return cursor + 1;
    }
    return NULL;
}

static const char *json_value_end(const char *start, const char *end)
{
    if (!start || start >= end)
        return NULL;
    if (*start == '"')
        return json_string_end(start, end);
    if (*start == '{' || *start == '[')
        return json_compound_end(start, end);
    const char *cursor = start;
    while (cursor < end && *cursor != ',' && *cursor != '}' && *cursor != ']' &&
           *cursor != ' ' && *cursor != '\t' && *cursor != '\r' && *cursor != '\n')
        cursor++;
    return cursor > start ? cursor : NULL;
}

static const char *skip_json_space(const char *cursor, const char *end)
{
    while (cursor < end && (*cursor == ' ' || *cursor == '\t' ||
                            *cursor == '\r' || *cursor == '\n'))
        cursor++;
    return cursor;
}

static const char *json_find_key(const char *start, const char *end, const char *key)
{
    if (!start || !end || start >= end || *start != '{')
        return NULL;
    const char *object_end = json_compound_end(start, end);
    if (!object_end)
        return NULL;
    const char *cursor = skip_json_space(start + 1, object_end);
    while (cursor < object_end && *cursor != '}') {
        const char *key_end = json_string_end(cursor, object_end);
        if (!key_end)
            return NULL;
        size_t key_length = strlen(key);
        int matches = (size_t)(key_end - cursor) == key_length + 2u &&
                      memcmp(cursor + 1, key, key_length) == 0;
        cursor = skip_json_space(key_end, object_end);
        if (cursor >= object_end || *cursor != ':')
            return NULL;
        const char *value = skip_json_space(cursor + 1, object_end);
        const char *value_end = json_value_end(value, object_end);
        if (!value_end)
            return NULL;
        if (matches)
            return value;
        cursor = skip_json_space(value_end, object_end);
        if (cursor < object_end && *cursor == ',')
            cursor = skip_json_space(cursor + 1, object_end);
        else if (cursor >= object_end || *cursor != '}')
            return NULL;
    }
    return NULL;
}

static int hex_value(char byte)
{
    if (byte >= '0' && byte <= '9')
        return byte - '0';
    if (byte >= 'a' && byte <= 'f')
        return byte - 'a' + 10;
    if (byte >= 'A' && byte <= 'F')
        return byte - 'A' + 10;
    return -1;
}

static int parse_json_string(const char *start, const char *end,
                             char *output, size_t capacity, const char **next)
{
    if (!start || start >= end || *start != '"' || !output || capacity == 0) {
        errno = EPROTO;
        return -1;
    }
    size_t used = 0;
    const char *cursor = start + 1;
    while (cursor < end) {
        unsigned char byte = (unsigned char)*cursor++;
        if (byte == '"') {
            output[used] = '\0';
            if (next)
                *next = cursor;
            return 0;
        }
        if (byte == '\\') {
            if (cursor >= end) {
                errno = EPROTO;
                return -1;
            }
            char escape = *cursor++;
            switch (escape) {
            case '"': byte = '"'; break;
            case '\\': byte = '\\'; break;
            case '/': byte = '/'; break;
            case 'b': byte = '\b'; break;
            case 'f': byte = '\f'; break;
            case 'n': byte = '\n'; break;
            case 'r': byte = '\r'; break;
            case 't': byte = '\t'; break;
            case 'u': {
                if (end - cursor < 4) {
                    errno = EPROTO;
                    return -1;
                }
                int a = hex_value(cursor[0]);
                int b = hex_value(cursor[1]);
                int c = hex_value(cursor[2]);
                int d = hex_value(cursor[3]);
                if (a < 0 || b < 0 || c < 0 || d < 0 || a != 0 || b != 0) {
                    errno = EPROTO;
                    return -1;
                }
                byte = (unsigned char)((c << 4) | d);
                cursor += 4;
                break;
            }
            default:
                errno = EPROTO;
                return -1;
            }
        } else if (byte < 0x20u) {
            errno = EPROTO;
            return -1;
        }
        if (used + 1u >= capacity) {
            errno = EMSGSIZE;
            return -1;
        }
        if (byte == 0) {
            errno = EPROTO;
            return -1;
        }
        output[used++] = (char)byte;
    }
    errno = EPROTO;
    return -1;
}

static int parse_json_integer(const char *start, const char *end, long *value, const char **next)
{
    if (!start || start >= end || !value) {
        errno = EPROTO;
        return -1;
    }
    errno = 0;
    char *parsed_end = NULL;
    long parsed = strtol(start, &parsed_end, 10);
    if (errno != 0 || parsed_end == start || parsed_end > end) {
        errno = EPROTO;
        return -1;
    }
    *value = parsed;
    if (next)
        *next = parsed_end;
    return 0;
}

static int parse_json_uint64(const char *start, const char *end, uint64_t *value)
{
    if (!start || start >= end || !value || *start == '-') {
        errno = EPROTO;
        return -1;
    }
    errno = 0;
    char *parsed_end = NULL;
    unsigned long long parsed = strtoull(start, &parsed_end, 10);
    const char *value_end = json_value_end(start, end);
    if (errno != 0 || parsed_end == start || !value_end || parsed_end != value_end) {
        errno = EPROTO;
        return -1;
    }
    *value = (uint64_t)parsed;
    return 0;
}

static int parse_byte_array(const char *start, const char *end,
                            uint8_t *bytes, size_t capacity, size_t *length)
{
    if (!start || start >= end || *start != '[' || !bytes || !length) {
        errno = EPROTO;
        return -1;
    }
    size_t used = 0;
    const char *cursor = start + 1;
    for (;;) {
        while (cursor < end && (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n'))
            cursor++;
        if (cursor >= end) {
            errno = EPROTO;
            return -1;
        }
        if (*cursor == ']') {
            *length = used;
            return 0;
        }
        long value = 0;
        if (parse_json_integer(cursor, end, &value, &cursor) < 0 || value < 0 || value > 255) {
            errno = EPROTO;
            return -1;
        }
        if (used >= capacity) {
            errno = EMSGSIZE;
            return -1;
        }
        bytes[used++] = (uint8_t)value;
        while (cursor < end && (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n'))
            cursor++;
        if (cursor >= end || (*cursor != ',' && *cursor != ']')) {
            errno = EPROTO;
            return -1;
        }
        if (*cursor == ']') {
            *length = used;
            return 0;
        }
        cursor++;
    }
}

static int varlink_error(const char *reply, size_t length)
{
    const char *end = reply + length;
    const char *value = json_find_key(reply, end, "error");
    if (!value)
        return 0;
    char identifier[256];
    const char *next = NULL;
    if (parse_json_string(value, end, identifier, sizeof identifier, &next) < 0 ||
        next != json_value_end(value, end))
        return -1;
    if (strcmp(identifier, "io.rustd.Resolve.NoSuchResourceRecord") == 0)
        errno = ENODATA;
    else if (strcmp(identifier, "io.rustd.Resolve.NoNameServers") == 0 ||
             strcmp(identifier, "io.rustd.Resolve.QueryTimedOut") == 0 ||
             strcmp(identifier, "io.rustd.Resolve.MaxAttemptsReached") == 0 ||
             strcmp(identifier, "io.rustd.Resolve.NetworkDown") == 0)
        errno = EAGAIN;
    else if (strstr(identifier, "Disconnected") || strstr(identifier, "Timeout") ||
             strstr(identifier, "Protocol") || strstr(identifier, "InterfaceNotFound") ||
             strstr(identifier, "MethodNotFound") || strstr(identifier, "MethodNotImplemented"))
        errno = ECOMM;
    else
        errno = ESRCH;
    return -1;
}

static int parse_varlink_addresses(const char *reply, size_t length,
                                   struct sr_resolved_addr **out, size_t *n_out,
                                   char canonical[256])
{
    if (varlink_error(reply, length) < 0)
        return -1;
    errno = 0;
    const char *end = reply + length;
    const char *parameters = json_find_key(reply, end, "parameters");
    const char *array = parameters ? json_find_key(parameters, end, "addresses") : NULL;
    const char *array_after = array ? json_compound_end(array, end) : NULL;
    if (!parameters || *parameters != '{' || !array || *array != '[' || !array_after) {
        errno = EPROTO;
        return -1;
    }
    const char *flags_value = json_find_key(parameters, end, "flags");
    uint64_t reply_flags = 0;
    if (flags_value && parse_json_uint64(flags_value, end, &reply_flags) < 0) {
        errno = EINVAL;
        return -1;
    }
    (void)reply_flags;
    const char *array_end = array_after - 1;
    const char *cursor = skip_json_space(array + 1, array_end);
    struct sr_resolved_addr *entries = NULL;
    size_t count = 0;
    size_t capacity = 0;
    while (cursor < array_end && *cursor != ']') {
        const char *entry_after = json_compound_end(cursor, array_end);
        if (*cursor != '{' || !entry_after)
            goto fail;
        const char *ifindex_value = json_find_key(cursor, entry_after, "ifindex");
        const char *family_value = json_find_key(cursor, entry_after, "family");
        const char *address_value = json_find_key(cursor, entry_after, "address");
        if (!family_value || !address_value)
            goto fail;
        long ifindex_number = 0;
        long family_number = 0;
        const char *ifindex_next = NULL;
        const char *family_next = NULL;
        if ((ifindex_value &&
             (parse_json_integer(ifindex_value, entry_after, &ifindex_number, &ifindex_next) < 0 ||
              ifindex_next != json_value_end(ifindex_value, entry_after))) ||
            ifindex_number < 0 || ifindex_number > INT_MAX ||
            parse_json_integer(family_value, entry_after, &family_number, &family_next) < 0 ||
            family_next != json_value_end(family_value, entry_after) ||
            family_number < 0 || family_number > INT_MAX)
            goto fail;
        uint8_t bytes[16];
        size_t byte_count = 0;
        if (parse_byte_array(address_value, entry_after, bytes, sizeof bytes, &byte_count) < 0)
            goto fail;
        int family = family_number == AF_INET ? AF_INET : family_number == AF_INET6 ? AF_INET6 : AF_UNSPEC;
        size_t expected = family == AF_INET ? 4u : family == AF_INET6 ? 16u : 0u;
        if (expected != 0 && byte_count != expected) {
            errno = EINVAL;
            goto fail;
        }
        if (expected != 0 && byte_count == expected) {
            if (count == capacity) {
                size_t next_capacity = capacity == 0 ? 8u : capacity * 2u;
                if (next_capacity < capacity || next_capacity > SIZE_MAX / sizeof *entries) {
                    free(entries);
                    errno = EOVERFLOW;
                    return -1;
                }
                struct sr_resolved_addr *grown = realloc(entries, next_capacity * sizeof *entries);
                if (!grown) {
                    free(entries);
                    errno = ENOMEM;
                    return -1;
                }
                entries = grown;
                capacity = next_capacity;
            }
            struct sr_resolved_addr *entry = &entries[count];
            memset(entry, 0, sizeof *entry);
            entry->family = family == AF_INET ? 4 : 6;
            memcpy(entry->addr, bytes, expected);
            if (family == AF_INET6 && ifindex_number > 0) {
                struct in6_addr address;
                memcpy(&address, bytes, sizeof address);
                if (IN6_IS_ADDR_LINKLOCAL(&address))
                    entry->scope_id = (uint32_t)ifindex_number;
            }
            count++;
        }
        cursor = skip_json_space(entry_after, array_end);
        if (cursor < array_end && *cursor == ',')
            cursor = skip_json_space(cursor + 1, array_end);
        else if (cursor < array_end && *cursor != ']')
            goto fail;
    }
    if (count == 0) {
        free(entries);
        errno = ESRCH;
        return -1;
    }
    if (canonical) {
        const char *name_value = json_find_key(parameters, end, "name");
        if (name_value) {
            const char *name_next = NULL;
            if (parse_json_string(name_value, end, canonical, 256, &name_next) < 0 ||
                name_next != json_value_end(name_value, end))
                goto fail;
        }
    }
    *out = entries;
    *n_out = count;
    return 0;

fail:
    free(entries);
    if (errno == 0 || errno == EPROTO)
        errno = EINVAL;
    return -1;
}

static int parse_varlink_names(const char *reply, size_t length,
                               char (**out)[256], size_t *n_out)
{
    if (varlink_error(reply, length) < 0)
        return -1;
    errno = 0;
    const char *end = reply + length;
    const char *parameters = json_find_key(reply, end, "parameters");
    const char *array = parameters ? json_find_key(parameters, end, "names") : NULL;
    const char *array_after = array ? json_compound_end(array, end) : NULL;
    if (!parameters || *parameters != '{' || !array || *array != '[' || !array_after) {
        errno = EPROTO;
        return -1;
    }
    const char *flags_value = json_find_key(parameters, end, "flags");
    uint64_t reply_flags = 0;
    if (flags_value && parse_json_uint64(flags_value, end, &reply_flags) < 0) {
        errno = EINVAL;
        return -1;
    }
    (void)reply_flags;
    const char *array_end = array_after - 1;
    const char *cursor = skip_json_space(array + 1, array_end);
    char (*entries)[256] = NULL;
    size_t count = 0;
    size_t capacity = 0;
    while (cursor < array_end && *cursor != ']') {
        const char *entry_after = json_compound_end(cursor, array_end);
        if (*cursor != '{' || !entry_after)
            goto fail_names;
        const char *name_value = json_find_key(cursor, entry_after, "name");
        if (!name_value)
            goto fail_names;
        const char *ifindex_value = json_find_key(cursor, entry_after, "ifindex");
        if (ifindex_value) {
            long ifindex_number = 0;
            const char *ifindex_next = NULL;
            if (parse_json_integer(ifindex_value, entry_after, &ifindex_number, &ifindex_next) < 0 ||
                ifindex_next != json_value_end(ifindex_value, entry_after) ||
                ifindex_number < 0 || ifindex_number > INT_MAX)
                goto fail_names;
        }
        if (count == capacity) {
            size_t next_capacity = capacity == 0 ? 8u : capacity * 2u;
            if (next_capacity < capacity || next_capacity > SIZE_MAX / sizeof *entries) {
                free(entries);
                errno = EOVERFLOW;
                return -1;
            }
            char (*grown)[256] = realloc(entries, next_capacity * sizeof *entries);
            if (!grown) {
                free(entries);
                errno = ENOMEM;
                return -1;
            }
            entries = grown;
            capacity = next_capacity;
        }
        const char *next = NULL;
        if (parse_json_string(name_value, entry_after, entries[count], 256, &next) < 0 ||
            next != json_value_end(name_value, entry_after))
            goto fail_names;
        count++;
        cursor = skip_json_space(entry_after, array_end);
        if (cursor < array_end && *cursor == ',')
            cursor = skip_json_space(cursor + 1, array_end);
        else if (cursor < array_end && *cursor != ']')
            goto fail_names;
    }
    if (count == 0) {
        free(entries);
        errno = ENODATA;
        return -1;
    }
    *out = entries;
    *n_out = count;
    return 0;

fail_names:
    free(entries);
    if (errno == 0 || errno == EPROTO)
        errno = EINVAL;
    return -1;
}

static int varlink_resolve_hostname(const char *name, int family,
                                    uint64_t flags, int ifindex,
                                    struct sr_resolved_addr **out, size_t *n_out,
                                    char canonical[256])
{
    char *escaped = NULL;
    if (json_escape(name, &escaped) < 0)
        return -1;
    size_t request_size = strlen(escaped) + 256u;
    char *request = malloc(request_size);
    if (!request) {
        free(escaped);
        errno = ENOMEM;
        return -1;
    }
    int written = snprintf(
        request,
        request_size,
        "{\"method\":\"io.rustd.Resolve.ResolveHostname\",\"parameters\":{\"ifindex\":%d,\"name\":\"%s\",\"family\":%d,\"flags\":%" PRIu64 "}}",
        ifindex,
        escaped,
        family,
        flags);
    free(escaped);
    if (written < 0 || (size_t)written >= request_size) {
        free(request);
        errno = EMSGSIZE;
        return -1;
    }
    char *reply = NULL;
    size_t reply_length = 0;
    int result = varlink_call(request, &reply, &reply_length);
    free(request);
    if (result == 0)
        result = parse_varlink_addresses(reply, reply_length, out, n_out, canonical);
    int saved = errno;
    free(reply);
    errno = saved;
    return result;
}

static int varlink_resolve_address(const void *address, socklen_t length, int family,
                                   uint64_t flags, int ifindex,
                                   char (**out)[256], size_t *n_out)
{
    size_t expected = family == AF_INET ? sizeof(struct in_addr) : family == AF_INET6 ? sizeof(struct in6_addr) : 0u;
    if (!address || expected == 0 || length != expected) {
        errno = family == AF_INET || family == AF_INET6 ? EINVAL : EAFNOSUPPORT;
        return -1;
    }
    const uint8_t *bytes = address;
    char address_json[16u * 4u + 1u];
    size_t used = 0;
    for (size_t i = 0; i < expected; i++) {
        int written = snprintf(address_json + used, sizeof address_json - used,
                               "%s%u", i == 0 ? "" : ",", bytes[i]);
        if (written < 0 || (size_t)written >= sizeof address_json - used) {
            errno = EMSGSIZE;
            return -1;
        }
        used += (size_t)written;
    }
    char request[512];
    int written = snprintf(
        request,
        sizeof request,
        "{\"method\":\"io.rustd.Resolve.ResolveAddress\",\"parameters\":{\"ifindex\":%d,\"family\":%d,\"address\":[%s],\"flags\":%" PRIu64 "}}",
        ifindex,
        family,
        address_json,
        flags);
    if (written < 0 || (size_t)written >= sizeof request) {
        errno = EMSGSIZE;
        return -1;
    }
    char *reply = NULL;
    size_t reply_length = 0;
    int result = varlink_call(request, &reply, &reply_length);
    if (result == 0)
        result = parse_varlink_names(reply, reply_length, out, n_out);
    int saved = errno;
    free(reply);
    errno = saved;
    return result;
}

static int varlink_fallback_allowed(int error)
{
    switch (error) {
    case ENOENT:
    case ECONNREFUSED:
    case ECONNRESET:
    case ENOTSOCK:
    case EPROTOTYPE:
    case EPIPE:
    case EPROTO:
    case ECOMM:
    case ETIMEDOUT:
        return 1;
    default:
        return 0;
    }
}

static int stub_fallback_enabled(void)
{
    const char *value = secure_getenv("RUSTD_NSS_DNS_STUB");
    return value && *value && strcmp(value, "0") != 0 &&
           strcasecmp(value, "no") != 0 && strcasecmp(value, "false") != 0 &&
           strcasecmp(value, "off") != 0;
}

int sr_varlink_resolve_hostname(const char *name, int family,
                                uint64_t flags, int ifindex,
                                struct sr_resolved_addr **out, size_t *n_out,
                                char canonical[256])
{
    if (!out || !n_out) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    *n_out = 0;
    if (canonical)
        canonical[0] = '\0';
    if (varlink_resolve_hostname(name, family, flags, ifindex, out, n_out, canonical) == 0) {
        if (canonical && canonical[0] == '\0') {
            strncpy(canonical, name, 255);
            canonical[255] = '\0';
        }
        return 0;
    }
    int varlink_error_number = errno;
    if (flags != 0 || ifindex != 0) {
        errno = varlink_error_number;
        return -1;
    }
    if (!varlink_fallback_allowed(varlink_error_number))
        return -1;
    if (!stub_fallback_enabled()) {
        errno = varlink_error_number;
        return -1;
    }
    char addresses[128][64];
    int stub_count = 0;
    if (sr_stub_resolve_hostname(name, addresses,
                                 (int)(sizeof addresses / sizeof addresses[0]),
                                 &stub_count, canonical) == 0) {
        struct sr_resolved_addr *entries = calloc((size_t)stub_count, sizeof *entries);
        if (!entries) {
            errno = ENOMEM;
            return -1;
        }
        size_t count = 0;
        for (int i = 0; i < stub_count; i++) {
            struct sr_resolved_addr *entry = &entries[count];
            memset(entry, 0, sizeof *entry);
            if (inet_pton(AF_INET, addresses[i], entry->addr) == 1) {
                if (family != AF_INET6) {
                    entry->family = 4;
                    count++;
                }
            } else if (inet_pton(AF_INET6, addresses[i], entry->addr) == 1 && family != AF_INET) {
                entry->family = 6;
                count++;
            }
        }
        *out = entries;
        *n_out = count;
        if (count > 0) {
            if (canonical && canonical[0] == '\0') {
                strncpy(canonical, name, 255);
                canonical[255] = '\0';
            }
            return 0;
        }
        free(entries);
        *out = NULL;
        errno = ENODATA;
    }
    if (varlink_error_number != ENOENT && varlink_error_number != ECONNREFUSED)
        errno = varlink_error_number;
    return -1;
}

int sr_varlink_resolve_address(const void *address, socklen_t length, int family,
                               uint64_t flags, int ifindex,
                               char (**out)[256], size_t *n_out)
{
    if (!out || !n_out) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    *n_out = 0;
    if (varlink_resolve_address(address, length, family, flags, ifindex, out, n_out) == 0)
        return 0;
    int varlink_error_number = errno;
    if (flags != 0 || ifindex != 0) {
        errno = varlink_error_number;
        return -1;
    }
    if (!varlink_fallback_allowed(varlink_error_number))
        return -1;
    if (!stub_fallback_enabled()) {
        errno = varlink_error_number;
        return -1;
    }
    char names[128][256];
    int stub_count = 0;
    if (sr_stub_resolve_address(address, length, family, names,
                                (int)(sizeof names / sizeof names[0]), &stub_count) == 0) {
        char (*entries)[256] = malloc((size_t)stub_count * sizeof *entries);
        if (!entries) {
            errno = ENOMEM;
            return -1;
        }
        memcpy(entries, names, (size_t)stub_count * sizeof *entries);
        *out = entries;
        *n_out = (size_t)stub_count;
        return 0;
    }
    if (varlink_error_number != ENOENT && varlink_error_number != ECONNREFUSED)
        errno = varlink_error_number;
    return -1;
}
