#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <nss.h>
#include <pthread.h>
#include <resolv.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "nss_resolve_shm.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define DEPRECATED_RES_USE_INET6 0x00002000

static int block_nss_signals(sigset_t *saved)
{
    sigset_t blocked;
    if (sigemptyset(&blocked) != 0)
        return -1;
    const int signals[] = {
        SIGALRM, SIGVTALRM, SIGPIPE, SIGCHLD, SIGTSTP, SIGIO, SIGHUP,
        SIGUSR1, SIGUSR2, SIGPROF, SIGURG, SIGWINCH,
    };
    for (size_t i = 0; i < ARRAY_SIZE(signals); i++) {
        if (sigaddset(&blocked, signals[i]) != 0)
            return -1;
    }
    return pthread_sigmask(SIG_BLOCK, &blocked, saved) == 0 ? 0 : -1;
}

static void restore_nss_signals(const sigset_t *saved)
{
    (void)pthread_sigmask(SIG_SETMASK, saved, NULL);
}

static size_t align_up(size_t value, size_t alignment)
{
    return (value + alignment - 1u) & ~(alignment - 1u);
}

static int add_size(size_t left, size_t right, size_t *ret)
{
    if (left > SIZE_MAX - right) {
        errno = EOVERFLOW;
        return -1;
    }
    *ret = left + right;
    return 0;
}

static int multiply_size(size_t left, size_t right, size_t *ret)
{
    if (left != 0 && right > SIZE_MAX / left) {
        errno = EOVERFLOW;
        return -1;
    }
    *ret = left * right;
    return 0;
}

static enum nss_status status_from_errno(int error, int *errnop, int *h_errnop)
{
    if (error == 0)
        error = EIO;
    if (errnop)
        *errnop = error;

    switch (error) {
    case ENOENT:
    case ESRCH:
        if (h_errnop)
            *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    case ENODATA:
        if (h_errnop)
            *h_errnop = NO_DATA;
        return NSS_STATUS_NOTFOUND;
    case ETIMEDOUT:
    case EAGAIN:
    case ENETDOWN:
    case ENETUNREACH:
    case EHOSTUNREACH:
        if (h_errnop)
            *h_errnop = TRY_AGAIN;
        return NSS_STATUS_TRYAGAIN;
    case ERANGE:
        if (h_errnop)
            *h_errnop = NETDB_INTERNAL;
        return NSS_STATUS_TRYAGAIN;
    default:
        if (h_errnop)
            *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }
}

static enum nss_status status_success(int *errnop, int *h_errnop)
{
    if (errnop)
        *errnop = 0;
    if (h_errnop)
        *h_errnop = NETDB_SUCCESS;
    h_errno = 0;
    return NSS_STATUS_SUCCESS;
}

static enum nss_status status_from_resolver_error(int error, int *errnop, int *h_errnop)
{
    switch (error) {
    case ESRCH:
        if (h_errnop)
            *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    case ENODATA:
        if (h_errnop)
            *h_errnop = NO_DATA;
        return NSS_STATUS_NOTFOUND;
    case EAGAIN:
        if (errnop)
            *errnop = 0;
        if (h_errnop)
            *h_errnop = TRY_AGAIN;
        return NSS_STATUS_TRYAGAIN;
    case ECOMM:
        if (errnop)
            *errnop = 0;
        if (h_errnop)
            *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    default:
        if (errnop)
            *errnop = error == 0 ? EIO : error;
        if (h_errnop)
            *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }
}

static int collect_addrs(const char *name, int family,
                         struct sr_resolved_addr **addrs_out, size_t *n_out,
                         int *secure, char canonical[256])
{
    if (!addrs_out || !n_out) {
        errno = EINVAL;
        return -1;
    }
    *addrs_out = NULL;
    *n_out = 0;
    uint64_t query_flags = sr_nss_query_flags();
    int query_ifindex = sr_nss_query_ifindex();
    uint8_t wire[256];
    size_t wire_length = 0;
    if (sr_encode_name(name, wire, sizeof wire, &wire_length) != 0) {
        errno = EINVAL;
        return -1;
    }

    struct sr_resolved_addr cached[128];
    const size_t capacity = ARRAY_SIZE(cached);
    size_t count = 0;
    uint8_t rcode = 0;
    int all_secure = 1;
    int cache_hit = 0;
    if (canonical) {
        strncpy(canonical, name, 255);
        canonical[255] = '\0';
    }

    if (query_flags == 0 && query_ifindex == 0) {
        if (family != AF_INET6) {
            struct sr_shm_addr ipv4[64];
            size_t ipv4_count = capacity < ARRAY_SIZE(ipv4) ? capacity : ARRAY_SIZE(ipv4);
            int ipv4_secure = 0;
            if (sr_shm_lookup(wire, wire_length, 1, 1, &rcode, ipv4, &ipv4_count, &ipv4_secure) == 0 &&
                rcode == 0) {
                for (size_t i = 0; i < ipv4_count; i++) {
                    memset(&cached[count], 0, sizeof cached[count]);
                    cached[count].family = ipv4[i].family;
                    cached[count].scope_id = ipv4[i].scope_id;
                    memcpy(cached[count].addr, ipv4[i].addr, sizeof cached[count].addr);
                    count++;
                }
                all_secure = ipv4_secure;
                cache_hit = 1;
            }
        }

        if (family != AF_INET && count < capacity) {
            struct sr_shm_addr ipv6[64];
            size_t ipv6_count = capacity - count;
            if (ipv6_count > ARRAY_SIZE(ipv6))
                ipv6_count = ARRAY_SIZE(ipv6);
            int ipv6_secure = 0;
            if (sr_shm_lookup(wire, wire_length, 28, 1, &rcode, ipv6, &ipv6_count, &ipv6_secure) == 0 &&
                rcode == 0) {
                for (size_t i = 0; i < ipv6_count && count < capacity; i++) {
                    memset(&cached[count], 0, sizeof cached[count]);
                    cached[count].family = ipv6[i].family;
                    cached[count].scope_id = ipv6[i].scope_id;
                    memcpy(cached[count].addr, ipv6[i].addr, sizeof cached[count].addr);
                    count++;
                }
                all_secure = cache_hit ? all_secure && ipv6_secure : ipv6_secure;
                cache_hit = 1;
            }
        }
    }

    if (count == 0) {
        if (sr_varlink_resolve_hostname(name, family, query_flags, query_ifindex,
                                        addrs_out, n_out,
                                        canonical) != 0)
            return -1;
        all_secure = 0;
    } else {
        struct sr_resolved_addr *result = malloc(count * sizeof *result);
        if (!result) {
            errno = ENOMEM;
            return -1;
        }
        memcpy(result, cached, count * sizeof *result);
        *addrs_out = result;
        *n_out = count;
    }

    if (*n_out == 0) {
        errno = ENODATA;
        free(*addrs_out);
        *addrs_out = NULL;
        return -1;
    }
    if (secure)
        *secure = all_secure;
    return 0;
}

static enum nss_status pack_gaih(
    const char *name,
    const struct sr_resolved_addr *addrs, size_t count,
    struct gaih_addrtuple **pat,
    char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop)
{
    size_t valid_count = 0;
    for (size_t i = 0; i < count; i++) {
        if (addrs[i].family == 4 || addrs[i].family == 6)
            valid_count++;
    }
    if (valid_count == 0)
        return status_from_errno(ENODATA, errnop, h_errnop);

    size_t name_length = strlen(name) + 1;
    size_t tuple_alignment = _Alignof(struct gaih_addrtuple);
    size_t tuple_stride = align_up(sizeof(struct gaih_addrtuple), tuple_alignment);
    size_t tuples_offset = align_up(name_length, tuple_alignment);
    size_t tuple_bytes = 0;
    size_t required = 0;
    if (multiply_size(valid_count, tuple_stride, &tuple_bytes) < 0 ||
        add_size(tuples_offset, tuple_bytes, &required) < 0)
        return status_from_errno(errno, errnop, h_errnop);
    if (required > buffer_length)
        return status_from_errno(ERANGE, errnop, h_errnop);

    memset(buffer, 0, required);
    memcpy(buffer, name, name_length);

    struct gaih_addrtuple *first = NULL;
    struct gaih_addrtuple *previous = NULL;
    size_t offset = tuples_offset;
    for (size_t i = 0; i < count; i++) {
        if (addrs[i].family != 4 && addrs[i].family != 6)
            continue;
        struct gaih_addrtuple *tuple = (struct gaih_addrtuple *)(void *)(buffer + offset);
        tuple->name = buffer;
        tuple->family = addrs[i].family == 4 ? AF_INET : AF_INET6;
        tuple->scopeid = tuple->family == AF_INET6 ? addrs[i].scope_id : 0;
        memcpy(tuple->addr, addrs[i].addr, tuple->family == AF_INET ? 4u : 16u);
        if (!first)
            first = tuple;
        if (previous)
            previous->next = tuple;
        previous = tuple;
        offset += tuple_stride;
    }

    if (*pat)
        **pat = *first;
    else
        *pat = first;
    return status_success(errnop, h_errnop);
}

static enum nss_status pack_hostent(
    const char *name, int family,
    const struct sr_resolved_addr *addrs, size_t count,
    struct hostent *result,
    char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop,
    int32_t *ttlp, char **canonp)
{
    if (family == AF_UNSPEC)
        family = AF_INET;
    if (family != AF_INET && family != AF_INET6)
        return status_from_errno(EAFNOSUPPORT, errnop, h_errnop);

    size_t address_length = family == AF_INET ? 4u : 16u;
    size_t matching = 0;
    for (size_t i = 0; i < count; i++) {
        if ((family == AF_INET && addrs[i].family == 4) ||
            (family == AF_INET6 && addrs[i].family == 6))
            matching++;
    }
    if (matching == 0)
        return status_from_errno(ENODATA, errnop, h_errnop);

    size_t pointer_alignment = _Alignof(char *);
    size_t name_length = strlen(name) + 1;
    size_t aliases_offset = align_up(name_length, pointer_alignment);
    size_t addresses_offset = aliases_offset + sizeof(char *);
    size_t address_stride = align_up(address_length, pointer_alignment);
    size_t address_bytes = 0;
    size_t address_list_offset = 0;
    size_t pointer_bytes = 0;
    size_t required = 0;
    if (multiply_size(matching, address_stride, &address_bytes) < 0 ||
        add_size(addresses_offset, address_bytes, &address_list_offset) < 0 ||
        multiply_size(matching + 1u, sizeof(char *), &pointer_bytes) < 0 ||
        add_size(address_list_offset, pointer_bytes, &required) < 0)
        return status_from_errno(errno, errnop, h_errnop);
    if (required > buffer_length)
        return status_from_errno(ERANGE, errnop, h_errnop);

    memset(buffer, 0, required);
    memcpy(buffer, name, name_length);
    char **aliases = (char **)(void *)(buffer + aliases_offset);
    aliases[0] = NULL;

    char *address_data = buffer + addresses_offset;
    char **address_list = (char **)(void *)(buffer + address_list_offset);
    size_t output = 0;
    for (size_t i = 0; i < count; i++) {
        if (!((family == AF_INET && addrs[i].family == 4) ||
              (family == AF_INET6 && addrs[i].family == 6)))
            continue;
        address_list[output] = address_data + output * address_stride;
        memcpy(address_list[output], addrs[i].addr, address_length);
        output++;
    }
    address_list[output] = NULL;

    result->h_name = buffer;
    result->h_aliases = aliases;
    result->h_addrtype = family;
    result->h_length = (int)address_length;
    result->h_addr_list = address_list;
    if (ttlp)
        *ttlp = 0;
    if (canonp)
        *canonp = result->h_name;
    return status_success(errnop, h_errnop);
}

static enum nss_status gethostbyname4_impl(
    const char *name,
    struct gaih_addrtuple **pat,
    char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop,
    int32_t *ttlp)
{
    if (!name || !*name || !pat || !buffer || !errnop || !h_errnop)
        return status_from_errno(EINVAL, errnop, h_errnop);

    struct sr_resolved_addr *addrs = NULL;
    size_t count = 0;
    int secure = 0;
    char canonical[256];
    if (collect_addrs(name, AF_UNSPEC, &addrs, &count, &secure, canonical) != 0)
        return status_from_resolver_error(errno, errnop, h_errnop);
    (void)secure;

    if (ttlp)
        *ttlp = 0;
    enum nss_status status = pack_gaih(
        canonical, addrs, count, pat, buffer, buffer_length, errnop, h_errnop);
    free(addrs);
    return status;
}

enum nss_status _nss_rustd_dns_gethostbyname4_r(
    const char *name,
    struct gaih_addrtuple **pat,
    char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop,
    int32_t *ttlp)
{
    int saved_errno = errno;
    sigset_t saved_signals;
    int signals_blocked = block_nss_signals(&saved_signals) == 0;
    enum nss_status status = gethostbyname4_impl(
        name, pat, buffer, buffer_length, errnop, h_errnop, ttlp);
    if (signals_blocked)
        restore_nss_signals(&saved_signals);
    errno = saved_errno;
    return status;
}

static enum nss_status gethostbyname3_impl(
    const char *name, int family,
    struct hostent *result, char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
    if (!name || !*name || !result || !buffer || !errnop || !h_errnop)
        return status_from_errno(EINVAL, errnop, h_errnop);

    if (family == AF_UNSPEC)
        family = AF_INET;
    if (family != AF_INET && family != AF_INET6)
        return status_from_errno(EAFNOSUPPORT, errnop, h_errnop);

    struct sr_resolved_addr *addrs = NULL;
    size_t count = 0;
    int secure = 0;
    char canonical[256];
    if (collect_addrs(name, family, &addrs, &count, &secure, canonical) != 0)
        return status_from_resolver_error(errno, errnop, h_errnop);
    (void)secure;

    enum nss_status status = pack_hostent(
        canonical, family, addrs, count, result, buffer, buffer_length,
        errnop, h_errnop, ttlp, canonp);
    free(addrs);
    return status;
}

enum nss_status _nss_rustd_dns_gethostbyname3_r(
    const char *name, int family,
    struct hostent *result, char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
    int saved_errno = errno;
    sigset_t saved_signals;
    int signals_blocked = block_nss_signals(&saved_signals) == 0;
    enum nss_status status = gethostbyname3_impl(
        name, family, result, buffer, buffer_length,
        errnop, h_errnop, ttlp, canonp);
    if (signals_blocked)
        restore_nss_signals(&saved_signals);
    errno = saved_errno;
    return status;
}

enum nss_status _nss_rustd_dns_gethostbyname2_r(
    const char *name, int family,
    struct hostent *result, char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop)
{
    return _nss_rustd_dns_gethostbyname3_r(name, family, result, buffer, buffer_length,
                                         errnop, h_errnop, NULL, NULL);
}

enum nss_status _nss_rustd_dns_gethostbyname_r(
    const char *name,
    struct hostent *result, char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop)
{
    enum nss_status status = NSS_STATUS_NOTFOUND;
    if (_res.options & DEPRECATED_RES_USE_INET6)
        status = _nss_rustd_dns_gethostbyname3_r(
            name, AF_INET6, result, buffer, buffer_length,
            errnop, h_errnop, NULL, NULL);
    if (status == NSS_STATUS_NOTFOUND)
        status = _nss_rustd_dns_gethostbyname3_r(
            name, AF_INET, result, buffer, buffer_length,
            errnop, h_errnop, NULL, NULL);
    return status;
}

static enum nss_status pack_reverse_hostent(
    const void *address, socklen_t address_length, int family,
    char names[][256], int name_count,
    struct hostent *result,
    char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop, int32_t *ttlp)
{
    if (name_count <= 0)
        return status_from_errno(ENODATA, errnop, h_errnop);

    size_t names_size = 0;
    for (int i = 0; i < name_count; i++) {
        size_t length = strlen(names[i]) + 1;
        if (add_size(names_size, align_up(length, _Alignof(char *)), &names_size) < 0)
            return status_from_errno(errno, errnop, h_errnop);
    }

    size_t pointer_alignment = _Alignof(char *);
    size_t address_offset = 0;
    size_t address_list_offset = align_up(address_length, pointer_alignment);
    size_t aliases_offset = 0;
    size_t names_offset = 0;
    size_t pointer_bytes = 0;
    size_t required = 0;
    if (add_size(address_list_offset, 2u * sizeof(char *), &aliases_offset) < 0 ||
        multiply_size((size_t)name_count, sizeof(char *), &pointer_bytes) < 0 ||
        add_size(aliases_offset, pointer_bytes, &names_offset) < 0 ||
        add_size(names_offset, names_size, &required) < 0)
        return status_from_errno(errno, errnop, h_errnop);
    if (required > buffer_length)
        return status_from_errno(ERANGE, errnop, h_errnop);

    memset(buffer, 0, required);
    memcpy(buffer + address_offset, address, address_length);
    char **address_list = (char **)(void *)(buffer + address_list_offset);
    address_list[0] = buffer + address_offset;
    address_list[1] = NULL;

    char **aliases = (char **)(void *)(buffer + aliases_offset);
    size_t name_cursor = 0;
    for (int i = 0; i < name_count; i++) {
        size_t length = strlen(names[i]) + 1;
        char *destination = buffer + names_offset + name_cursor;
        memcpy(destination, names[i], length);
        if (i > 0)
            aliases[i - 1] = destination;
        name_cursor += align_up(length, pointer_alignment);
    }
    aliases[name_count - 1] = NULL;

    result->h_name = buffer + names_offset;
    result->h_aliases = aliases;
    result->h_addrtype = family;
    result->h_length = (int)address_length;
    result->h_addr_list = address_list;
    if (ttlp)
        *ttlp = 0;
    return status_success(errnop, h_errnop);
}

static enum nss_status gethostbyaddr2_impl(
    const void *address, socklen_t address_length, int family,
    struct hostent *result, char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop, int32_t *ttlp)
{
    if (!address || !result || !buffer || !errnop || !h_errnop)
        return status_from_errno(EINVAL, errnop, h_errnop);
    if (family != AF_INET && family != AF_INET6) {
        *errnop = EAFNOSUPPORT;
        *h_errnop = NO_DATA;
        return NSS_STATUS_UNAVAIL;
    }
    if ((family == AF_INET && address_length != sizeof(struct in_addr)) ||
        (family == AF_INET6 && address_length != sizeof(struct in6_addr)))
        return status_from_errno(EINVAL, errnop, h_errnop);

    char (*names)[256] = NULL;
    size_t name_count = 0;
    uint64_t query_flags = sr_nss_query_flags();
    int query_ifindex = sr_nss_query_ifindex();
    if (sr_varlink_resolve_address(address, address_length, family,
                                   query_flags, query_ifindex,
                                   &names, &name_count) != 0) {
        if (errno == ENODATA)
            errno = ESRCH;
        return status_from_resolver_error(errno, errnop, h_errnop);
    }

    if (name_count > INT_MAX) {
        free(names);
        return status_from_errno(EOVERFLOW, errnop, h_errnop);
    }
    enum nss_status status = pack_reverse_hostent(
        address, address_length, family, names, (int)name_count,
        result, buffer, buffer_length, errnop, h_errnop, ttlp);
    free(names);
    return status;
}

enum nss_status _nss_rustd_dns_gethostbyaddr2_r(
    const void *address, socklen_t address_length, int family,
    struct hostent *result, char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop, int32_t *ttlp)
{
    int saved_errno = errno;
    sigset_t saved_signals;
    int signals_blocked = block_nss_signals(&saved_signals) == 0;
    enum nss_status status = gethostbyaddr2_impl(
        address, address_length, family, result, buffer, buffer_length,
        errnop, h_errnop, ttlp);
    if (signals_blocked)
        restore_nss_signals(&saved_signals);
    errno = saved_errno;
    return status;
}

enum nss_status _nss_rustd_dns_gethostbyaddr_r(
    const void *address, socklen_t address_length, int family,
    struct hostent *result, char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop)
{
    return _nss_rustd_dns_gethostbyaddr2_r(address, address_length, family,
                                         result, buffer, buffer_length,
                                         errnop, h_errnop, NULL);
}
