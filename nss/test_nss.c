#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <nss.h>
#include <resolv.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nss_resolve_shm.h"

extern enum nss_status _nss_resolve_gethostbyname4_r(
    const char *name,
    struct gaih_addrtuple **pat,
    char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop,
    int32_t *ttlp);

extern enum nss_status _nss_resolve_gethostbyname2_r(
    const char *name, int family,
    struct hostent *result, char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop);

extern enum nss_status _nss_resolve_gethostbyname_r(
    const char *name,
    struct hostent *result, char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop);

extern enum nss_status _nss_resolve_gethostbyaddr2_r(
    const void *address, socklen_t address_length, int family,
    struct hostent *result, char *buffer, size_t buffer_length,
    int *errnop, int *h_errnop, int32_t *ttlp);

static void fail(const char *message)
{
    fprintf(stderr, "NSS test failed: %s\n", message);
    exit(EXIT_FAILURE);
}

static void require_status(enum nss_status actual, enum nss_status expected,
                           const char *operation, int error, int host_error)
{
    if (actual != expected) {
        fprintf(stderr,
                "NSS test failed: %s returned %d instead of %d (errno=%d h_errno=%d)\n",
                operation, actual, expected, error, host_error);
        exit(EXIT_FAILURE);
    }
}

static void test_interface_policy_parser(void)
{
    const char *current = getenv("RUSTD_NSS_RESOLVE_INTERFACE");
    char *saved = current ? strdup(current) : NULL;
    if (current && !saved)
        fail("could not preserve interface policy");

    unsigned int loopback = if_nametoindex("lo");
    if (loopback == 0)
        fail("loopback interface is unavailable");
    char numeric[32];
    if (snprintf(numeric, sizeof numeric, "%u", loopback) < 0 ||
        setenv("RUSTD_NSS_RESOLVE_INTERFACE", numeric, 1) != 0 ||
        sr_nss_query_ifindex() != (int)loopback)
        fail("numeric interface policy was not resolved");
    if (setenv("RUSTD_NSS_RESOLVE_INTERFACE", "2147483647", 1) != 0 ||
        sr_nss_query_ifindex() != 0)
        fail("nonexistent numeric interface policy was accepted");

    if (saved) {
        if (setenv("RUSTD_NSS_RESOLVE_INTERFACE", saved, 1) != 0)
            fail("could not restore interface policy");
    } else if (unsetenv("RUSTD_NSS_RESOLVE_INTERFACE") != 0) {
        fail("could not clear interface policy");
    }
    free(saved);
}

static int hostent_has_address(const struct hostent *entry, const char *expected)
{
    uint8_t binary[sizeof(struct in6_addr)];
    if (inet_pton(entry->h_addrtype, expected, binary) != 1)
        fail("invalid expected address");
    for (char **address = entry->h_addr_list; address && *address; address++) {
        if (memcmp(*address, binary, (size_t)entry->h_length) == 0)
            return 1;
    }
    return 0;
}

static void test_gaih(void)
{
    char buffer[8192];
    struct gaih_addrtuple *tuples = NULL;
    int error = 0;
    int host_error = 0;
    int32_t ttl = -1;
    errno = E2BIG;
    enum nss_status status = _nss_resolve_gethostbyname4_r(
        "example.test", &tuples, buffer, sizeof buffer, &error, &host_error, &ttl);
    require_status(status, NSS_STATUS_SUCCESS, "gethostbyname4", error, host_error);
    if (!tuples || ttl != 0 || error != 0 || host_error != NETDB_SUCCESS)
        fail("invalid gethostbyname4 metadata");
    if (errno != E2BIG)
        fail("successful NSS lookup did not preserve errno");

    const char *expected_ipv6 = getenv("NSS_TEST_IPV6_ADDRESS");
    if (!expected_ipv6)
        expected_ipv6 = "2001:db8::123";
    unsigned int expected_scope = 0;
    const char *scope_interface = getenv("NSS_TEST_IPV6_SCOPE_INTERFACE");
    if (scope_interface)
        expected_scope = if_nametoindex(scope_interface);

    int ipv4 = 0;
    int ipv6 = 0;
    unsigned count = 0;
    for (struct gaih_addrtuple *tuple = tuples; tuple; tuple = tuple->next) {
        if (!tuple->name || strcmp(tuple->name, "example.test") != 0)
            fail("invalid gaih canonical name");
        if (tuple->family == AF_INET) {
            struct in_addr expected;
            if (inet_pton(AF_INET, "192.0.2.123", &expected) != 1 ||
                memcmp(tuple->addr, &expected, sizeof expected) != 0)
                fail("invalid gaih IPv4 address");
            ipv4++;
        } else if (tuple->family == AF_INET6) {
            struct in6_addr expected;
            if (inet_pton(AF_INET6, expected_ipv6, &expected) != 1 ||
                memcmp(tuple->addr, &expected, sizeof expected) != 0)
                fail("invalid gaih IPv6 address");
            if (tuple->scopeid != expected_scope)
                fail("invalid gaih IPv6 scope identifier");
            ipv6++;
        } else {
            fail("invalid gaih address family");
        }
        if (++count > 8)
            fail("gaih tuple list contains a cycle");
    }
    if (ipv4 != 1 || ipv6 != 1)
        fail("gaih tuple list is incomplete");
}

static void test_hostent_family(int family, const char *expected)
{
    char buffer[8192];
    struct hostent result;
    int error = 0;
    int host_error = 0;
    enum nss_status status = _nss_resolve_gethostbyname2_r(
        "example.test", family, &result, buffer, sizeof buffer, &error, &host_error);
    require_status(status, NSS_STATUS_SUCCESS, "gethostbyname2", error, host_error);
    if (!result.h_name || strcmp(result.h_name, "example.test") != 0 ||
        result.h_addrtype != family || !result.h_aliases || result.h_aliases[0] != NULL ||
        !result.h_addr_list || !result.h_addr_list[0] || result.h_addr_list[1] != NULL)
        fail("invalid hostent layout");
    if (!hostent_has_address(&result, expected))
        fail("hostent address is missing");
}

static void test_canonical_name(void)
{
    char buffer[8192];
    struct hostent result;
    int error = 0;
    int host_error = 0;
    enum nss_status status = _nss_resolve_gethostbyname2_r(
        "alias.test", AF_INET, &result, buffer, sizeof buffer, &error, &host_error);
    require_status(status, NSS_STATUS_SUCCESS, "canonical-name lookup", error, host_error);
    if (!result.h_name || strcmp(result.h_name, "example.test") != 0)
        fail("canonical name from Varlink was not preserved");

    status = _nss_resolve_gethostbyname2_r(
        "canonical-omitted.test", AF_INET, &result, buffer, sizeof buffer, &error, &host_error);
    require_status(status, NSS_STATUS_SUCCESS, "optional canonical-name lookup", error, host_error);
    if (!result.h_name || strcmp(result.h_name, "canonical-omitted.test") != 0)
        fail("query name was not used when the Varlink canonical name was omitted");

    status = _nss_resolve_gethostbyname2_r(
        "canonical-extension.test", AF_INET, &result, buffer, sizeof buffer, &error, &host_error);
    require_status(status, NSS_STATUS_SUCCESS, "canonical extension lookup", error, host_error);
    if (!result.h_name || strcmp(result.h_name, "canonical-extension.test") != 0)
        fail("nested extension field replaced the canonical name");
}

static void test_legacy_ipv6_preference(void)
{
    char buffer[8192];
    struct hostent result;
    int error = 0;
    int host_error = 0;
    unsigned long saved_options = _res.options;
    _res.options |= 0x00002000;
    enum nss_status status = _nss_resolve_gethostbyname_r(
        "example.test", &result, buffer, sizeof buffer, &error, &host_error);
    _res.options = saved_options;
    require_status(status, NSS_STATUS_SUCCESS, "legacy IPv6 preference", error, host_error);
    if (result.h_addrtype != AF_INET6)
        fail("legacy resolver IPv6 preference was ignored");
}

static void test_reverse(int family, const char *address)
{
    uint8_t binary[sizeof(struct in6_addr)];
    int length = family == AF_INET ? (int)sizeof(struct in_addr) : (int)sizeof(struct in6_addr);
    if (inet_pton(family, address, binary) != 1)
        fail("invalid reverse test address");

    char buffer[8192];
    struct hostent result;
    int error = 0;
    int host_error = 0;
    int32_t ttl = -1;
    enum nss_status status = _nss_resolve_gethostbyaddr2_r(
        binary, (socklen_t)length, family, &result, buffer, sizeof buffer,
        &error, &host_error, &ttl);
    require_status(status, NSS_STATUS_SUCCESS, "gethostbyaddr2", error, host_error);
    if (!result.h_name || strcmp(result.h_name, "example.test") != 0 ||
        result.h_addrtype != family || result.h_length != length || ttl != 0 ||
        !result.h_addr_list || !result.h_addr_list[0] || result.h_addr_list[1] != NULL ||
        memcmp(result.h_addr_list[0], binary, (size_t)length) != 0)
        fail("invalid reverse hostent");
    if (!getenv("NSS_TEST_SKIP_REVERSE_ALIAS") &&
        (!result.h_aliases || !result.h_aliases[0] || result.h_aliases[1] != NULL ||
         strcmp(result.h_aliases[0], "alias.test") != 0))
            fail("invalid reverse aliases");
}

static void test_not_found(void)
{
    char buffer[8192];
    struct hostent result;
    int error = 0;
    int host_error = 0;
    errno = E2BIG;
    enum nss_status status = _nss_resolve_gethostbyname2_r(
        "missing.test", AF_INET, &result, buffer, sizeof buffer, &error, &host_error);
    require_status(status, NSS_STATUS_NOTFOUND, "missing lookup", error, host_error);
    if (error != 0 || host_error != NO_DATA)
        fail("missing lookup returned the wrong errors");
    if (errno != E2BIG)
        fail("negative NSS lookup did not preserve errno");
}

static void test_small_buffer(void)
{
    char buffer[8];
    struct hostent result;
    int error = 0;
    int host_error = 0;
    enum nss_status status = _nss_resolve_gethostbyname2_r(
        "example.test", AF_INET, &result, buffer, sizeof buffer, &error, &host_error);
    require_status(status, NSS_STATUS_TRYAGAIN, "small-buffer lookup", error, host_error);
    if (error != ERANGE || host_error != NETDB_INTERNAL)
        fail("small-buffer lookup returned the wrong errors");
}

static void test_empty_and_reverse_buffer_contracts(void)
{
    char buffer[68];
    struct hostent result;
    int error = 0;
    int host_error = 0;
    enum nss_status status;
    if (!getenv("NSS_TEST_SKIP_VARLINK_ERRORS")) {
        status = _nss_resolve_gethostbyname2_r(
            "empty.test", AF_INET, &result, buffer, sizeof buffer, &error, &host_error);
        require_status(status, NSS_STATUS_NOTFOUND, "empty address list", error, host_error);
        if (host_error != HOST_NOT_FOUND)
            fail("empty address list did not map to HOST_NOT_FOUND");
    }

    if (!getenv("NSS_TEST_SKIP_REVERSE_ALIAS")) {
        struct in_addr address;
        if (inet_pton(AF_INET, "192.0.2.123", &address) != 1)
            fail("invalid reverse buffer test address");
        error = 0;
        host_error = 0;
        status = _nss_resolve_gethostbyaddr2_r(
            &address, sizeof address, AF_INET, &result, buffer, sizeof buffer,
            &error, &host_error, NULL);
        require_status(status, NSS_STATUS_TRYAGAIN, "reverse small-buffer lookup", error, host_error);
        if (error != ERANGE || host_error != NETDB_INTERNAL)
            fail("reverse small-buffer lookup returned the wrong errors");
    }
}

static void test_error_status(const char *name, enum nss_status expected,
                              int expected_error, int expected_host_error)
{
    char buffer[8192];
    struct hostent result;
    int error = 0;
    int host_error = 0;
    enum nss_status status = _nss_resolve_gethostbyname2_r(
        name, AF_INET, &result, buffer, sizeof buffer, &error, &host_error);
    require_status(status, expected, name, error, host_error);
    if (error != expected_error || host_error != expected_host_error) {
        fprintf(stderr,
                "NSS test failed: %s mapped to errno=%d h_errno=%d instead of errno=%d h_errno=%d\n",
                name, error, host_error, expected_error, expected_host_error);
        exit(EXIT_FAILURE);
    }
}

static void test_reverse_error_contracts(void)
{
    char buffer[8192];
    struct hostent result;
    struct in_addr address;
    if (inet_pton(AF_INET, "203.0.113.1", &address) != 1)
        fail("invalid missing reverse address");

    int error = 0;
    int host_error = 0;
    enum nss_status status = _nss_resolve_gethostbyaddr2_r(
        &address, sizeof address, AF_INET, &result, buffer, sizeof buffer,
        &error, &host_error, NULL);
    require_status(status, NSS_STATUS_NOTFOUND, "missing reverse lookup", error, host_error);
    if (error != 0 || host_error != HOST_NOT_FOUND)
        fail("missing reverse lookup returned the wrong errors");

    error = 0;
    host_error = 0;
    status = _nss_resolve_gethostbyaddr2_r(
        &address, sizeof address, AF_UNSPEC, &result, buffer, sizeof buffer,
        &error, &host_error, NULL);
    require_status(status, NSS_STATUS_UNAVAIL, "invalid reverse family", error, host_error);
    if (error != EAFNOSUPPORT || host_error != NO_DATA)
        fail("invalid reverse family returned the wrong errors");

    if (!getenv("NSS_TEST_SKIP_VARLINK_ERRORS")) {
        if (inet_pton(AF_INET, "198.51.100.41", &address) != 1)
            fail("invalid reverse schema address");
        error = 0;
        host_error = 0;
        status = _nss_resolve_gethostbyaddr2_r(
            &address, sizeof address, AF_INET, &result, buffer, sizeof buffer,
            &error, &host_error, NULL);
        require_status(status, NSS_STATUS_UNAVAIL, "invalid reverse schema", error, host_error);
        if (error != EINVAL || host_error != NO_RECOVERY)
            fail("invalid reverse schema returned the wrong errors");
    }
}

static void test_large_varlink_results(void)
{
    char buffer[65536];
    struct gaih_addrtuple *tuples = NULL;
    int error = 0;
    int host_error = 0;
    enum nss_status status = _nss_resolve_gethostbyname4_r(
        "many.test", &tuples, buffer, sizeof buffer, &error, &host_error, NULL);
    require_status(status, NSS_STATUS_SUCCESS, "large forward result", error, host_error);
    size_t address_count = 0;
    for (struct gaih_addrtuple *tuple = tuples; tuple; tuple = tuple->next) {
        if (tuple->family != AF_INET || ++address_count > 80)
            fail("large forward result was malformed");
    }
    if (address_count != 80)
        fail("large forward result was truncated");

    struct in_addr address;
    if (inet_pton(AF_INET, "198.51.100.40", &address) != 1)
        fail("invalid large reverse address");
    struct hostent result;
    error = 0;
    host_error = 0;
    status = _nss_resolve_gethostbyaddr2_r(
        &address, sizeof address, AF_INET, &result, buffer, sizeof buffer,
        &error, &host_error, NULL);
    require_status(status, NSS_STATUS_SUCCESS, "large reverse result", error, host_error);
    size_t name_count = 1;
    for (char **alias = result.h_aliases; alias && *alias; alias++)
        name_count++;
    if (name_count != 40)
        fail("large reverse result was truncated");
}

static void test_resolver_unavailable(void)
{
    char buffer[8192];
    struct hostent result;
    int error = 0;
    int host_error = 0;
    enum nss_status status = _nss_resolve_gethostbyname2_r(
        "example.test", AF_INET, &result, buffer, sizeof buffer, &error, &host_error);
    require_status(status, NSS_STATUS_UNAVAIL, "unavailable resolver", error, host_error);
    if (host_error != NO_RECOVERY)
        fail("unavailable resolver mapped to the wrong host error");
}

int main(void)
{
    test_interface_policy_parser();
    if (getenv("NSS_TEST_EXPECT_UNAVAILABLE")) {
        test_resolver_unavailable();
        puts("NSS unavailable-resolver fallback test passed");
        return EXIT_SUCCESS;
    }
    const char *expected_ipv6 = getenv("NSS_TEST_IPV6_ADDRESS");
    if (!expected_ipv6)
        expected_ipv6 = "2001:db8::123";
    test_gaih();
    test_hostent_family(AF_INET, "192.0.2.123");
    test_hostent_family(AF_INET6, expected_ipv6);
    test_legacy_ipv6_preference();
    if (!getenv("NSS_TEST_SKIP_CANONICAL"))
        test_canonical_name();
    test_reverse(AF_INET, "192.0.2.123");
    test_reverse(AF_INET6, expected_ipv6);
    test_not_found();
    test_reverse_error_contracts();
    if (!getenv("NSS_TEST_SKIP_VARLINK_ERRORS"))
        test_large_varlink_results();
    test_empty_and_reverse_buffer_contracts();
    if (!getenv("NSS_TEST_SKIP_VARLINK_ERRORS")) {
        test_error_status("dnssec.test", NSS_STATUS_NOTFOUND, 0, HOST_NOT_FOUND);
        test_error_status("retry.test", NSS_STATUS_TRYAGAIN, 0, TRY_AGAIN);
        test_error_status("protocol.test", NSS_STATUS_UNAVAIL, 0, NO_RECOVERY);
        test_error_status("nested-fields.test", NSS_STATUS_UNAVAIL, EINVAL, NO_RECOVERY);
        test_error_status("malformed-address.test", NSS_STATUS_UNAVAIL, EINVAL, NO_RECOVERY);
        test_error_status("malformed-flags.test", NSS_STATUS_UNAVAIL, EINVAL, NO_RECOVERY);
    }
    test_small_buffer();
    puts("NSS forward, reverse, legacy hostent, and buffer tests passed");
    return EXIT_SUCCESS;
}
