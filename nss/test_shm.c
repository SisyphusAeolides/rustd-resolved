#define _GNU_SOURCE
#include "nss_resolve_shm.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct sr_hdr_fixture {
    uint64_t magic;
    uint32_t version;
    uint32_t n_buckets;
    uint32_t arena_off;
    uint32_t arena_size;
    uint64_t write_gen;
    uint32_t arena_used;
    uint32_t pad;
};

struct sr_bucket_fixture {
    uint64_t gen;
    uint64_t hash;
    uint32_t off;
    uint32_t len;
    uint64_t expires_ms;
    uint32_t flags;
    uint16_t qtype;
    uint16_t qclass;
    uint8_t rcode;
    uint8_t n_addrs;
    uint16_t pad;
};

_Static_assert(sizeof(struct sr_hdr_fixture) == 40, "fixture header ABI mismatch");
_Static_assert(sizeof(struct sr_bucket_fixture) == 48, "fixture bucket ABI mismatch");

#define FIXTURE_BUCKETS 8u
#define FIXTURE_ARENA 4096u
#define EXAMPLE_HASH UINT64_C(0xd6a34bfb57570ef4)

static void fail(const char *message)
{
    fprintf(stderr, "NSS shared-memory test failed: %s (errno=%d)\n", message, errno);
    exit(EXIT_FAILURE);
}

static uint64_t realtime_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0)
        fail("clock_gettime");
    return (uint64_t)now.tv_sec * 1000ULL + (uint64_t)now.tv_nsec / 1000000ULL;
}

int main(void)
{
    char path[] = "/tmp/rustd-resolved-shm.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
        fail("mkstemp");

    const size_t header_size = sizeof(struct sr_hdr_fixture);
    const size_t buckets_size = FIXTURE_BUCKETS * sizeof(struct sr_bucket_fixture);
    const size_t arena_offset = header_size + buckets_size;
    const size_t total = arena_offset + FIXTURE_ARENA;
    if (ftruncate(fd, (off_t)total) != 0)
        fail("ftruncate");

    uint8_t *mapping = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapping == MAP_FAILED)
        fail("mmap");
    memset(mapping, 0, total);

    uint8_t owner[256];
    size_t owner_length = 0;
    if (sr_encode_name("Example.Test.", owner, sizeof owner, &owner_length) != 0)
        fail("sr_encode_name");
    static const uint8_t expected_owner[] = {
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        4, 't', 'e', 's', 't', 0,
    };
    if (owner_length != sizeof expected_owner ||
        memcmp(owner, expected_owner, sizeof expected_owner) != 0)
        fail("wire-name canonicalization");

    struct sr_hdr_fixture *header = (struct sr_hdr_fixture *)(void *)mapping;
    struct sr_bucket_fixture *buckets =
        (struct sr_bucket_fixture *)(void *)(mapping + header_size);
    struct sr_bucket_fixture *bucket = &buckets[EXAMPLE_HASH & (FIXTURE_BUCKETS - 1u)];
    uint8_t *arena = mapping + arena_offset;

    struct sr_shm_addr expected_address;
    memset(&expected_address, 0, sizeof expected_address);
    expected_address.family = 4;
    if (inet_pton(AF_INET, "192.0.2.123", expected_address.addr) != 1)
        fail("inet_pton");

    const size_t entry_length = 1u + owner_length + sizeof expected_address;
    arena[0] = (uint8_t)owner_length;
    memcpy(arena + 1, owner, owner_length);
    memcpy(arena + 1 + owner_length, &expected_address, sizeof expected_address);

    header->magic = SR_SHM_MAGIC;
    header->version = 1;
    header->n_buckets = FIXTURE_BUCKETS;
    header->arena_off = (uint32_t)arena_offset;
    header->arena_size = FIXTURE_ARENA;
    header->write_gen = 2;
    header->arena_used = (uint32_t)entry_length;

    bucket->gen = 2;
    bucket->hash = EXAMPLE_HASH;
    bucket->off = 0;
    bucket->len = (uint32_t)entry_length;
    bucket->expires_ms = realtime_ms() + 60000u;
    bucket->flags = 4u;
    bucket->qtype = 1;
    bucket->qclass = 1;
    bucket->rcode = 0;
    bucket->n_addrs = 1;

    if (msync(mapping, total, MS_SYNC) != 0)
        fail("msync");
    if (setenv("RUSTD_NSS_DNS_SHM", path, 1) != 0)
        fail("setenv");

    struct sr_shm_addr addresses[2];
    size_t address_count = 2;
    uint8_t rcode = 255;
    int secure = 0;
    if (sr_shm_lookup(owner, owner_length, 1, 1, &rcode,
                      addresses, &address_count, &secure) != 0)
        fail("valid fixture lookup");
    if (address_count != 1 || rcode != 0 || secure != 1 ||
        memcmp(&addresses[0], &expected_address, sizeof expected_address) != 0)
        fail("valid fixture contents");

    if (unsetenv("RUSTD_NSS_DNS_SHM") != 0)
        fail("unsetenv");
    address_count = 2;
    errno = 0;
    if (sr_shm_lookup(owner, owner_length, 1, 1, &rcode,
                      addresses, &address_count, &secure) == 0 || errno != ENOENT)
        fail("shared-memory extension was enabled by default");
    if (setenv("RUSTD_NSS_DNS_SHM", path, 1) != 0)
        fail("setenv");

    bucket->expires_ms = realtime_ms() - 1u;
    bucket->flags = 0;
    if (msync(mapping, total, MS_SYNC) != 0)
        fail("msync stale fixture");
    address_count = 2;
    errno = 0;
    if (sr_shm_lookup(owner, owner_length, 1, 1, &rcode,
                      addresses, &address_count, &secure) == 0 || errno != ENOENT)
        fail("expired fixture was accepted");

    bucket->expires_ms = realtime_ms() + 60000u;
    bucket->len = UINT32_MAX;
    if (msync(mapping, total, MS_SYNC) != 0)
        fail("msync corrupt fixture");
    address_count = 2;
    errno = 0;
    if (sr_shm_lookup(owner, owner_length, 1, 1, &rcode,
                      addresses, &address_count, &secure) == 0 || errno != EPROTO)
        fail("out-of-bounds fixture was accepted");

    if (munmap(mapping, total) != 0)
        fail("munmap");
    close(fd);
    unlink(path);
    puts("NSS shared-memory ABI, hash, expiry, and bounds tests passed");
    return EXIT_SUCCESS;
}
