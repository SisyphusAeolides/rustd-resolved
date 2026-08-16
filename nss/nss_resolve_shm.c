#define _GNU_SOURCE
#include "nss_resolve_shm.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct sr_hdr {
    uint64_t magic;
    uint32_t version;
    uint32_t n_buckets;
    uint32_t arena_off;
    uint32_t arena_size;
    uint64_t write_gen;
    uint32_t arena_used;
    uint32_t pad;
};

struct sr_bucket {
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

_Static_assert(sizeof(struct sr_hdr) == 40, "unexpected shared-memory header layout");
_Static_assert(sizeof(struct sr_bucket) == 48, "unexpected shared-memory bucket layout");

static uint64_t hash_key(const uint8_t *owner, size_t owner_length,
                         uint16_t qtype, uint16_t qclass)
{
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < owner_length; i++) {
        hash ^= owner[i];
        hash *= 0x100000001b3ULL;
    }
    hash ^= ((uint64_t)qtype) << 16;
    hash *= 0x100000001b3ULL;
    hash ^= qclass;
    hash ^= hash >> 33;
    hash *= 0xff51afd7ed558ccdULL;
    hash ^= hash >> 33;
    return hash;
}

static uint64_t now_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0)
        return 0;
    return (uint64_t)now.tv_sec * 1000ULL + (uint64_t)now.tv_nsec / 1000000ULL;
}

static int range_valid(uint64_t offset, uint64_t length, size_t total)
{
    return offset <= total && length <= (uint64_t)total - offset;
}

static int multiply_u64(uint64_t left, uint64_t right, uint64_t *result)
{
    if (left != 0 && right > UINT64_MAX / left)
        return -1;
    *result = left * right;
    return 0;
}

static const char *shared_memory_path(void)
{
    const char *value = secure_getenv("RUSTD_NSS_RESOLVE_SHM");
    if (!value || !*value) {
        errno = ENOENT;
        return NULL;
    }
    if (strcmp(value, "0") == 0 || strcasecmp(value, "no") == 0 ||
        strcasecmp(value, "false") == 0 || strcasecmp(value, "off") == 0) {
        errno = ENOENT;
        return NULL;
    }
    return value;
}

static int load_header(const struct sr_hdr *mapped, struct sr_hdr *copy)
{
    for (unsigned attempt = 0; attempt < 4; attempt++) {
        uint64_t before = __atomic_load_n(&mapped->write_gen, __ATOMIC_ACQUIRE);
        memcpy(copy, mapped, sizeof *copy);
        uint64_t after = __atomic_load_n(&mapped->write_gen, __ATOMIC_ACQUIRE);
        if (before == after && before == copy->write_gen)
            return 0;
    }
    errno = EAGAIN;
    return -1;
}

static int load_bucket(const struct sr_bucket *mapped, struct sr_bucket *copy)
{
    for (unsigned attempt = 0; attempt < 4; attempt++) {
        uint64_t before = __atomic_load_n(&mapped->gen, __ATOMIC_ACQUIRE);
        memcpy(copy, mapped, sizeof *copy);
        uint64_t after = __atomic_load_n(&mapped->gen, __ATOMIC_ACQUIRE);
        if (before == after && before == copy->gen)
            return 0;
    }
    errno = EAGAIN;
    return -1;
}

static int bucket_is_fresh(const struct sr_bucket *bucket, uint64_t now)
{
    if (now <= bucket->expires_ms)
        return 1;
    if ((bucket->flags & 1u) == 0)
        return 0;
    return now - bucket->expires_ms <= 30000ULL;
}

int sr_encode_name(const char *name, uint8_t *out, size_t capacity, size_t *out_length)
{
    if (!name || !*name || !out || !out_length || capacity == 0)
        return -1;
    if (strcmp(name, ".") == 0) {
        out[0] = 0;
        *out_length = 1;
        return 0;
    }

    size_t output = 0;
    const char *cursor = name;
    while (*cursor) {
        const char *dot = strchr(cursor, '.');
        size_t label_length = dot ? (size_t)(dot - cursor) : strlen(cursor);
        if (label_length == 0 || label_length > 63 ||
            output + 1 + label_length + 1 > capacity ||
            output + 1 + label_length + 1 > 255)
            return -1;

        out[output++] = (uint8_t)label_length;
        for (size_t i = 0; i < label_length; i++) {
            unsigned char byte = (unsigned char)cursor[i];
            out[output++] = byte >= 'A' && byte <= 'Z'
                                ? (uint8_t)(byte + ('a' - 'A'))
                                : byte;
        }

        if (!dot)
            break;
        cursor = dot + 1;
        if (*cursor == '\0')
            break;
    }

    if (output + 1 > capacity || output + 1 > 255)
        return -1;
    out[output++] = 0;
    *out_length = output;
    return 0;
}

int sr_shm_lookup(const uint8_t *owner, size_t owner_length,
                  uint16_t qtype, uint16_t qclass,
                  uint8_t *rcode_out,
                  struct sr_shm_addr *addrs, size_t *n_io,
                  int *secure_out)
{
    if (!owner || owner_length == 0 || owner_length > 255 ||
        !rcode_out || !addrs || !n_io) {
        errno = EINVAL;
        return -1;
    }

    const char *path = shared_memory_path();
    if (!path)
        return -1;

    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;

    struct stat status;
    if (fstat(fd, &status) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    if (!S_ISREG(status.st_mode) || status.st_size < (off_t)sizeof(struct sr_hdr) ||
        (uintmax_t)status.st_size > SIZE_MAX) {
        close(fd);
        errno = EPROTO;
        return -1;
    }

    size_t mapping_length = (size_t)status.st_size;
    void *mapping = mmap(NULL, mapping_length, PROT_READ, MAP_SHARED, fd, 0);
    int saved = errno;
    close(fd);
    if (mapping == MAP_FAILED) {
        errno = saved;
        return -1;
    }

    int result = -1;
    const uint8_t *base = mapping;
    struct sr_hdr header;
    if (load_header((const struct sr_hdr *)mapping, &header) < 0)
        goto finish;

    if (header.magic != SR_SHM_MAGIC || header.version != 1 ||
        header.n_buckets == 0 || (header.n_buckets & (header.n_buckets - 1u)) != 0) {
        errno = EPROTO;
        goto finish;
    }

    uint64_t bucket_bytes = 0;
    if (multiply_u64(header.n_buckets, sizeof(struct sr_bucket), &bucket_bytes) < 0 ||
        !range_valid(sizeof(struct sr_hdr), bucket_bytes, mapping_length) ||
        header.arena_off < sizeof(struct sr_hdr) + bucket_bytes ||
        !range_valid(header.arena_off, header.arena_size, mapping_length) ||
        header.arena_used > header.arena_size) {
        errno = EPROTO;
        goto finish;
    }

    uint64_t hash = hash_key(owner, owner_length, qtype, qclass);
    size_t index = (size_t)hash & ((size_t)header.n_buckets - 1u);
    const struct sr_bucket *buckets =
        (const struct sr_bucket *)(const void *)(base + sizeof(struct sr_hdr));
    struct sr_bucket bucket;
    if (load_bucket(&buckets[index], &bucket) < 0)
        goto finish;

    if (bucket.gen == 0 || bucket.hash != hash ||
        bucket.qtype != qtype || bucket.qclass != qclass ||
        !bucket_is_fresh(&bucket, now_ms())) {
        errno = ENOENT;
        goto finish;
    }

    if (bucket.off > header.arena_used || bucket.len > header.arena_used - bucket.off ||
        !range_valid((uint64_t)header.arena_off + bucket.off, bucket.len, mapping_length)) {
        errno = EPROTO;
        goto finish;
    }

    size_t address_bytes = (size_t)bucket.n_addrs * sizeof(struct sr_shm_addr);
    size_t minimum_length = 1u + owner_length;
    if (minimum_length > SIZE_MAX - address_bytes)
        goto protocol_error;
    minimum_length += address_bytes;
    if (bucket.len < minimum_length)
        goto protocol_error;

    const uint8_t *slot = base + header.arena_off + bucket.off;
    if (slot[0] != (uint8_t)owner_length ||
        memcmp(slot + 1, owner, owner_length) != 0) {
        errno = ENOENT;
        goto finish;
    }

    size_t capacity = *n_io;
    size_t copy_count = bucket.n_addrs < capacity ? bucket.n_addrs : capacity;
    const uint8_t *addresses = slot + 1 + owner_length;
    for (size_t i = 0; i < copy_count; i++)
        memcpy(&addrs[i], addresses + i * sizeof(struct sr_shm_addr),
               sizeof(struct sr_shm_addr));

    struct sr_bucket verification;
    if (load_bucket(&buckets[index], &verification) < 0)
        goto finish;
    if (verification.gen != bucket.gen || verification.hash != bucket.hash ||
        verification.off != bucket.off || verification.len != bucket.len) {
        errno = EAGAIN;
        goto finish;
    }

    *n_io = copy_count;
    *rcode_out = bucket.rcode;
    if (secure_out)
        *secure_out = (bucket.flags & 4u) != 0;
    result = 0;
    goto finish;

protocol_error:
    errno = EPROTO;

finish:
    saved = errno;
    munmap(mapping, mapping_length);
    errno = saved;
    return result;
}
