#ifndef NSS_RESOLVE_SHM_H
#define NSS_RESOLVE_SHM_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SR_SHM_PATH "/dev/shm/rustd-resolved-l1"
#define SR_SHM_MAGIC 0x52534C314E535301ULL

#define SR_RESOLVED_NO_VALIDATE (UINT64_C(1) << 10)
#define SR_RESOLVED_NO_SYNTHESIZE (UINT64_C(1) << 11)
#define SR_RESOLVED_NO_CACHE (UINT64_C(1) << 12)
#define SR_RESOLVED_NO_ZONE (UINT64_C(1) << 13)
#define SR_RESOLVED_NO_TRUST_ANCHOR (UINT64_C(1) << 14)
#define SR_RESOLVED_NO_NETWORK (UINT64_C(1) << 15)

struct sr_shm_addr {
    uint8_t family;     /* 4 or 6 */
    uint8_t pad;
    uint16_t scope_id;
    uint8_t addr[16];
};

struct sr_resolved_addr {
    uint8_t family;     /* 4 or 6 */
    uint32_t scope_id;
    uint8_t addr[16];
};

/*
 * Lookup owner wire name (lowercase absolute) in shared cache.
 * Returns 0 on hit, -1 on miss/error.
 * *n_io is in/out capacity/count of addrs.
 */
int sr_shm_lookup(const uint8_t *owner, size_t owner_len,
                  uint16_t qtype, uint16_t qclass,
                  uint8_t *rcode_out,
                  struct sr_shm_addr *addrs, size_t *n_io,
                  int *secure_out);

/* Encode presentation name to wire lowercase absolute. */
int sr_encode_name(const char *name, uint8_t *out, size_t cap, size_t *out_len);

/* Miss paths: prefer io.rustd.Resolve Varlink, then use the local DNS stub. */
int sr_stub_resolve_hostname(const char *name,
                             char out[][64], int max, int *n_out,
                             char canonical[256]);
int sr_stub_resolve_address(const void *address, socklen_t length, int family,
                            char out[][256], int max, int *n_out);
uint64_t sr_nss_query_flags(void);
int sr_nss_query_ifindex(void);
int sr_varlink_resolve_hostname(const char *name, int family,
                                uint64_t flags, int ifindex,
                                struct sr_resolved_addr **out, size_t *n_out,
                                char canonical[256]);
int sr_varlink_resolve_address(const void *address, socklen_t length, int family,
                               uint64_t flags, int ifindex,
                               char (**out)[256], size_t *n_out);

#ifdef __cplusplus
}
#endif
#endif
