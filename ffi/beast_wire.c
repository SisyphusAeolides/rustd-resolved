/*
 * beast_wire.c — Einstein-tier DNS wire firewall for rustd-resolved
 *
 * - AVX2/NEON-friendly ASCII lower + label scan
 * - Strict name compression graph validation (cycle-free DAG)
 * - Multi-message recvmmsg/sendmmsg batch path
 * - Query fingerprinting (0x20 bit encoding ready)
 * - OPT/EDNS bounds + cookie presence checks
 *
 * cc -O3 -fPIC -shared -o libbeast_wire.so beast_wire.c
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __AVX2__
#include <immintrin.h>
#endif

#define BW_MAX_NAME        255
#define BW_MAX_LABEL       63
#define BW_MAX_HOPS        128
#define BW_MAX_RR          4096
#define BW_MAX_PACKET      65535
#define BW_HEADER          12

/* ─── Error codes (stable ABI) ─── */
enum {
    BW_OK = 0,
    BW_E_SHORT = -1,
    BW_E_OPCODE = -2,
    BW_E_QDCOUNT = -3,
    BW_E_NAME = -4,
    BW_E_CYCLE = -5,
    BW_E_HOPS = -6,
    BW_E_RR = -7,
    BW_E_OPT = -8,
    BW_E_RDLEN = -9,
    BW_E_FORM = -10,
    BW_E_LIMIT = -11
};

typedef struct bw_name_info {
    uint8_t  uncompressed[BW_MAX_NAME];
    uint16_t ulen;
    uint16_t next_off;
    uint8_t  label_count;
    uint8_t  had_compression;
} bw_name_info;

typedef struct bw_question {
    bw_name_info name;
    uint16_t qtype;
    uint16_t qclass;
} bw_question;

typedef struct bw_opt_info {
    int      present;
    uint16_t udp_payload;
    uint8_t  ext_rcode;
    uint8_t  version;
    uint16_t flags;      /* DO etc */
    int      has_cookie;
    uint8_t  cookie[40];
    uint8_t  cookie_len;
} bw_opt_info;

typedef struct bw_report {
    int          err;
    int          qr;
    int          aa;
    int          tc;
    int          rd;
    int          ra;
    int          ad;
    int          cd;
    uint8_t      opcode;
    uint8_t      rcode;
    uint16_t     id;
    uint16_t     qdcount, ancount, nscount, arcount;
    bw_question  q0;
    bw_opt_info  opt;
    uint32_t     min_ttl;
    uint32_t     rr_scanned;
} bw_report;

/* ─── Bitmap for cycle detection (64k bits) ─── */
typedef struct {
    uint64_t w[1024];
} bw_bitset;

static inline void bw_bs_clear(bw_bitset *b) { memset(b, 0, sizeof *b); }
static inline int  bw_bs_test(const bw_bitset *b, unsigned i) {
    return (int)((b->w[i >> 6] >> (i & 63)) & 1ULL);
}
static inline void bw_bs_set(bw_bitset *b, unsigned i) {
    b->w[i >> 6] |= 1ULL << (i & 63);
}

/* ─── SIMD ASCII lower for contiguous label payload ─── */
void bw_ascii_lower(uint8_t *dst, const uint8_t *src, size_t n)
{
#if defined(__AVX2__)
    size_t i = 0;
    const __m256i A = _mm256_set1_epi8('A');
    const __m256i Z = _mm256_set1_epi8('Z');
    const __m256i thirtytwo = _mm256_set1_epi8(32);
    for (; i + 32 <= n; i += 32) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(src + i));
        __m256i geA = _mm256_cmpgt_epi8(v, _mm256_sub_epi8(A, _mm256_set1_epi8(1)));
        __m256i leZ = _mm256_cmpgt_epi8(_mm256_add_epi8(Z, _mm256_set1_epi8(1)), v);
        __m256i is_upper = _mm256_and_si256(geA, leZ);
        v = _mm256_or_si256(v, _mm256_and_si256(is_upper, thirtytwo));
        /* fix: uppercase OR 0x20 lowercases ASCII */
        _mm256_storeu_si256((__m256i *)(dst + i), v);
    }
    for (; i < n; i++) {
        uint8_t c = src[i];
        dst[i] = (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c;
    }
#else
    for (size_t i = 0; i < n; i++) {
        uint8_t c = src[i];
        dst[i] = (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c;
    }
#endif
}

/* ─── Hardened name walk ─── */
int bw_name_walk(const uint8_t *msg, size_t len, size_t off, bw_name_info *out)
{
    if (!msg || !out || off >= len) return BW_E_NAME;
    memset(out, 0, sizeof *out);
    bw_bitset seen;
    bw_bs_clear(&seen);
    size_t o = off;
    size_t hops = 0;
    int jumped = 0;
    size_t ret_off = 0;
    size_t nlen = 0;

    for (;;) {
        if (o >= len) return BW_E_NAME;
        if (hops++ > BW_MAX_HOPS) return BW_E_HOPS;
        if (o < 65536u) {
            if (bw_bs_test(&seen, (unsigned)o)) return BW_E_CYCLE;
            bw_bs_set(&seen, (unsigned)o);
        }
        uint8_t lab = msg[o];
        if (lab == 0) {
            if (nlen + 1 > BW_MAX_NAME) return BW_E_NAME;
            out->uncompressed[nlen++] = 0;
            out->ulen = (uint16_t)nlen;
            out->next_off = (uint16_t)(jumped ? ret_off : (o + 1));
            return BW_OK;
        }
        if ((lab & 0xC0) == 0xC0) {
            if (o + 1 >= len) return BW_E_NAME;
            uint16_t ptr = (uint16_t)(((lab & 0x3F) << 8) | msg[o + 1]);
            if ((size_t)ptr >= len) return BW_E_NAME;
            out->had_compression = 1;
            if (!jumped) {
                ret_off = o + 2;
                jumped = 1;
            }
            o = ptr;
            continue;
        }
        if ((lab & 0xC0) != 0) return BW_E_NAME;
        if (lab > BW_MAX_LABEL) return BW_E_NAME;
        if (o + 1 + lab >= len) return BW_E_NAME;
        if (nlen + 1 + lab + 1 > BW_MAX_NAME) return BW_E_NAME;
        out->uncompressed[nlen++] = lab;
        bw_ascii_lower(out->uncompressed + nlen, msg + o + 1, lab);
        nlen += lab;
        out->label_count++;
        o += 1u + lab;
    }
}

/* ─── Full packet audit ─── */
int bw_audit_packet(const uint8_t *pkt, size_t len, int expect_qr, bw_report *r)
{
    if (!pkt || !r) return BW_E_FORM;
    memset(r, 0, sizeof *r);
    r->min_ttl = UINT32_MAX;
    if (len < BW_HEADER) { r->err = BW_E_SHORT; return r->err; }

    r->id = (uint16_t)((pkt[0] << 8) | pkt[1]);
    uint16_t flags = (uint16_t)((pkt[2] << 8) | pkt[3]);
    r->qr = (flags >> 15) & 1;
    r->opcode = (flags >> 11) & 0xF;
    r->aa = (flags >> 10) & 1;
    r->tc = (flags >> 9) & 1;
    r->rd = (flags >> 8) & 1;
    r->ra = (flags >> 7) & 1;
    r->ad = (flags >> 5) & 1;
    r->cd = (flags >> 4) & 1;
    r->rcode = flags & 0xF;
    r->qdcount = (uint16_t)((pkt[4] << 8) | pkt[5]);
    r->ancount = (uint16_t)((pkt[6] << 8) | pkt[7]);
    r->nscount = (uint16_t)((pkt[8] << 8) | pkt[9]);
    r->arcount = (uint16_t)((pkt[10] << 8) | pkt[11]);

    if (expect_qr >= 0 && r->qr != expect_qr) { r->err = BW_E_FORM; return r->err; }
    if (r->opcode != 0 && r->opcode != 4 /* notify */ && r->opcode != 5 /* update */) {
        /* allow QUERY primarily */
        if (r->opcode != 0) { r->err = BW_E_OPCODE; return r->err; }
    }

    uint32_t total_rr = (uint32_t)r->qdcount + r->ancount + r->nscount + r->arcount;
    if (total_rr > BW_MAX_RR) { r->err = BW_E_LIMIT; return r->err; }
    if (!r->qr && r->qdcount == 0) { r->err = BW_E_QDCOUNT; return r->err; }

    size_t off = BW_HEADER;

    /* questions */
    for (uint16_t qi = 0; qi < r->qdcount; qi++) {
        bw_name_info ni;
        int e = bw_name_walk(pkt, len, off, &ni);
        if (e != BW_OK) { r->err = e; return e; }
        off = ni.next_off;
        if (off + 4 > len) { r->err = BW_E_SHORT; return r->err; }
        uint16_t qt = (uint16_t)((pkt[off] << 8) | pkt[off + 1]);
        uint16_t qc = (uint16_t)((pkt[off + 2] << 8) | pkt[off + 3]);
        off += 4;
        if (qi == 0) {
            r->q0.name = ni;
            r->q0.qtype = qt;
            r->q0.qclass = qc;
        }
    }

    uint32_t rr_remaining = (uint32_t)r->ancount + r->nscount + r->arcount;
    for (uint32_t ri = 0; ri < rr_remaining; ri++) {
        bw_name_info ni;
        int e = bw_name_walk(pkt, len, off, &ni);
        if (e != BW_OK) { r->err = e; return e; }
        off = ni.next_off;
        if (off + 10 > len) { r->err = BW_E_RR; return r->err; }
        uint16_t typ = (uint16_t)((pkt[off] << 8) | pkt[off + 1]);
        uint16_t cls = (uint16_t)((pkt[off + 2] << 8) | pkt[off + 3]);
        uint32_t ttl = ((uint32_t)pkt[off + 4] << 24) | ((uint32_t)pkt[off + 5] << 16) |
                       ((uint32_t)pkt[off + 6] << 8) | (uint32_t)pkt[off + 7];
        uint16_t rdlen = (uint16_t)((pkt[off + 8] << 8) | pkt[off + 9]);
        off += 10;
        if (off + rdlen > len) { r->err = BW_E_RDLEN; return r->err; }

        if (typ != 41 /* OPT */) {
            if (ttl < r->min_ttl) r->min_ttl = ttl;
        } else {
            /* OPT: class = udp payload, ttl = ext-rcode|version|flags */
            r->opt.present = 1;
            r->opt.udp_payload = cls;
            r->opt.ext_rcode = (uint8_t)((ttl >> 24) & 0xFF);
            r->opt.version = (uint8_t)((ttl >> 16) & 0xFF);
            r->opt.flags = (uint16_t)(ttl & 0xFFFF);
            if (r->opt.version != 0) { r->err = BW_E_OPT; return r->err; }
            /* parse options for COOKIE (code 10) */
            size_t ooff = off;
            size_t oend = off + rdlen;
            while (ooff + 4 <= oend) {
                uint16_t code = (uint16_t)((pkt[ooff] << 8) | pkt[ooff + 1]);
                uint16_t olen = (uint16_t)((pkt[ooff + 2] << 8) | pkt[ooff + 3]);
                ooff += 4;
                if (ooff + olen > oend) { r->err = BW_E_OPT; return r->err; }
                if (code == 10 && olen <= 40) {
                    r->opt.has_cookie = 1;
                    r->opt.cookie_len = (uint8_t)olen;
                    memcpy(r->opt.cookie, pkt + ooff, olen);
                }
                ooff += olen;
            }
        }

        /* lightweight RDATA name checks for NS/CNAME/PTR/MX/SOA first name */
        if (typ == 2 || typ == 5 || typ == 12 || typ == 15 || typ == 6) {
            size_t ro = off;
            if (typ == 15) { /* MX preference */
                if (rdlen < 3) { r->err = BW_E_RDLEN; return r->err; }
                ro = off + 2;
            }
            bw_name_info dummy;
            e = bw_name_walk(pkt, off + rdlen, ro - off > len ? off : ro, &dummy);
            /* walk within full message for compression — use full len */
            e = bw_name_walk(pkt, len, ro, &dummy);
            if (e != BW_OK) { r->err = e; return e; }
        }

        off += rdlen;
        r->rr_scanned++;
    }

    if (r->min_ttl == UINT32_MAX) r->min_ttl = 0;
    r->err = BW_OK;
    return BW_OK;
}

/* ─── 0x20 encoding: randomize query name case for anti-poison ─── */
int bw_apply_0x20(uint8_t *pkt, size_t len, uint64_t seed)
{
    bw_report r;
    if (bw_audit_packet(pkt, len, 0, &r) != BW_OK) return BW_E_FORM;
    /* find first question name on wire (not uncompressed) */
    size_t off = BW_HEADER;
    uint64_t s = seed ? seed : ((uint64_t)time(NULL) << 32) ^ (uint64_t)(uintptr_t)pkt;
    size_t o = off;
    while (o < len) {
        uint8_t lab = pkt[o];
        if (lab == 0) break;
        if ((lab & 0xC0) == 0xC0) break; /* shouldn't compress in query we build */
        if (lab > BW_MAX_LABEL || o + 1 + lab >= len) return BW_E_NAME;
        for (uint8_t i = 0; i < lab; i++) {
            uint8_t *c = &pkt[o + 1 + i];
            if ((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z')) {
                s ^= s << 13; s ^= s >> 7; s ^= s << 17;
                if (s & 1ULL) *c ^= 0x20;
            }
        }
        o += 1u + lab;
    }
    return BW_OK;
}

/* Verify response name case matches 0x20 query pattern */
int bw_check_0x20(const uint8_t *query, size_t qlen,
                  const uint8_t *resp, size_t rlen)
{
    bw_name_info qn, rn;
    if (qlen < BW_HEADER || rlen < BW_HEADER) return BW_E_SHORT;
    if (bw_name_walk(query, qlen, BW_HEADER, &qn) != BW_OK) return BW_E_NAME;
    if (bw_name_walk(resp, rlen, BW_HEADER, &rn) != BW_OK) return BW_E_NAME;
    /* Compare case-sensitive on original wire labels of first question —
       for full 0x20 walk original query bytes vs response question bytes. */
    size_t qo = BW_HEADER, ro = BW_HEADER;
    while (qo < qlen && ro < rlen) {
        uint8_t ql = query[qo], rl = resp[ro];
        if (ql == 0 && rl == 0) return BW_OK;
        if (ql != rl) return BW_E_FORM;
        if ((ql & 0xC0) != 0) return BW_OK; /* stop */
        if (qo + 1 + ql > qlen || ro + 1 + rl > rlen) return BW_E_NAME;
        if (memcmp(query + qo + 1, resp + ro + 1, ql) != 0) return BW_E_FORM;
        qo += 1u + ql;
        ro += 1u + rl;
    }
    return BW_E_FORM;
}

/* ─── mmsg batch I/O ─── */
typedef struct bw_mmsg_slot {
    uint8_t            buf[1232];
    struct sockaddr_in addr;
    struct iovec       iov;
    struct mmsghdr     msg;
    int                result_len;
} bw_mmsg_slot;

int bw_recvmmsg_batch(int fd, bw_mmsg_slot *slots, unsigned n, int flags)
{
    if (!slots || n == 0) return -EINVAL;
    for (unsigned i = 0; i < n; i++) {
        memset(&slots[i].msg, 0, sizeof slots[i].msg);
        slots[i].iov.iov_base = slots[i].buf;
        slots[i].iov.iov_len = sizeof slots[i].buf;
        slots[i].msg.msg_hdr.msg_iov = &slots[i].iov;
        slots[i].msg.msg_hdr.msg_iovlen = 1;
        slots[i].msg.msg_hdr.msg_name = &slots[i].addr;
        slots[i].msg.msg_hdr.msg_namelen = sizeof slots[i].addr;
        slots[i].result_len = 0;
    }
    struct mmsghdr hdrs[64];
    if (n > 64) n = 64;
    for (unsigned i = 0; i < n; i++) hdrs[i] = slots[i].msg;
    int rc = recvmmsg(fd, hdrs, n, flags, NULL);
    if (rc < 0) return -errno;
    for (int i = 0; i < rc; i++) {
        slots[i].msg = hdrs[i];
        slots[i].result_len = (int)hdrs[i].msg_len;
    }
    return rc;
}

int bw_sendmmsg_batch(int fd, bw_mmsg_slot *slots, unsigned n, int flags)
{
    if (!slots || n == 0) return -EINVAL;
    if (n > 64) n = 64;
    struct mmsghdr hdrs[64];
    for (unsigned i = 0; i < n; i++) {
        memset(&hdrs[i], 0, sizeof hdrs[i]);
        slots[i].iov.iov_base = slots[i].buf;
        slots[i].iov.iov_len = (size_t)slots[i].result_len;
        hdrs[i].msg_hdr.msg_iov = &slots[i].iov;
        hdrs[i].msg_hdr.msg_iovlen = 1;
        hdrs[i].msg_hdr.msg_name = &slots[i].addr;
        hdrs[i].msg_hdr.msg_namelen = sizeof slots[i].addr;
    }
    int rc = sendmmsg(fd, hdrs, n, flags);
    return rc < 0 ? -errno : rc;
}

/* ─── FNV-1a name hash matching Rust side ─── */
uint64_t bw_name_hash64(const uint8_t *wire, size_t len)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= wire[i];
        h *= 0x100000001b3ULL;
    }
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}
