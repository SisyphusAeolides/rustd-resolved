/*
 * iouring_dns.c — batched non-blocking DNS UDP I/O with hardened name walk.
 *
 * Build (Linux):
 *   cc -O3 -fPIC -c iouring_dns.c
 *   cc -shared -o libiouring_dns.so iouring_dns.o -luring
 *
 * Links with rustd-resolved via build.rs / cc crate.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <liburing.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SR_MAX_BATCH        64
#define SR_MAX_PACKET       1232   /* EDNS safe default */
#define SR_MAX_NAME_HOPS    128
#define SR_NAME_WIRE_MAX    255

typedef struct sr_packet {
    uint8_t  data[SR_MAX_PACKET];
    uint16_t len;
    uint16_t peer_port;
    uint32_t peer_addr;     /* IPv4 host order for demo; extend to v6 */
    int      ifindex;
    int      result;        /* 0 ok, -errno on completion error */
} sr_packet;

typedef struct sr_ring {
    struct io_uring ring;
    int             fd;           /* UDP socket */
    sr_packet      *rx;           /* caller-owned array */
    sr_packet      *tx;
    unsigned        rx_cap;
    unsigned        tx_cap;
    bool            registered;
} sr_ring;

/* ---- Name walk: rejects cycles, OOB, overlong labels, overlong names ---- */

typedef enum {
    SR_NAME_OK = 0,
    SR_NAME_OOB = 1,
    SR_NAME_BAD_LABEL = 2,
    SR_NAME_CYCLE = 3,
    SR_NAME_HOP_LIMIT = 4,
    SR_NAME_TOO_LONG = 5,
    SR_NAME_PTR = 6
} sr_name_err;

static inline int sr_bit_test(uint64_t *bm, unsigned bit)
{
    return (bm[bit >> 6] >> (bit & 63)) & 1ULL;
}

static inline void sr_bit_set(uint64_t *bm, unsigned bit)
{
    bm[bit >> 6] |= 1ULL << (bit & 63);
}

/*
 * Walk name at *off. On success, *off is first byte after the name
 * (compression: advanced only past the first pointer).
 * If out != NULL and out_cap > 0, writes lowercased uncompressed form.
 */
int sr_dns_name_walk(const uint8_t *msg, size_t msg_len, size_t *off,
                     uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t o = *off;
    size_t hops = 0;
    size_t nlen = 0;
    int jumped = 0;
    size_t return_off = 0;
    /* bitmap for 512-byte granules up to 64k message */
    uint64_t seen[1024 / 64];
    memset(seen, 0, sizeof seen);

    if (out_len) *out_len = 0;

    for (;;) {
        if (o >= msg_len)
            return SR_NAME_OOB;
        if (hops++ > SR_MAX_NAME_HOPS)
            return SR_NAME_HOP_LIMIT;
        if (o < 65536u && sr_bit_test(seen, (unsigned)o))
            return SR_NAME_CYCLE;
        if (o < 65536u)
            sr_bit_set(seen, (unsigned)o);

        uint8_t lab = msg[o];
        if (lab == 0) {
            if (out && nlen < out_cap)
                out[nlen++] = 0;
            else if (out)
                return SR_NAME_TOO_LONG;
            nlen += (out ? 0 : 1);
            if (!jumped)
                *off = o + 1;
            else
                *off = return_off;
            if (out_len) *out_len = nlen;
            if (nlen > SR_NAME_WIRE_MAX)
                return SR_NAME_TOO_LONG;
            return SR_NAME_OK;
        }

        if ((lab & 0xC0) == 0xC0) {
            if (o + 1 >= msg_len)
                return SR_NAME_OOB;
            uint16_t ptr = ((uint16_t)(lab & 0x3F) << 8) | msg[o + 1];
            if ((size_t)ptr >= msg_len)
                return SR_NAME_OOB;
            if (!jumped) {
                return_off = o + 2;
                jumped = 1;
            }
            o = ptr;
            continue;
        }

        if ((lab & 0xC0) != 0)
            return SR_NAME_BAD_LABEL; /* 10/01 reserved */
        if (lab > 63)
            return SR_NAME_BAD_LABEL;
        if (o + 1 + lab >= msg_len)
            return SR_NAME_OOB;
        if (nlen + 1 + lab + 1 > SR_NAME_WIRE_MAX)
            return SR_NAME_TOO_LONG;

        if (out) {
            if (nlen + 1 + lab >= out_cap)
                return SR_NAME_TOO_LONG;
            out[nlen++] = lab;
            for (uint8_t i = 0; i < lab; i++) {
                uint8_t c = msg[o + 1 + i];
                if (c >= 'A' && c <= 'Z')
                    c = (uint8_t)(c + 32);
                out[nlen++] = c;
            }
        } else {
            nlen += 1u + lab;
        }
        o += 1u + lab;
    }
}

/* ---- io_uring batch RX/TX ---- */

int sr_ring_init(sr_ring *r, int fd, unsigned qd)
{
    memset(r, 0, sizeof *r);
    r->fd = fd;
    if (qd < 8)
        qd = 8;
    if (qd > 4096)
        qd = 4096;
    int rc = io_uring_queue_init((unsigned)qd, &r->ring, 0);
    if (rc < 0)
        return rc;
    r->registered = true;
    return 0;
}

void sr_ring_destroy(sr_ring *r)
{
    if (r->registered) {
        io_uring_queue_exit(&r->ring);
        r->registered = false;
    }
}

static void prep_recv(sr_ring *r, sr_packet *p, unsigned user_idx)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&r->ring);
    if (!sqe)
        return;
    struct iovec iov = { .iov_base = p->data, .iov_len = sizeof p->data };
    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    /* For production: store sockaddr + msghdr in side array; simplified here. */
    io_uring_prep_recv(sqe, r->fd, p->data, sizeof p->data, 0);
    sqe->user_data = ((uint64_t)1 << 63) | user_idx;
    (void)iov;
    (void)msg;
}

static void prep_send(sr_ring *r, sr_packet *p, unsigned user_idx)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&r->ring);
    if (!sqe)
        return;
    io_uring_prep_send(sqe, r->fd, p->data, p->len, 0);
    sqe->user_data = user_idx;
}

/*
 * Submit up to tx_n sends and arm rx_n recvs. Returns submitted SQEs.
 * Completions drained into packets' .len/.result.
 */
int sr_ring_submit_batch(sr_ring *r,
                         sr_packet *tx, unsigned tx_n,
                         sr_packet *rx, unsigned rx_n)
{
    if (!r || !r->registered)
        return -EINVAL;
    unsigned sub = 0;
    for (unsigned i = 0; i < tx_n; i++) {
        if (tx[i].len == 0 || tx[i].len > SR_MAX_PACKET)
            continue;
        prep_send(r, &tx[i], i);
        sub++;
    }
    for (unsigned i = 0; i < rx_n; i++) {
        rx[i].len = 0;
        rx[i].result = 0;
        prep_recv(r, &rx[i], i);
        sub++;
    }
    if (sub == 0)
        return 0;
    int rc = io_uring_submit(&r->ring);
    return rc < 0 ? rc : (int)sub;
}

/* Non-blocking completion harvest. Returns number of CQEs handled. */
int sr_ring_reap(sr_ring *r, sr_packet *tx, unsigned tx_n,
                 sr_packet *rx, unsigned rx_n, unsigned max_cqe)
{
    unsigned got = 0;
    while (got < max_cqe) {
        struct io_uring_cqe *cqe;
        int rc = io_uring_peek_cqe(&r->ring, &cqe);
        if (rc < 0)
            break;
        uint64_t ud = cqe->user_data;
        int res = cqe->res;
        int is_rx = (ud >> 63) & 1;
        unsigned idx = (unsigned)(ud & 0xffffffffu);
        if (is_rx) {
            if (idx < rx_n) {
                if (res > 0) {
                    rx[idx].len = (uint16_t)((res > SR_MAX_PACKET) ? SR_MAX_PACKET : res);
                    rx[idx].result = 0;
                } else {
                    rx[idx].len = 0;
                    rx[idx].result = res;
                }
            }
        } else {
            if (idx < tx_n)
                tx[idx].result = res;
        }
        io_uring_cqe_seen(&r->ring, cqe);
        got++;
    }
    return (int)got;
}

/*
 * Quick header sanity: QR/opcode/qdcount bounds before full parse.
 * Returns 0 if plausible query or response.
 */
int sr_dns_header_precheck(const uint8_t *pkt, size_t len, int expect_response)
{
    if (len < 12)
        return -EINVAL;
    uint8_t flags0 = pkt[2];
    int qr = (flags0 >> 7) & 1;
    int opcode = (flags0 >> 3) & 0xF;
    if (opcode != 0)
        return -EPROTONOSUPPORT;
    if (expect_response && !qr)
        return -EINVAL;
    if (!expect_response && qr)
        return -EINVAL;
    uint16_t qd = ((uint16_t)pkt[4] << 8) | pkt[5];
    uint16_t an = ((uint16_t)pkt[6] << 8) | pkt[7];
    uint16_t ns = ((uint16_t)pkt[8] << 8) | pkt[9];
    uint16_t ar = ((uint16_t)pkt[10] << 8) | pkt[11];
    /* Absurd RR counts relative to packet size */
    uint32_t total = (uint32_t)qd + an + ns + ar;
    if (total > 4096)
        return -E2BIG;
    if (qd == 0 && !expect_response)
        return -EINVAL;
    size_t off = 12;
    if (qd) {
        int nerr = sr_dns_name_walk(pkt, len, &off, NULL, 0, NULL);
        if (nerr != SR_NAME_OK)
            return -EBADMSG;
        if (off + 4 > len)
            return -EBADMSG;
    }
    return 0;
}

/* FFI-visible: validate question name and produce cache key bytes. */
int sr_extract_question_owner(const uint8_t *pkt, size_t len,
                              uint8_t *owner_out, size_t owner_cap,
                              size_t *owner_len, uint16_t *qtype, uint16_t *qclass)
{
    if (!pkt || len < 12 || !owner_out || !owner_len || !qtype || !qclass)
        return -EINVAL;
    int pr = sr_dns_header_precheck(pkt, len, 0);
    if (pr < 0)
        return pr;
    size_t off = 12;
    size_t ol = 0;
    int nerr = sr_dns_name_walk(pkt, len, &off, owner_out, owner_cap, &ol);
    if (nerr != SR_NAME_OK)
        return -EBADMSG;
    if (off + 4 > len)
        return -EBADMSG;
    *owner_len = ol;
    *qtype  = (uint16_t)((pkt[off] << 8) | pkt[off + 1]);
    *qclass = (uint16_t)((pkt[off + 2] << 8) | pkt[off + 3]);
    return 0;
}
