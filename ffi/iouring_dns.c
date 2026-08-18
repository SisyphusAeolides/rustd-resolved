/*
 * iouring_dns.c — batched non-blocking DNS UDP I/O with hardened name walk.
 *
 * Build (Linux):
 *   cc -O3 -fPIC -c iouring_dns.c
 *   cc -shared -o libiouring_dns.so iouring_dns.o -luring
 *
 * Links with rustd-resolved via build.rs.
 */

#define _GNU_SOURCE
#include "iouring_dns.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define SR_MAX_NAME_HOPS 128U
#define SR_NAME_WIRE_MAX 255U
#define SR_DNS_MESSAGE_MAX 65535U

static inline int sr_bit_test(const uint64_t *bm, unsigned bit)
{
    return (int)((bm[bit >> 6] >> (bit & 63U)) & 1ULL);
}

static inline void sr_bit_set(uint64_t *bm, unsigned bit)
{
    bm[bit >> 6] |= 1ULL << (bit & 63U);
}

static int sr_peer_length_valid(const struct sockaddr_storage *peer, socklen_t length)
{
    if (!peer || length < (socklen_t)sizeof(sa_family_t) ||
        length > (socklen_t)sizeof(*peer))
        return 0;

    switch (peer->ss_family) {
    case AF_INET:
        return length >= (socklen_t)sizeof(struct sockaddr_in);
    case AF_INET6:
        return length >= (socklen_t)sizeof(struct sockaddr_in6);
    default:
        return 0;
    }
}

/*
 * Walk name at *off. On success, *off is first byte after the name
 * (compression: advanced only past the first pointer).
 * If out != NULL and out_cap > 0, writes lowercased uncompressed form.
 */
int sr_dns_name_walk(const uint8_t *msg, size_t msg_len, size_t *off,
                     uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t o;
    size_t hops = 0;
    size_t nlen = 0;
    int jumped = 0;
    size_t return_off = 0;
    /*
     * Cover the entire DNS message address space. Keeping the bitmap sized
     * to the protocol limit makes every bit index checked below safe even
     * under adversarial compression-pointer chains.
     */
    uint64_t seen[1024];

    if (out_len)
        *out_len = 0;
    if (!msg || !off || msg_len == 0U)
        return SR_NAME_OOB;
    if (msg_len > SR_DNS_MESSAGE_MAX)
        return SR_NAME_TOO_LONG;
    if (*off >= msg_len)
        return SR_NAME_OOB;
    if (out && out_cap == 0U)
        return SR_NAME_TOO_LONG;

    o = *off;
    memset(seen, 0, sizeof(seen));

    for (;;) {
        uint8_t lab;

        if (o >= msg_len)
            return SR_NAME_OOB;
        if (hops++ >= SR_MAX_NAME_HOPS)
            return SR_NAME_HOP_LIMIT;
        if (sr_bit_test(seen, (unsigned)o))
            return SR_NAME_CYCLE;
        sr_bit_set(seen, (unsigned)o);

        lab = msg[o];
        if (lab == 0U) {
            if (out) {
                if (nlen >= out_cap)
                    return SR_NAME_TOO_LONG;
                out[nlen++] = 0U;
            } else {
                nlen++;
            }
            *off = jumped ? return_off : o + 1U;
            if (out_len)
                *out_len = nlen;
            if (nlen > SR_NAME_WIRE_MAX)
                return SR_NAME_TOO_LONG;
            return SR_NAME_OK;
        }

        if ((lab & 0xC0U) == 0xC0U) {
            uint16_t ptr;

            if (o + 1U >= msg_len)
                return SR_NAME_OOB;
            ptr = (uint16_t)(((uint16_t)(lab & 0x3FU) << 8U) | msg[o + 1U]);
            if ((size_t)ptr >= msg_len)
                return SR_NAME_OOB;
            if (!jumped) {
                return_off = o + 2U;
                jumped = 1;
            }
            o = ptr;
            continue;
        }

        if ((lab & 0xC0U) != 0U || lab > 63U)
            return SR_NAME_BAD_LABEL;
        if (o + 1U + (size_t)lab >= msg_len)
            return SR_NAME_OOB;
        if (nlen + 1U + (size_t)lab + 1U > SR_NAME_WIRE_MAX)
            return SR_NAME_TOO_LONG;

        if (out) {
            uint8_t i;

            if (nlen + 1U + (size_t)lab >= out_cap)
                return SR_NAME_TOO_LONG;
            out[nlen++] = lab;
            for (i = 0U; i < lab; ++i) {
                uint8_t c = msg[o + 1U + i];
                if (c >= (uint8_t)'A' && c <= (uint8_t)'Z')
                    c = (uint8_t)(c + 32U);
                out[nlen++] = c;
            }
        } else {
            nlen += 1U + (size_t)lab;
        }
        o += 1U + (size_t)lab;
    }
}

int sr_ring_init(sr_ring *r, int fd, unsigned qd)
{
    int rc;

    if (!r)
        return -EINVAL;
    if (fd < 0)
        return -EBADF;

    memset(r, 0, sizeof(*r));
    r->fd = fd;
    if (qd < 8U)
        qd = 8U;
    if (qd > 4096U)
        qd = 4096U;
    rc = io_uring_queue_init(qd, &r->ring, 0);
    if (rc < 0)
        return rc;
    r->registered = true;
    return 0;
}

void sr_ring_destroy(sr_ring *r)
{
    if (!r)
        return;
    if (r->registered) {
        io_uring_queue_exit(&r->ring);
        r->registered = false;
    }
}

static int prep_recvmsg(sr_ring *r, sr_packet *p, sr_msg_slot *slot,
                        unsigned user_idx)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&r->ring);

    if (!sqe)
        return -ENOSPC;

    memset(slot, 0, sizeof(*slot));
    slot->peer_len = (socklen_t)sizeof(slot->peer);
    slot->iov.iov_base = p->data;
    slot->iov.iov_len = sizeof(p->data);
    slot->hdr.msg_name = &slot->peer;
    slot->hdr.msg_namelen = slot->peer_len;
    slot->hdr.msg_iov = &slot->iov;
    slot->hdr.msg_iovlen = 1U;

    io_uring_prep_recvmsg(sqe, r->fd, &slot->hdr, 0);
    sqe->user_data = ((uint64_t)1U << 63U) | (uint64_t)user_idx;
    return 0;
}

static int prep_sendmsg(sr_ring *r, const sr_packet *p, sr_msg_slot *slot,
                        unsigned user_idx)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&r->ring);

    if (!sqe)
        return -ENOSPC;

    memset(slot, 0, sizeof(*slot));
    memcpy(&slot->peer, &p->peer, p->peer_len);
    slot->peer_len = p->peer_len;
    slot->iov.iov_base = (void *)p->data;
    slot->iov.iov_len = p->len;
    slot->hdr.msg_name = &slot->peer;
    slot->hdr.msg_namelen = slot->peer_len;
    slot->hdr.msg_iov = &slot->iov;
    slot->hdr.msg_iovlen = 1U;

    io_uring_prep_sendmsg(sqe, r->fd, &slot->hdr, 0);
    sqe->user_data = (uint64_t)user_idx;
    return 0;
}

int sr_ring_submit_batch(sr_ring *r,
                         sr_packet *tx, sr_msg_slot *tx_slots, unsigned tx_n,
                         sr_packet *rx, sr_msg_slot *rx_slots, unsigned rx_n)
{
    unsigned sub = 0U;
    int exhausted = 0;
    int rc;
    unsigned i;

    if (!r || !r->registered)
        return -EINVAL;
    if (tx_n > SR_MAX_BATCH || rx_n > SR_MAX_BATCH)
        return -E2BIG;
    if ((tx_n && (!tx || !tx_slots)) || (rx_n && (!rx || !rx_slots)))
        return -EINVAL;

    for (i = 0U; i < tx_n; ++i) {
        if (tx[i].len == 0U || tx[i].len > SR_MAX_PACKET)
            return -EINVAL;
        if (!sr_peer_length_valid(&tx[i].peer, tx[i].peer_len))
            return -EINVAL;
    }

    for (i = 0U; i < tx_n; ++i) {
        rc = prep_sendmsg(r, &tx[i], &tx_slots[i], i);
        if (rc == -ENOSPC) {
            exhausted = 1;
            break;
        }
        if (rc < 0)
            return rc;
        tx[i].result = 0;
        sub++;
    }

    if (!exhausted) {
        for (i = 0U; i < rx_n; ++i) {
            rx[i].len = 0U;
            rx[i].peer_len = 0U;
            rx[i].result = 0;
            rc = prep_recvmsg(r, &rx[i], &rx_slots[i], i);
            if (rc == -ENOSPC) {
                exhausted = 1;
                break;
            }
            if (rc < 0)
                return rc;
            sub++;
        }
    }

    if (sub == 0U)
        return exhausted ? -ENOSPC : 0;

    rc = io_uring_submit(&r->ring);
    return rc < 0 ? rc : rc;
}

int sr_ring_reap(sr_ring *r,
                 sr_packet *tx, unsigned tx_n,
                 sr_packet *rx, sr_msg_slot *rx_slots, unsigned rx_n,
                 unsigned max_cqe)
{
    unsigned got = 0U;

    if (!r || !r->registered)
        return -EINVAL;
    if (tx_n > SR_MAX_BATCH || rx_n > SR_MAX_BATCH)
        return -E2BIG;
    if ((tx_n && !tx) || (rx_n && (!rx || !rx_slots)))
        return -EINVAL;

    while (got < max_cqe) {
        struct io_uring_cqe *cqe;
        uint64_t ud;
        int res;
        int is_rx;
        unsigned idx;
        int rc = io_uring_peek_cqe(&r->ring, &cqe);

        if (rc == -EAGAIN)
            break;
        if (rc < 0)
            return got ? (int)got : rc;

        ud = cqe->user_data;
        res = cqe->res;
        is_rx = (int)((ud >> 63U) & 1U);
        idx = (unsigned)(ud & 0xffffffffU);

        if (is_rx) {
            if (idx < rx_n) {
                if (res >= 0) {
                    socklen_t peer_len = rx_slots[idx].hdr.msg_namelen;

                    if (!sr_peer_length_valid(&rx_slots[idx].peer, peer_len)) {
                        rx[idx].len = 0U;
                        rx[idx].peer_len = 0U;
                        rx[idx].result = -EOVERFLOW;
                    } else {
                        rx[idx].len = (uint16_t)((res > (int)SR_MAX_PACKET) ?
                                                 SR_MAX_PACKET : (unsigned)res);
                        rx[idx].result = 0;
                        memcpy(&rx[idx].peer, &rx_slots[idx].peer, peer_len);
                        rx[idx].peer_len = peer_len;
                    }
                } else {
                    rx[idx].len = 0U;
                    rx[idx].peer_len = 0U;
                    rx[idx].result = res;
                }
            }
        } else if (idx < tx_n) {
            tx[idx].result = res < 0 ? res : 0;
        }

        io_uring_cqe_seen(&r->ring, cqe);
        got++;
    }
    return (int)got;
}

int sr_dns_header_precheck(const uint8_t *pkt, size_t len, int expect_response)
{
    uint8_t flags0;
    int qr;
    int opcode;
    uint16_t qd;
    uint16_t an;
    uint16_t ns;
    uint16_t ar;
    uint32_t total;
    size_t off;

    if (!pkt)
        return -EINVAL;
    if (len < 12U)
        return -EINVAL;
    if (len > SR_DNS_MESSAGE_MAX)
        return -EMSGSIZE;

    flags0 = pkt[2];
    qr = (flags0 >> 7U) & 1U;
    opcode = (flags0 >> 3U) & 0xFU;
    if (opcode != 0)
        return -EPROTONOSUPPORT;
    if (expect_response && !qr)
        return -EINVAL;
    if (!expect_response && qr)
        return -EINVAL;

    qd = (uint16_t)(((uint16_t)pkt[4] << 8U) | pkt[5]);
    an = (uint16_t)(((uint16_t)pkt[6] << 8U) | pkt[7]);
    ns = (uint16_t)(((uint16_t)pkt[8] << 8U) | pkt[9]);
    ar = (uint16_t)(((uint16_t)pkt[10] << 8U) | pkt[11]);
    total = (uint32_t)qd + (uint32_t)an + (uint32_t)ns + (uint32_t)ar;
    if (total > 4096U)
        return -E2BIG;
    if (qd == 0U && !expect_response)
        return -EINVAL;

    off = 12U;
    if (qd) {
        int nerr = sr_dns_name_walk(pkt, len, &off, NULL, 0U, NULL);
        if (nerr != SR_NAME_OK)
            return -EBADMSG;
        if (off + 4U > len)
            return -EBADMSG;
    }
    return 0;
}

int sr_extract_question_owner(const uint8_t *pkt, size_t len,
                              uint8_t *owner_out, size_t owner_cap,
                              size_t *owner_len, uint16_t *qtype, uint16_t *qclass)
{
    size_t off;
    size_t ol = 0U;
    int pr;
    int nerr;

    if (!pkt || len < 12U || !owner_out || !owner_len || !qtype || !qclass)
        return -EINVAL;
    pr = sr_dns_header_precheck(pkt, len, 0);
    if (pr < 0)
        return pr;
    off = 12U;
    nerr = sr_dns_name_walk(pkt, len, &off, owner_out, owner_cap, &ol);
    if (nerr != SR_NAME_OK)
        return -EBADMSG;
    if (off + 4U > len)
        return -EBADMSG;
    *owner_len = ol;
    *qtype = (uint16_t)(((uint16_t)pkt[off] << 8U) | pkt[off + 1U]);
    *qclass = (uint16_t)(((uint16_t)pkt[off + 2U] << 8U) | pkt[off + 3U]);
    return 0;
}
