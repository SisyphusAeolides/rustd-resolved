#pragma once

#include <liburing.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SR_MAX_BATCH 64U
#define SR_MAX_PACKET 1232U

typedef struct sr_msg_slot {
    struct sockaddr_storage peer;
    socklen_t peer_len;
    struct iovec iov;
    struct msghdr hdr;
} sr_msg_slot;

typedef struct sr_packet {
    uint8_t data[SR_MAX_PACKET];
    uint16_t len;
    uint16_t _pad;
    int ifindex;
    int result;
    struct sockaddr_storage peer;
    socklen_t peer_len;
} sr_packet;

typedef struct sr_ring {
    struct io_uring ring;
    int fd;
    sr_packet *rx;
    sr_packet *tx;
    unsigned rx_cap;
    unsigned tx_cap;
    sr_msg_slot *rx_slots;
    sr_msg_slot *tx_slots;
    bool registered;
} sr_ring;

typedef enum sr_name_err {
    SR_NAME_OK = 0,
    SR_NAME_OOB = 1,
    SR_NAME_BAD_LABEL = 2,
    SR_NAME_CYCLE = 3,
    SR_NAME_HOP_LIMIT = 4,
    SR_NAME_TOO_LONG = 5,
    SR_NAME_PTR = 6
} sr_name_err;

int sr_ring_init(sr_ring *r, int fd, unsigned qd);
void sr_ring_destroy(sr_ring *r);
int sr_ring_submit_batch(sr_ring *r,
                         sr_packet *tx, sr_msg_slot *tx_slots, unsigned tx_n,
                         sr_packet *rx, sr_msg_slot *rx_slots, unsigned rx_n);
int sr_ring_reap(sr_ring *r,
                 sr_packet *tx, unsigned tx_n,
                 sr_packet *rx, sr_msg_slot *rx_slots, unsigned rx_n,
                 unsigned max_cqe);

int sr_dns_name_walk(const uint8_t *msg, size_t msg_len, size_t *off,
                     uint8_t *out, size_t out_cap, size_t *out_len);
int sr_dns_header_precheck(const uint8_t *pkt, size_t len, int expect_response);
int sr_extract_question_owner(const uint8_t *pkt, size_t len,
                              uint8_t *owner_out, size_t owner_cap,
                              size_t *owner_len, uint16_t *qtype, uint16_t *qclass);

#ifdef __cplusplus
}
#endif
