#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sr_packet sr_packet;
typedef struct sr_ring sr_ring;

int  sr_ring_init(sr_ring *r, int fd, unsigned qd);
void sr_ring_destroy(sr_ring *r);
int  sr_ring_submit_batch(sr_ring *r, sr_packet *tx, unsigned tx_n,
                          sr_packet *rx, unsigned rx_n);
int  sr_ring_reap(sr_ring *r, sr_packet *tx, unsigned tx_n,
                  sr_packet *rx, unsigned rx_n, unsigned max_cqe);

int sr_dns_name_walk(const uint8_t *msg, size_t msg_len, size_t *off,
                     uint8_t *out, size_t out_cap, size_t *out_len);
int sr_dns_header_precheck(const uint8_t *pkt, size_t len, int expect_response);
int sr_extract_question_owner(const uint8_t *pkt, size_t len,
                              uint8_t *owner_out, size_t owner_cap,
                              size_t *owner_len, uint16_t *qtype, uint16_t *qclass);

#ifdef __cplusplus
}
#endif
