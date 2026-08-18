/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include "iouring_dns.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void test_name_walk(void)
{
    static const uint8_t name[] = {
        3, 'W', 'W', 'W',
        7, 'E', 'x', 'a', 'M', 'p', 'l', 'E',
        3, 'C', 'O', 'M',
        0
    };
    static const uint8_t expected[] = {
        3, 'w', 'w', 'w',
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm',
        0
    };
    uint8_t out[256];
    size_t off = 0U;
    size_t out_len = 0U;
    uint8_t *cycle;
    uint8_t *oversized;

    assert(sr_dns_name_walk(name, sizeof(name), &off, out, sizeof(out), &out_len) == SR_NAME_OK);
    assert(off == sizeof(name));
    assert(out_len == sizeof(expected));
    assert(memcmp(out, expected, sizeof(expected)) == 0);

    /* Compression pointers can target the top of their 14-bit address space.
     * A self-pointer there exercises the highest bitmap word needed to catch
     * pointer cycles and regresses the former undersized-bitmap OOB bug. */
    cycle = calloc(16385U, 1U);
    assert(cycle != NULL);
    cycle[16383] = 0xffU;
    cycle[16384] = 0xffU;
    off = 16383U;
    assert(sr_dns_name_walk(cycle, 16385U, &off, NULL, 0U, NULL) == SR_NAME_CYCLE);
    free(cycle);

    oversized = calloc(65536U, 1U);
    assert(oversized != NULL);
    off = 0U;
    assert(sr_dns_name_walk(oversized, 65536U, &off, NULL, 0U, NULL) == SR_NAME_TOO_LONG);
    free(oversized);

    off = 0U;
    assert(sr_dns_name_walk(NULL, sizeof(name), &off, NULL, 0U, NULL) == SR_NAME_OOB);
    assert(sr_dns_name_walk(name, sizeof(name), NULL, NULL, 0U, NULL) == SR_NAME_OOB);
    off = sizeof(name);
    assert(sr_dns_name_walk(name, sizeof(name), &off, NULL, 0U, NULL) == SR_NAME_OOB);
}

static int reap_until(sr_ring *ring,
                      sr_packet *tx, unsigned tx_n,
                      sr_packet *rx, sr_msg_slot *rx_slots, unsigned rx_n)
{
    unsigned i;
    for (i = 0U; i < 2000U; ++i) {
        int rc = sr_ring_reap(ring, tx, tx_n, rx, rx_slots, rx_n, 1U);
        if (rc != 0)
            return rc;
        usleep(1000U);
    }
    return -ETIMEDOUT;
}

static void test_udp_round_trip(void)
{
    static const uint8_t request[] = {0x12, 0x34, 0x01, 0x00, 'q'};
    static const uint8_t reply[] = {0x12, 0x34, 0x81, 0x80, 'r'};
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    sr_ring ring;
    sr_packet rx[1];
    sr_packet tx[1];
    sr_msg_slot rx_slots[1];
    sr_msg_slot tx_slots[1];
    uint8_t buffer[32];
    struct pollfd pfd;
    int server;
    int client;
    int rc;
    ssize_t n;

    if (getenv("SR_SKIP_RING") != NULL)
        return;

    server = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    client = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    assert(server >= 0 && client >= 0);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(server, (const struct sockaddr *)&server_addr, sizeof(server_addr)) == 0);
    addr_len = sizeof(server_addr);
    assert(getsockname(server, (struct sockaddr *)&server_addr, &addr_len) == 0);

    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(client, (const struct sockaddr *)&client_addr, sizeof(client_addr)) == 0);
    addr_len = sizeof(client_addr);
    assert(getsockname(client, (struct sockaddr *)&client_addr, &addr_len) == 0);

    memset(&ring, 0, sizeof(ring));
    rc = sr_ring_init(&ring, server, 8U);
    if (rc == -ENOSYS || rc == -EPERM || rc == -EACCES) {
        fprintf(stderr, "io_uring unavailable in test environment: %d\n", rc);
        close(client);
        close(server);
        return;
    }
    assert(rc == 0);

    memset(rx, 0, sizeof(rx));
    memset(rx_slots, 0, sizeof(rx_slots));
    assert(sr_ring_submit_batch(&ring, NULL, NULL, 0U, rx, rx_slots, 1U) == 1);
    assert(sendto(client, request, sizeof(request), 0,
                  (const struct sockaddr *)&server_addr, sizeof(server_addr)) == (ssize_t)sizeof(request));
    assert(reap_until(&ring, NULL, 0U, rx, rx_slots, 1U) == 1);
    assert(rx[0].result == 0);
    assert(rx[0].len == sizeof(request));
    assert(memcmp(rx[0].data, request, sizeof(request)) == 0);
    assert(rx[0].peer_len == sizeof(struct sockaddr_in));
    assert(rx[0].peer.ss_family == AF_INET);
    {
        const struct sockaddr_in *peer = (const struct sockaddr_in *)&rx[0].peer;
        assert(peer->sin_port == client_addr.sin_port);
        assert(peer->sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    }

    memset(tx, 0, sizeof(tx));
    memset(tx_slots, 0, sizeof(tx_slots));
    memcpy(tx[0].data, reply, sizeof(reply));
    tx[0].len = sizeof(reply);
    memcpy(&tx[0].peer, &rx[0].peer, rx[0].peer_len);
    tx[0].peer_len = rx[0].peer_len;
    assert(sr_ring_submit_batch(&ring, tx, tx_slots, 1U, NULL, NULL, 0U) == 1);
    assert(reap_until(&ring, tx, 1U, NULL, NULL, 0U) == 1);
    assert(tx[0].result == 0);

    pfd.fd = client;
    pfd.events = POLLIN;
    pfd.revents = 0;
    assert(poll(&pfd, 1U, 2000) == 1);
    n = recv(client, buffer, sizeof(buffer), 0);
    assert(n == (ssize_t)sizeof(reply));
    assert(memcmp(buffer, reply, sizeof(reply)) == 0);

    /* Peer lengths are untrusted FFI input and must never drive an OOB copy. */
    tx[0].peer_len = (socklen_t)(sizeof(tx[0].peer) + 1U);
    assert(sr_ring_submit_batch(&ring, tx, tx_slots, 1U, NULL, NULL, 0U) == -EINVAL);
    assert(sr_ring_submit_batch(&ring, tx, tx_slots, SR_MAX_BATCH + 1U,
                                NULL, NULL, 0U) == -E2BIG);

    sr_ring_destroy(&ring);
    close(client);
    close(server);
}

int main(void)
{
    test_name_walk();
    test_udp_round_trip();
    return 0;
}
