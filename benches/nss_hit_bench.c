/* gcc -O2 -o nss_hit_bench nss_hit_bench.c nss_resolve_shm.c */
#include <stdio.h>
#include <time.h>
#include "../nss/nss_resolve_shm.h"

int main(void) {
    uint8_t owner[] = {7,'e','x','a','m','p','l','e',3,'c','o','m',0};
    struct sr_shm_addr addrs[8];
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    const int N = 1000000;
    int hits = 0;
    for (int i = 0; i < N; i++) {
        size_t n = 8; uint8_t rc; int sec;
        if (sr_shm_lookup(owner, sizeof owner, 1, 1, &rc, addrs, &n, &sec) == 0)
            hits++;
    }
    clock_gettime(CLOCK_MONOTONIC, &b);
    double ns = (b.tv_sec - a.tv_sec) * 1e9 + (b.tv_nsec - a.tv_nsec);
    printf("hits=%d avg_ns=%.2f\n", hits, ns / N);
    return 0;
}
