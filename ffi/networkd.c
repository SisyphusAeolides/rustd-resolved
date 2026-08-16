/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include "native.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

static const char *const watch_paths[] = {
    "/run/systemd/netif/links",
    "/run/systemd/netif",
    "/run/systemd",
    "/run",
};

int resolved_networkd_open(void) {
    const uint32_t mask = IN_MOVED_TO | IN_DELETE | IN_CLOSE_WRITE | IN_CREATE | IN_DELETE_SELF | IN_MOVE_SELF;
    int fd;
    size_t i;

    fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd < 0) {
        return -errno;
    }

    for (i = 0; i < sizeof(watch_paths) / sizeof(watch_paths[0]); i++) {
        if (inotify_add_watch(fd, watch_paths[i], mask) >= 0) {
            return fd;
        }
        if (errno != ENOENT && errno != ENOTDIR) {
            const int error = errno;
            (void)close(fd);
            return -error;
        }
    }

    (void)close(fd);
    return -ENOENT;
}

int resolved_networkd_wait(int fd, uint32_t timeout_msec) {
    struct pollfd descriptor;
    char buffer[16384];
    int timeout;
    int result;
    bool changed = false;

    if (fd < 0) {
        return -EBADF;
    }
    timeout = timeout_msec > (uint32_t)INT_MAX ? INT_MAX : (int)timeout_msec;
    descriptor.fd = fd;
    descriptor.events = POLLIN;
    descriptor.revents = 0;

    do {
        result = poll(&descriptor, 1, timeout);
    } while (result < 0 && errno == EINTR);
    if (result < 0) {
        return -errno;
    }
    if (result == 0) {
        return 0;
    }
    if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        return -EIO;
    }

    for (;;) {
        ssize_t length = read(fd, buffer, sizeof(buffer));
        if (length > 0) {
            changed = true;
            continue;
        }
        if (length == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        }
        return -errno;
    }
    return changed ? 1 : 0;
}
