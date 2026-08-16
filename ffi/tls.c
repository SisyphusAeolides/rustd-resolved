/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "native.h"

#include <errno.h>
#include <limits.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

struct resolved_tls_stream {
    int fd;
    SSL_CTX *context;
    SSL *ssl;
};

static int set_timeout(int fd, uint32_t timeout_msec) {
    struct timeval timeout;

    if (timeout_msec == 0U) {
        return -EINVAL;
    }
    timeout.tv_sec = (time_t)(timeout_msec / 1000U);
    timeout.tv_usec = (suseconds_t)((timeout_msec % 1000U) * 1000U);
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        return -errno;
    }
    return 0;
}

static int ssl_error(SSL *ssl, int result) {
    const int error = SSL_get_error(ssl, result);

    if (error == SSL_ERROR_ZERO_RETURN) {
        return 0;
    }
    if (error == SSL_ERROR_SYSCALL) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return -ETIMEDOUT;
        }
        return errno != 0 ? -errno : -EPIPE;
    }
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
        return -ETIMEDOUT;
    }
    return -ECONNREFUSED;
}

int resolved_tls_connect(
    const char *address,
    uint16_t port,
    uint32_t scope_id,
    int ifindex,
    uint32_t firewall_mark,
    const char *server_name,
    int strict,
    uint32_t timeout_msec,
    resolved_tls_stream **ret
) {
    resolved_tls_stream *stream = NULL;
    X509_VERIFY_PARAM *verify;
    int fd = -1;
    int result;

    if (address == NULL || ret == NULL || timeout_msec == 0U) {
        return -EINVAL;
    }
    *ret = NULL;

    fd = resolved_tcp_connect(address, port, scope_id, ifindex, firewall_mark, timeout_msec);
    if (fd < 0) {
        return fd;
    }
    result = set_timeout(fd, timeout_msec);
    if (result < 0) {
        goto fail;
    }

    stream = calloc(1, sizeof(*stream));
    if (stream == NULL) {
        result = -ENOMEM;
        goto fail;
    }
    stream->fd = fd;
    fd = -1;

    stream->context = SSL_CTX_new(TLS_client_method());
    if (stream->context == NULL) {
        result = -ENOMEM;
        goto fail;
    }
    if (SSL_CTX_set_min_proto_version(stream->context, TLS1_2_VERSION) != 1) {
        result = -EIO;
        goto fail;
    }
    (void)SSL_CTX_set_options(stream->context, SSL_OP_NO_COMPRESSION);
    if (SSL_CTX_set_default_verify_paths(stream->context) != 1) {
        result = -EIO;
        goto fail;
    }
    SSL_CTX_set_verify(stream->context, strict != 0 ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);

    stream->ssl = SSL_new(stream->context);
    if (stream->ssl == NULL) {
        result = -ENOMEM;
        goto fail;
    }
    if (SSL_set_fd(stream->ssl, stream->fd) != 1) {
        result = -EIO;
        goto fail;
    }

    verify = SSL_get0_param(stream->ssl);
    if (strict != 0) {
        if (server_name != NULL && server_name[0] != '\0') {
            X509_VERIFY_PARAM_set_hostflags(verify, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            if (X509_VERIFY_PARAM_set1_host(verify, server_name, 0) != 1) {
                result = -ECONNREFUSED;
                goto fail;
            }
        } else if (X509_VERIFY_PARAM_set1_ip_asc(verify, address) != 1) {
            result = -ECONNREFUSED;
            goto fail;
        }
    }

    if (server_name != NULL && server_name[0] != '\0' &&
        SSL_set_tlsext_host_name(stream->ssl, server_name) != 1) {
        result = -EINVAL;
        goto fail;
    }

    result = SSL_connect(stream->ssl);
    if (result != 1) {
        result = ssl_error(stream->ssl, result);
        if (result == 0) {
            result = -ECONNREFUSED;
        }
        goto fail;
    }
    if (strict != 0 && SSL_get_verify_result(stream->ssl) != X509_V_OK) {
        result = -ECONNREFUSED;
        goto fail;
    }

    *ret = stream;
    return 0;

fail:
    if (stream != NULL) {
        if (stream->ssl != NULL) {
            SSL_free(stream->ssl);
        }
        if (stream->context != NULL) {
            SSL_CTX_free(stream->context);
        }
        if (stream->fd >= 0) {
            (void)close(stream->fd);
        }
        free(stream);
    }
    if (fd >= 0) {
        (void)close(fd);
    }
    return result;
}

int resolved_tls_set_timeout(resolved_tls_stream *stream, uint32_t timeout_msec) {
    if (stream == NULL || stream->fd < 0) {
        return -EINVAL;
    }
    return set_timeout(stream->fd, timeout_msec);
}

int64_t resolved_tls_read(resolved_tls_stream *stream, void *buffer, size_t capacity) {
    int result;
    int count;

    if (stream == NULL || stream->ssl == NULL || buffer == NULL || capacity == 0U) {
        return -EINVAL;
    }
    count = capacity > (size_t)INT_MAX ? INT_MAX : (int)capacity;
    result = SSL_read(stream->ssl, buffer, count);
    if (result > 0) {
        return result;
    }
    return ssl_error(stream->ssl, result);
}

int64_t resolved_tls_write(resolved_tls_stream *stream, const void *buffer, size_t length) {
    int result;
    int count;

    if (stream == NULL || stream->ssl == NULL || buffer == NULL || length == 0U) {
        return -EINVAL;
    }
    count = length > (size_t)INT_MAX ? INT_MAX : (int)length;
    result = SSL_write(stream->ssl, buffer, count);
    if (result > 0) {
        return result;
    }
    return ssl_error(stream->ssl, result);
}

void resolved_tls_free(resolved_tls_stream *stream) {
    if (stream == NULL) {
        return;
    }
    if (stream->ssl != NULL) {
        (void)SSL_shutdown(stream->ssl);
        SSL_free(stream->ssl);
    }
    if (stream->context != NULL) {
        SSL_CTX_free(stream->context);
    }
    if (stream->fd >= 0) {
        (void)close(stream->fd);
    }
    free(stream);
}
