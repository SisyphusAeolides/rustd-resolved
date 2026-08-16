/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "native.h"

#include <errno.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const EVP_MD *dnssec_signature_digest(uint8_t algorithm) {
    switch (algorithm) {
    case 5:
    case 7:
        return EVP_sha1();
    case 8:
    case 13:
        return EVP_sha256();
    case 14:
        return EVP_sha384();
    case 10:
        return EVP_sha512();
    default:
        return NULL;
    }
}

static int dnssec_rsa_public_key(
    const uint8_t *key,
    size_t key_length,
    EVP_PKEY **ret
) {
    BIGNUM *exponent = NULL;
    BIGNUM *modulus = NULL;
    OSSL_PARAM_BLD *builder = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *context = NULL;
    EVP_PKEY *public_key = NULL;
    size_t exponent_length;
    size_t prefix_length;
    int result = -EIO;

    if (key == NULL || ret == NULL || key_length < 3U) {
        return -EINVAL;
    }

    if (key[0] == 0U) {
        exponent_length = ((size_t)key[1] << 8U) | (size_t)key[2];
        prefix_length = 3U;
        if (exponent_length < 256U) {
            return -EINVAL;
        }
    } else {
        exponent_length = (size_t)key[0];
        prefix_length = 1U;
    }
    if (exponent_length == 0U || prefix_length + exponent_length >= key_length) {
        return -EINVAL;
    }

    exponent = BN_bin2bn(key + prefix_length, (int)exponent_length, NULL);
    modulus = BN_bin2bn(
        key + prefix_length + exponent_length,
        (int)(key_length - prefix_length - exponent_length),
        NULL
    );
    if (exponent == NULL || modulus == NULL) {
        result = -ENOMEM;
        goto finish;
    }

    builder = OSSL_PARAM_BLD_new();
    if (builder == NULL) {
        result = -ENOMEM;
        goto finish;
    }
    if (OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_E, exponent) <= 0 ||
        OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_N, modulus) <= 0) {
        goto finish;
    }
    params = OSSL_PARAM_BLD_to_param(builder);
    if (params == NULL) {
        goto finish;
    }

    context = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (context == NULL) {
        result = -ENOMEM;
        goto finish;
    }
    if (EVP_PKEY_fromdata_init(context) <= 0 ||
        EVP_PKEY_fromdata(context, &public_key, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        goto finish;
    }

    *ret = public_key;
    public_key = NULL;
    result = 0;

finish:
    EVP_PKEY_free(public_key);
    EVP_PKEY_CTX_free(context);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(builder);
    BN_free(modulus);
    BN_free(exponent);
    return result;
}

static int dnssec_ec_public_key(
    uint8_t algorithm,
    const uint8_t *key,
    size_t key_length,
    EVP_PKEY **ret
) {
    const char *group;
    size_t coordinate_length;
    uint8_t *encoded = NULL;
    EVP_PKEY_CTX *context = NULL;
    EVP_PKEY *public_key = NULL;
    int result = -EIO;

    if (key == NULL || ret == NULL) {
        return -EINVAL;
    }
    if (algorithm == 13U) {
        group = "prime256v1";
        coordinate_length = 32U;
    } else if (algorithm == 14U) {
        group = "secp384r1";
        coordinate_length = 48U;
    } else {
        return -EOPNOTSUPP;
    }
    if (key_length != coordinate_length * 2U) {
        return -EINVAL;
    }

    encoded = malloc(key_length + 1U);
    if (encoded == NULL) {
        return -ENOMEM;
    }
    encoded[0] = 0x04U;
    memcpy(encoded + 1U, key, key_length);

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)group, 0),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, encoded, key_length + 1U),
        OSSL_PARAM_construct_end(),
    };

    context = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (context == NULL) {
        result = -ENOMEM;
        goto finish;
    }
    if (EVP_PKEY_fromdata_init(context) <= 0 ||
        EVP_PKEY_fromdata(context, &public_key, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        goto finish;
    }

    *ret = public_key;
    public_key = NULL;
    result = 0;

finish:
    EVP_PKEY_free(public_key);
    EVP_PKEY_CTX_free(context);
    free(encoded);
    return result;
}

static int dnssec_ecdsa_signature(
    const uint8_t *signature,
    size_t signature_length,
    size_t coordinate_length,
    uint8_t **ret,
    size_t *ret_length
) {
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;
    ECDSA_SIG *ecdsa = NULL;
    uint8_t *der = NULL;
    uint8_t *cursor;
    int length;

    if (signature == NULL || ret == NULL || ret_length == NULL ||
        signature_length != coordinate_length * 2U) {
        return -EINVAL;
    }

    r = BN_bin2bn(signature, (int)coordinate_length, NULL);
    s = BN_bin2bn(signature + coordinate_length, (int)coordinate_length, NULL);
    ecdsa = ECDSA_SIG_new();
    if (r == NULL || s == NULL || ecdsa == NULL) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(ecdsa);
        return -ENOMEM;
    }
    if (ECDSA_SIG_set0(ecdsa, r, s) <= 0) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(ecdsa);
        return -EIO;
    }
    r = NULL;
    s = NULL;

    length = i2d_ECDSA_SIG(ecdsa, NULL);
    if (length <= 0) {
        ECDSA_SIG_free(ecdsa);
        return -EIO;
    }
    der = malloc((size_t)length);
    if (der == NULL) {
        ECDSA_SIG_free(ecdsa);
        return -ENOMEM;
    }
    cursor = der;
    if (i2d_ECDSA_SIG(ecdsa, &cursor) != length) {
        free(der);
        ECDSA_SIG_free(ecdsa);
        return -EIO;
    }

    ECDSA_SIG_free(ecdsa);
    *ret = der;
    *ret_length = (size_t)length;
    return 0;
}

int resolved_dnssec_verify(
    uint8_t algorithm,
    const uint8_t *key,
    size_t key_length,
    const uint8_t *data,
    size_t data_length,
    const uint8_t *signature,
    size_t signature_length
) {
    const EVP_MD *digest;
    EVP_PKEY *public_key = NULL;
    EVP_MD_CTX *context = NULL;
    uint8_t *encoded_signature = NULL;
    size_t encoded_signature_length = signature_length;
    int result;

    if (key == NULL || data == NULL || signature == NULL) {
        return -EINVAL;
    }

    if (algorithm == 15U) {
        if (key_length != 32U || signature_length != 64U) {
            return -EINVAL;
        }
        public_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, key, key_length);
        if (public_key == NULL) {
            return -EIO;
        }
        context = EVP_MD_CTX_new();
        if (context == NULL) {
            EVP_PKEY_free(public_key);
            return -ENOMEM;
        }
        if (EVP_DigestVerifyInit(context, NULL, NULL, NULL, public_key) <= 0) {
            result = -EIO;
        } else {
            result = EVP_DigestVerify(context, signature, signature_length, data, data_length);
            if (result < 0) {
                result = -EIO;
            }
        }
        EVP_MD_CTX_free(context);
        EVP_PKEY_free(public_key);
        return result;
    }
    if (algorithm == 16U) {
        return -EOPNOTSUPP;
    }

    digest = dnssec_signature_digest(algorithm);
    if (digest == NULL) {
        return -EOPNOTSUPP;
    }

    if (algorithm == 5U || algorithm == 7U || algorithm == 8U || algorithm == 10U) {
        result = dnssec_rsa_public_key(key, key_length, &public_key);
        if (result < 0) {
            return result;
        }
    } else if (algorithm == 13U || algorithm == 14U) {
        const size_t coordinate_length = algorithm == 13U ? 32U : 48U;
        result = dnssec_ec_public_key(algorithm, key, key_length, &public_key);
        if (result < 0) {
            return result;
        }
        result = dnssec_ecdsa_signature(
            signature,
            signature_length,
            coordinate_length,
            &encoded_signature,
            &encoded_signature_length
        );
        if (result < 0) {
            EVP_PKEY_free(public_key);
            return result;
        }
        signature = encoded_signature;
    } else {
        return -EOPNOTSUPP;
    }

    context = EVP_MD_CTX_new();
    if (context == NULL) {
        free(encoded_signature);
        EVP_PKEY_free(public_key);
        return -ENOMEM;
    }
    if (EVP_DigestVerifyInit(context, NULL, digest, NULL, public_key) <= 0) {
        result = -EIO;
    } else {
        result = EVP_DigestVerify(
            context,
            signature,
            encoded_signature_length,
            data,
            data_length
        );
        if (result < 0) {
            result = -EIO;
        }
    }

    EVP_MD_CTX_free(context);
    free(encoded_signature);
    EVP_PKEY_free(public_key);
    return result;
}

int resolved_dnssec_digest(
    uint8_t digest_type,
    const void *data,
    size_t length,
    uint8_t *output,
    size_t capacity
) {
    const EVP_MD *digest;
    unsigned int output_length = 0;
    int expected;

    if (data == NULL || output == NULL) {
        return -EINVAL;
    }

    switch (digest_type) {
    case 1:
        digest = EVP_sha1();
        break;
    case 2:
        digest = EVP_sha256();
        break;
    case 4:
        digest = EVP_sha384();
        break;
    default:
        return -EOPNOTSUPP;
    }

    expected = EVP_MD_size(digest);
    if (expected <= 0 || capacity < (size_t)expected) {
        return -ENOBUFS;
    }
    if (EVP_Digest(data, length, output, &output_length, digest, NULL) != 1) {
        return -EIO;
    }
    if (output_length != (unsigned int)expected) {
        return -EIO;
    }
    return (int)output_length;
}
