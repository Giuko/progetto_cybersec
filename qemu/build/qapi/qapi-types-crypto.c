/* AUTOMATICALLY GENERATED by qapi-gen.py DO NOT MODIFY */

/*
 * Schema-defined QAPI types
 *
 * Copyright IBM, Corp. 2011
 * Copyright (c) 2013-2018 Red Hat Inc.
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qapi/dealloc-visitor.h"
#include "qapi-types-crypto.h"
#include "qapi-visit-crypto.h"
#include "qapi-features.h"

const QEnumLookup QCryptoTLSCredsEndpoint_lookup = {
    .array = (const char *const[]) {
        [QCRYPTO_TLS_CREDS_ENDPOINT_CLIENT] = "client",
        [QCRYPTO_TLS_CREDS_ENDPOINT_SERVER] = "server",
    },
    .size = QCRYPTO_TLS_CREDS_ENDPOINT__MAX
};

const QEnumLookup QCryptoSecretFormat_lookup = {
    .array = (const char *const[]) {
        [QCRYPTO_SECRET_FORMAT_RAW] = "raw",
        [QCRYPTO_SECRET_FORMAT_BASE64] = "base64",
    },
    .size = QCRYPTO_SECRET_FORMAT__MAX
};

const QEnumLookup QCryptoHashAlgo_lookup = {
    .array = (const char *const[]) {
        [QCRYPTO_HASH_ALGO_MD5] = "md5",
        [QCRYPTO_HASH_ALGO_SHA1] = "sha1",
        [QCRYPTO_HASH_ALGO_SHA224] = "sha224",
        [QCRYPTO_HASH_ALGO_SHA256] = "sha256",
        [QCRYPTO_HASH_ALGO_SHA384] = "sha384",
        [QCRYPTO_HASH_ALGO_SHA512] = "sha512",
        [QCRYPTO_HASH_ALGO_RIPEMD160] = "ripemd160",
        [QCRYPTO_HASH_ALGO_SM3] = "sm3",
    },
    .size = QCRYPTO_HASH_ALGO__MAX
};

const QEnumLookup QCryptoCipherAlgo_lookup = {
    .array = (const char *const[]) {
        [QCRYPTO_CIPHER_ALGO_AES_128] = "aes-128",
        [QCRYPTO_CIPHER_ALGO_AES_192] = "aes-192",
        [QCRYPTO_CIPHER_ALGO_AES_256] = "aes-256",
        [QCRYPTO_CIPHER_ALGO_DES] = "des",
        [QCRYPTO_CIPHER_ALGO_3DES] = "3des",
        [QCRYPTO_CIPHER_ALGO_CAST5_128] = "cast5-128",
        [QCRYPTO_CIPHER_ALGO_SERPENT_128] = "serpent-128",
        [QCRYPTO_CIPHER_ALGO_SERPENT_192] = "serpent-192",
        [QCRYPTO_CIPHER_ALGO_SERPENT_256] = "serpent-256",
        [QCRYPTO_CIPHER_ALGO_TWOFISH_128] = "twofish-128",
        [QCRYPTO_CIPHER_ALGO_TWOFISH_192] = "twofish-192",
        [QCRYPTO_CIPHER_ALGO_TWOFISH_256] = "twofish-256",
        [QCRYPTO_CIPHER_ALGO_SM4] = "sm4",
    },
    .size = QCRYPTO_CIPHER_ALGO__MAX
};

const QEnumLookup QCryptoCipherMode_lookup = {
    .array = (const char *const[]) {
        [QCRYPTO_CIPHER_MODE_ECB] = "ecb",
        [QCRYPTO_CIPHER_MODE_CBC] = "cbc",
        [QCRYPTO_CIPHER_MODE_XTS] = "xts",
        [QCRYPTO_CIPHER_MODE_CTR] = "ctr",
    },
    .size = QCRYPTO_CIPHER_MODE__MAX
};

const QEnumLookup QCryptoIVGenAlgo_lookup = {
    .array = (const char *const[]) {
        [QCRYPTO_IV_GEN_ALGO_PLAIN] = "plain",
        [QCRYPTO_IV_GEN_ALGO_PLAIN64] = "plain64",
        [QCRYPTO_IV_GEN_ALGO_ESSIV] = "essiv",
    },
    .size = QCRYPTO_IV_GEN_ALGO__MAX
};

const QEnumLookup QCryptoBlockFormat_lookup = {
    .array = (const char *const[]) {
        [QCRYPTO_BLOCK_FORMAT_QCOW] = "qcow",
        [QCRYPTO_BLOCK_FORMAT_LUKS] = "luks",
    },
    .size = QCRYPTO_BLOCK_FORMAT__MAX
};

void qapi_free_QCryptoBlockOptionsBase(QCryptoBlockOptionsBase *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockOptionsBase(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockOptionsQCow(QCryptoBlockOptionsQCow *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockOptionsQCow(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockOptionsLUKS(QCryptoBlockOptionsLUKS *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockOptionsLUKS(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockCreateOptionsLUKS(QCryptoBlockCreateOptionsLUKS *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockCreateOptionsLUKS(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockOpenOptions(QCryptoBlockOpenOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockOpenOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockCreateOptions(QCryptoBlockCreateOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockCreateOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockInfoBase(QCryptoBlockInfoBase *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockInfoBase(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockInfoLUKSSlot(QCryptoBlockInfoLUKSSlot *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockInfoLUKSSlot(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockInfoLUKSSlotList(QCryptoBlockInfoLUKSSlotList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockInfoLUKSSlotList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockInfoLUKS(QCryptoBlockInfoLUKS *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockInfoLUKS(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockInfo(QCryptoBlockInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

const QEnumLookup QCryptoBlockLUKSKeyslotState_lookup = {
    .array = (const char *const[]) {
        [QCRYPTO_BLOCK_LUKS_KEYSLOT_STATE_ACTIVE] = "active",
        [QCRYPTO_BLOCK_LUKS_KEYSLOT_STATE_INACTIVE] = "inactive",
    },
    .size = QCRYPTO_BLOCK_LUKS_KEYSLOT_STATE__MAX
};

void qapi_free_QCryptoBlockAmendOptionsLUKS(QCryptoBlockAmendOptionsLUKS *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockAmendOptionsLUKS(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoBlockAmendOptions(QCryptoBlockAmendOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoBlockAmendOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SecretCommonProperties(SecretCommonProperties *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SecretCommonProperties(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_SecretProperties(SecretProperties *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SecretProperties(v, NULL, &obj, NULL);
    visit_free(v);
}

#if defined(CONFIG_SECRET_KEYRING)
void qapi_free_SecretKeyringProperties(SecretKeyringProperties *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_SecretKeyringProperties(v, NULL, &obj, NULL);
    visit_free(v);
}
#endif /* defined(CONFIG_SECRET_KEYRING) */

void qapi_free_TlsCredsProperties(TlsCredsProperties *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_TlsCredsProperties(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_TlsCredsAnonProperties(TlsCredsAnonProperties *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_TlsCredsAnonProperties(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_TlsCredsPskProperties(TlsCredsPskProperties *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_TlsCredsPskProperties(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_TlsCredsX509Properties(TlsCredsX509Properties *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_TlsCredsX509Properties(v, NULL, &obj, NULL);
    visit_free(v);
}

const QEnumLookup QCryptoAkCipherAlgo_lookup = {
    .array = (const char *const[]) {
        [QCRYPTO_AK_CIPHER_ALGO_RSA] = "rsa",
    },
    .size = QCRYPTO_AK_CIPHER_ALGO__MAX
};

const QEnumLookup QCryptoAkCipherKeyType_lookup = {
    .array = (const char *const[]) {
        [QCRYPTO_AK_CIPHER_KEY_TYPE_PUBLIC] = "public",
        [QCRYPTO_AK_CIPHER_KEY_TYPE_PRIVATE] = "private",
    },
    .size = QCRYPTO_AK_CIPHER_KEY_TYPE__MAX
};

const QEnumLookup QCryptoRSAPaddingAlgo_lookup = {
    .array = (const char *const[]) {
        [QCRYPTO_RSA_PADDING_ALGO_RAW] = "raw",
        [QCRYPTO_RSA_PADDING_ALGO_PKCS1] = "pkcs1",
    },
    .size = QCRYPTO_RSA_PADDING_ALGO__MAX
};

void qapi_free_QCryptoAkCipherOptionsRSA(QCryptoAkCipherOptionsRSA *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoAkCipherOptionsRSA(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptoAkCipherOptions(QCryptoAkCipherOptions *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptoAkCipherOptions(v, NULL, &obj, NULL);
    visit_free(v);
}

/* Dummy declaration to prevent empty .o file */
char qapi_dummy_qapi_types_crypto_c;
