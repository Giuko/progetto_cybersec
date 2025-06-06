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
#include "qapi-types-cryptodev.h"
#include "qapi-visit-cryptodev.h"
#include "qapi-features.h"

const QEnumLookup QCryptodevBackendAlgoType_lookup = {
    .array = (const char *const[]) {
        [QCRYPTODEV_BACKEND_ALGO_TYPE_SYM] = "sym",
        [QCRYPTODEV_BACKEND_ALGO_TYPE_ASYM] = "asym",
    },
    .size = QCRYPTODEV_BACKEND_ALGO_TYPE__MAX
};

const QEnumLookup QCryptodevBackendServiceType_lookup = {
    .array = (const char *const[]) {
        [QCRYPTODEV_BACKEND_SERVICE_TYPE_CIPHER] = "cipher",
        [QCRYPTODEV_BACKEND_SERVICE_TYPE_HASH] = "hash",
        [QCRYPTODEV_BACKEND_SERVICE_TYPE_MAC] = "mac",
        [QCRYPTODEV_BACKEND_SERVICE_TYPE_AEAD] = "aead",
        [QCRYPTODEV_BACKEND_SERVICE_TYPE_AKCIPHER] = "akcipher",
    },
    .size = QCRYPTODEV_BACKEND_SERVICE_TYPE__MAX
};

const QEnumLookup QCryptodevBackendType_lookup = {
    .array = (const char *const[]) {
        [QCRYPTODEV_BACKEND_TYPE_BUILTIN] = "builtin",
        [QCRYPTODEV_BACKEND_TYPE_VHOST_USER] = "vhost-user",
        [QCRYPTODEV_BACKEND_TYPE_LKCF] = "lkcf",
    },
    .size = QCRYPTODEV_BACKEND_TYPE__MAX
};

void qapi_free_QCryptodevBackendClient(QCryptodevBackendClient *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptodevBackendClient(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptodevBackendServiceTypeList(QCryptodevBackendServiceTypeList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptodevBackendServiceTypeList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptodevBackendClientList(QCryptodevBackendClientList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptodevBackendClientList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptodevInfo(QCryptodevInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptodevInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_QCryptodevInfoList(QCryptodevInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_QCryptodevInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

/* Dummy declaration to prevent empty .o file */
char qapi_dummy_qapi_types_cryptodev_c;
