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

#ifndef QAPI_TYPES_UEFI_H
#define QAPI_TYPES_UEFI_H

#include "qapi/qapi-builtin-types.h"

typedef struct UefiVariable UefiVariable;

typedef struct UefiVariableList UefiVariableList;

typedef struct UefiVarStore UefiVarStore;

struct UefiVariable {
    char *guid;
    char *name;
    int64_t attr;
    char *data;
    char *time;
    char *digest;
};

void qapi_free_UefiVariable(UefiVariable *obj);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(UefiVariable, qapi_free_UefiVariable)

struct UefiVariableList {
    UefiVariableList *next;
    UefiVariable *value;
};

void qapi_free_UefiVariableList(UefiVariableList *obj);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(UefiVariableList, qapi_free_UefiVariableList)

struct UefiVarStore {
    int64_t version;
    UefiVariableList *variables;
};

void qapi_free_UefiVarStore(UefiVarStore *obj);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(UefiVarStore, qapi_free_UefiVarStore)

#endif /* QAPI_TYPES_UEFI_H */
