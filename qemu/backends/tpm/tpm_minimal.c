#include "qemu/osdep.h"
#include "hw/tpm/tpm_backend.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "qemu/log.h"
#include "trace.h"

typedef struct TPMMinimalState {
	TPMBackendState parent;
} TPMMinimalState;

static TPMBackend *tpm_minimal_create



