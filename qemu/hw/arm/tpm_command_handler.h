#ifndef __TPM__COMMAND_HANDLER__
#define __TPM__COMMAND_HANDLER__

#include <stdint.h>

typedef struct {
    uint32_t primaryHandle;
    uint16_t inSensitive;
    uint16_t inPublic;
    uint16_t outsideInfo;
    uint32_t creationPCR;
} TPM2_CreatePrimary_Cmd;


#endif //__TPM__COMMAND_HANDLER__
