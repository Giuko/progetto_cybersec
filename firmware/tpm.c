#include "tpm.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>



// ############### COMMAND HEADER VALIDATION ###############
// Command header structure:
//TPMI_ST_COMMAND_TAG (2B) | UINT32 commandSize (4B)| TPM_CC commandCode

typedef uint16_t TPMI_ST_COMMAND_TAG;
typedef uint32_t TPM_CC;

// Sample list of implemented commands
const TPM_CC implemented_commands[] = {
    0x0000017A,  // TPM2_StartAuthSession
    0x00000153,  // TPM2_Hash
    0x0000017B   // TPM2_PolicyAuthValue
};

int is_command_supported(TPM_CC cc) {
    for (size_t i = 0; i < sizeof(implemented_commands)/sizeof(TPM_CC); i++) {
        if (implemented_commands[i] == cc) return 1;
    }
    return 0;
}

uint32_t validate_command_header(const uint8_t *buffer, size_t buffer_len) {
    if (buffer_len < 10) return TPM_RC_COMMAND_SIZE; // Not enough for header: min size is 10 (10 + 2 optional)

    TPMI_ST_COMMAND_TAG tag = (buffer[0] << 8) | buffer[1];
    if (tag != TPM_ST_NO_SESSIONS && tag != TPM_ST_SESSIONS) {
        return TPM_RC_BAD_TAG;
    }

    uint32_t commandSize = (buffer[2] << 24) | (buffer[3] << 16) |
                           (buffer[4] << 8) | buffer[5];
    if (commandSize != buffer_len) {
        return TPM_RC_COMMAND_SIZE;
    }

    TPM_CC commandCode = (buffer[6] << 24) | (buffer[7] << 16) |
                         (buffer[8] << 8) | buffer[9];
    if (!is_command_supported(commandCode)) {
        return TPM_RC_COMMAND_CODE;
    }

    return TPM_RC_SUCCESS;
}


