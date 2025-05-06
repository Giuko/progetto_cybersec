#ifndef __TPMH__
#define __TPMH__

#include <stdint.h>
#include <stddef.h>

#define TPM_ADDRESS                         ( 0xE0000000UL )
#define TPM_SIZE                            ( 4 * 1024 )

#define TPM_RC_SUCCESS            0x000
#define TPM_RC_BAD_TAG            0x01E
#define TPM_RC_COMMAND_SIZE       0x01D
#define TPM_RC_COMMAND_CODE       0x014

#define TPM_ST_NO_SESSIONS        0x8001
#define TPM_ST_SESSIONS           0x8002

//void is_command_supported(TPM_CC);
//uint32_t validate_command_header(const uint8_t, size_t );

#endif
