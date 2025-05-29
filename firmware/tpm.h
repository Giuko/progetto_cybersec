#ifndef __TPMH__
#define __TPMH__

#include <stdint.h>
#include <stdbool.h>

/* Peripheral memory region */
#define TPM_BASE_ADDRESS                        ( 0xF0000000UL )
#define TPM_SIZE                                ( 4 * 1024 )

// MACROS to access MMIO
#define mmio_read8(addr) (*(volatile uint8_t *)(addr))
#define mmio_write8(addr, val) (*(volatile uint8_t *)(addr) = (val))

/* TPM Interface Specification Registers */
#define TPM_ACCESS      0x00
#define TPM_STS         0x18
#define TPM_DATA_FIFO   0x24

/* TPM Status Register Flags */
#define TPM_STS_ERROR       0x01        // bit 0
#define TPM_STS_DATA_EXPECT 0x04        // bit 2
#define TPM_STS_DATA_AVAIL  0x10        // bit 4
#define TPM_STS_GO          0x20        // bit 5
#define TPM_STS_CMD_READY   0x40        // bit 6
#define TPM_STS_VALID       0x80        // bit 7

/* TPM Command Codes */
#define TPM2_CC_NV_DefineSpace      0x0000012A
#define TPM2_CC_SelfTest            0x00000143
#define TPM2_CC_Startup             0x00000144
#define TPM2_CC_Shatdown            0x00000145
#define TPM2_CC_StartAuthSession    0x00000176
#define TPM2_CC_GetCapability       0x0000017A
#define TPM2_CC_GetRandom           0x0000017B

/* TPM TAG */
#define TAG_TPM_ST_NO_SESSIONS      0x8001  // Command uses no authorization sessions (password-based authorization)
#define TAG_TPM_ST_SESSIONS         0x8002  // Command uses authorization sessions
#define TAG_TPM_ST_ATTEST_NV        0x8003  // Used for NV attestation

/* TPM Command Header */
struct tpm_command_header{
    uint16_t tag;
    uint32_t size;
    uint32_t command_code;
} __attribute__((packed));      // To avoid padding

/* TPM Response Header */
struct tpm_response_header{
    uint16_t tag;
    uint32_t size;
    uint32_t response_code;
} __attribute__((packed));      // To avoid padding

enum tpm_state {
    TPM_STATE_IDLE,
    TPM_STATE_READY,
    TPM_STATE_RECEIVING,
    TPM_STATE_PROCESSING,
    TPM_STATE_SENDING
};

/* TPM Interface */
struct tpm_device {
    void *mmio_base;
    uint8_t command_buffer[256];
    uint8_t response_buffer[256];
    uint32_t cmd_size;
    uint32_t resp_size;
    enum tpm_state state;
};

/* Basic Function */
void tpm_init(struct tpm_device *dev, void *base_address);

int tpm_send_command(struct tpm_device *dev, void *command, uint32_t size);
int tpm_receive_response(struct tpm_device *dev, void *buffer, uint32_t max_size);


/* Helper and log function */

const char* tpm_command_name(uint32_t command_code);
int tpm_send_command_with_log(struct tpm_device *dev, void *command, uint32_t size);
int tpm_receive_response_with_log(struct tpm_device *dev, void *buffer, uint32_t max_size);
void log_tpm_status(struct tpm_device *dev);
#endif
