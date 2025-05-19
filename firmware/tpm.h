#ifndef __TPMH__
#define __TPMH__

#include <stdint.h>
#include <stdbool.h>

#define TPM_BASE_ADDRESS                        ( 0xF0000000UL )
#define TPM_SIZE                                ( 4 * 1024 )

#define TPM_ACCESS          (*(volatile uint8_t *)(TPM_BASE_ADDRESS + 0x00))    // Used to gain ownership of the TPM for this locality (only 0 implemented)
#define TPM_INT_ENABLE      (*(volatile uint8_t *)(TPM_BASE_ADDRESS + 0x08))    // Interrupt configuration register
#define TPM_INT_VECTOR      (*(volatile uint8_t *)(TPM_BASE_ADDRESS + 0x0C))    // SIRQ vector used by the TPM
#define TPM_INT_STATUS      (*(volatile uint8_t *)(TPM_BASE_ADDRESS + 0x10))    // Shows which interrupt has occured 
#define TPM_INTF_CAPABILITY (*(volatile uint8_t *)(TPM_BASE_ADDRESS + 0x14))    // Provides the information about supported interrupts
#define TPM_STS             (*(volatile uint8_t *)(TPM_BASE_ADDRESS + 0x18))    // Status register
#define TPM_DATA_FIFO       (*(volatile uint8_t *)(TPM_BASE_ADDRESS + 0x24))    // ReadFIFO or WriteFIFO depending on the bus sycle
#define TPM_XDATA_FIFO      (*(volatile uint8_t *)(TPM_BASE_ADDRESS + 0x80))    // Extended ReadFIFO or WriteFIFO

typedef struct {
    uint8_t     access;
    uint32_t    int_enable;
    uint8_t     int_vector;
    uint32_t    int_status;
    uint32_t    intf_capability;
    uint32_t    sts;
    uint8_t     fifo[256];
    uint32_t    cmd_len;
    uint32_t    cmd_idx;
    bool        is_ready;
} TPMStruct;

void TPM_write(uint8_t data);
uint8_t TPM_read(void);
void TPM_GainOwnership(void);
void TPM_EnableInterrupts(void);
void TPM_WriteFIFO(TPMStruct *tpm);
uint8_t TPM_ReadFIFO(TPMStruct *tpm);


#endif
