#ifndef __NXPS32K3X8EVB_TPM__ 
#define __NXPS32K3X8EVB_TPM__ 

#include "stdint.h"
#include "stdbool.h"

#define TPM_BASE_ADDRESS                        ( 0xF0000000UL )
#define TPM_SIZE                                ( 4 * 1024 )
#define NXPS32K3X8EVB_TPM_BASE_ADDRESS          TPM_BASE_ADDRESS
#define NXPS32K3X8EVB_TPM_SIZE                  TPM_SIZE 

#define TPM_ACCESS          (*(volatile uint8_t *)(TPM_BASE_ADDRESS + 0x00))    // Used to gain ownership of the TPM for this locality (only 0 implemented)
#define TPM_INT_ENABLE      (*(volatile uint8_t *)(TPM_BASE_ADDRESS + 0x00))    // Interrupt configuration register
#define TPM_INT_VECTOR      (*(volatile uint8_t *)(TPM_BASE_ADDRESS + 0x00))    // SIRQ vector used by the TPM
#define TPM_INT_STATUS      (*(volatile uint8_t *)(TPM_BASE_ADDRESS + 0x18))    // Shows which interrupt has occured 
#define TPM_INTF_CAPABILITY (*(volatile uint8_t *)(TPM_BASE_ADDRESS + 0x24))    // Provides the information about supported interrupts
#define TPM_STS             (*(volatile uint8_t *)(TPM_BASE_ADDRESS + 0x24))    // Status register
#define TPM_DATA_FIFO       (*(volatile uint8_t *)(TPM_BASE_ADDRESS + 0x24))    // ReadFIFO or WriteFIFO depending on the bus sycle
#define TPM_XDATA_FIFO      (*(volatile uint8_t *)(TPM_BASE_ADDRESS + 0x24))    // Extended ReadFIFO or WriteFIFO

typedef struct {
    uint8_t     access;
    uint32_t    sts;
    uint8_t     fifo[256];
    uint32_t    cmd_len;
    uint32_t    cmd_idx;
    bool        is_ready;
} TPMDevice;



#endif
