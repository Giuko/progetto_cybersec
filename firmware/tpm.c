#include "tpm.h"
#include <stdint.h>

void tpm_init(struct tpm_device *dev, void *base_address){
    dev->mmio_base = base_address;
    dev->state = TPM_STATE_IDLE;
    dev->cmd_size = 0;
    dev->resp_size = 0;

    // Reset TPM to ready state
    mmio_write8(dev->mmio_base+TPM_STS, TPM_STS_CMD_READY);
}

static int wait_for_status(struct tpm_device *dev, uint8_t mask, uint8_t value){
    int timeout = 50;       // Simulating waiting for peripheral
    while(timeout-- > 0){
        uint8_t status = mmio_read8(dev->mmio_base+TPM_STS);
        if((status & mask)==value)
            return 0;
    }
    return -1; // Timeout error
}

int tpm_send_command(struct tpm_device *dev, void *command, uint32_t size){
    // Check command size
    if(size > sizeof(dev->command_buffer))
        return -1;

    // Wait for command ready
    if(wait_for_status(dev, TPM_STS_CMD_READY, TPM_STS_CMD_READY))
        return -1;

    // Write command to FIFO
    uint8_t *cmd = (uint8_t *)command;
    for(int i = 0; i < size; i++){
        mmio_write8(dev->mmio_base+TPM_DATA_FIFO, cmd[i]);
    }

    // Trigger command execution
    mmio_write8(dev->mmio_base+TPM_STS, TPM_STS_GO);
    
    dev->state = TPM_STATE_PROCESSING;
    return 0;
}

int tpm_receive_response(struct tpm_device *dev, void *buffer, uint32_t max_size){
    // Wait for data availability
    if(wait_for_status(dev, TPM_STS_DATA_AVAIL, TPM_STS_DATA_AVAIL))
        return -1;

    struct tpm_response_header *res = (struct tpm_response_header *)buffer;
    // Standard response 10 is ok
    for(int i = 0; i < 10; i++)
        ((uint8_t *)res)[i] = mmio_read8(dev->mmio_base + TPM_DATA_FIFO);

    if(res->size > max_size || res->size < 10)
        return -1;

    uint32_t remaining = res->size-10;
    uint8_t *buf_ptr = (uint8_t*)buffer + 10;

    for(int i = 0; i < remaining; i++)
        buf_ptr[i] = mmio_read8(dev->mmio_base+TPM_DATA_FIFO);


    // Clear status
    mmio_write8(dev->mmio_base+TPM_STS, TPM_STS_CMD_READY);

    dev->state = TPM_STATE_READY;
    return res->size;
}



