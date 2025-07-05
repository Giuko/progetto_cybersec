#include "tpm.h"
#include "uart.h"
#include <stdint.h>

void tpm_init(struct tpm_device *dev, void *base_address){
    dev->mmio_base = base_address;
    dev->state = TPM_STATE_IDLE;
    dev->cmd_size = 0;
    dev->resp_size = 0;

    // Reset TPM to ready state
    mmio_write8(dev->mmio_base+TPM_STS, TPM_STS_CMD_READY|TPM_STS_VALID);
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
    UART_init();
    // Wait for data availability
    if(wait_for_status(dev, TPM_STS_DATA_AVAIL, TPM_STS_DATA_AVAIL))
        return -1;

    struct tpm_response_header *res = (struct tpm_response_header *)buffer;
    // Standard response 10 is ok
    for(int i = 0; i < 10; i++){
        ((uint8_t *)res)[i] = mmio_read8(dev->mmio_base + TPM_DATA_FIFO);
    }
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

const char* tpm_command_name(uint32_t command_code) {
    switch(command_code) {
        case TPM2_CC_Startup: return "Startup";
        case TPM2_CC_GetCapability: return "GetCapability";
        case TPM2_CC_SelfTest: return "SelfTest";
        case TPM2_CC_CreatePrimary: return "CreatePrimary";
        case TPM2_CC_Create: return "Create";
        case TPM2_CC_Shutdown: return "Shutdown";
        case TPM2_CC_RSA_Decrypt: return "RSA Decrypt";
        case TPM2_CC_RSA_Encrypt: return "RSA Encrypt";
        default: return "Unknown";
    }
}

int tpm_send_command_with_log(struct tpm_device *dev, void *command, uint32_t size){
    struct tpm_command_header *hdr = (struct tpm_command_header *)command;
    
    UART_putstr("Sending command: 0x");
    UART_puthex(hdr->command_code);
    UART_putstr(" (");
    UART_putstr(tpm_command_name(hdr->command_code));
    UART_putstr("), size: ");
    UART_puthex(size);
    UART_putstr("\n");

    int result = tpm_send_command(dev, command, size);
    if(result != 0) {
        UART_putstr("[TPM] Error sending command!\n");
    }
    return result;
}

int tpm_receive_response_with_log(struct tpm_device *dev, void *buffer, uint32_t max_size){
    UART_putstr("Waiting for response...\n");
    int result = tpm_receive_response(dev, buffer, max_size); 
    struct tpm_response_header *response;
    response = buffer;
    if(result > 0) {
        UART_putstr("Tag: 0x");
        //uint8_t tag = response[1] >> 8 | response[0];
        UART_puthex_byte(response->tag);
        UART_println();

        UART_putstr("Size: 0x");
        //uint16_t size = response[9] >> 24 | response[8] >> 16 | response[7] >> 8 | response[6];
        UART_puthex(response->size);
        UART_println();

        UART_putstr("Response code: 0x");
        //uint16_t response_code = response[5] >> 24 | response[4] >> 16 | response[3] >> 8 | response[2];
        UART_puthex(response->response_code);
        UART_println();
    }
    
    return result;
}

void log_tpm_status(struct tpm_device *dev) {
    uint8_t status = mmio_read8(dev->mmio_base + TPM_STS);
    UART_putstr("Status: 0x");
    UART_puthex(status);
    UART_putstr(" [ ");
    if(status & TPM_STS_ERROR) UART_putstr("ERROR ");
    if(status & TPM_STS_DATA_EXPECT) UART_putstr("DATA_EXPECT ");
    if(status & TPM_STS_DATA_AVAIL) UART_putstr("DATA_AVAIL ");
    if(status & TPM_STS_GO) UART_putstr("GO ");
    if(status & TPM_STS_CMD_READY) UART_putstr("CMD_READY ");
    if(status & TPM_STS_VALID) UART_putstr("VALID ");
    UART_putstr("]\n");
}
