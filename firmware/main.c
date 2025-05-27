#include "uart.h"
#include "tpm.h"
#include <string.h>
#include <stdio.h>

// Helper function to print TPM command names
static const char* tpm_command_name(uint32_t command_code) {
    switch(command_code) {
        case TPM2_CC_Startup: return "Startup";
        case TPM2_CC_GetCapability: return "GetCapability";
        case TPM2_CC_SelfTest: return "SelfTest";
        default: return "Unknown";
    }
}

// Enhanced TPM functions with logging
int tpm_send_command_with_log(struct tpm_device *dev, void *command, uint32_t size)
{
    struct tpm_command_header *hdr = (struct tpm_command_header *)command;
    
    UART_putstr("[TPM] Sending command: 0x");
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

int tpm_receive_response_with_log(struct tpm_device *dev, void *buffer, uint32_t max_size)
{
    UART_putstr("[TPM] Waiting for response...\n");
    int result = tpm_receive_response(dev, buffer, max_size);
    
    if(result > 0) {
        struct tpm_response_header *hdr = (struct tpm_response_header *)buffer;
        UART_putstr("[TPM] Received response: ");
        UART_putstr("Code: 0x");
        UART_puthex(hdr->response_code);
        UART_putstr(", Size: ");
        UART_puthex(hdr->size);
        UART_putstr("\n");
    } else {
        UART_putstr("[TPM] Error receiving response!\n");
    }
    
    return result;
}

// Log TPM status register
void log_tpm_status(struct tpm_device *dev) {
    uint8_t status = mmio_read8(dev->mmio_base + TPM_STS);
    UART_putstr("[TPM] Status: 0x");
    UART_puthex(status);
    UART_putstr(" [");
    if(status & TPM_STS_VALID) UART_putstr("VALID ");
    if(status & TPM_STS_CMD_READY) UART_putstr("CMD_READY ");
    if(status & TPM_STS_GO) UART_putstr("GO ");
    if(status & TPM_STS_DATA_AVAIL) UART_putstr("DATA_AVAIL");
    UART_putstr("]\n");
}

int main(void) {
    UART_init();
    struct tpm_device tpm;

    UART_putstr("Initializing TPM...\n");
    tpm_init(&tpm, (void*)TPM_BASE_ADDRESS);
    log_tpm_status(&tpm);

    // Example: Get Capability command
    struct tpm_command_header cmd = {
        .tag = 0x8001,
        .command_code = TPM2_CC_GetCapability,
        .size = sizeof(struct tpm_command_header)
    };
    
    UART_putstr("\nSending GetCapability command...\n");
    tpm_send_command_with_log(&tpm, &cmd, cmd.size);
    log_tpm_status(&tpm);

    uint8_t response[128];
    int resp_size = tpm_receive_response_with_log(&tpm, response, sizeof(response));
    
    if(resp_size > 0) {
        UART_putstr("Response data: ");
        for(int i = 0; i < resp_size; i++) {
            UART_puthex(response[i]);
            UART_putstr(" ");
        }
        UART_putstr("\n");
    }

    return 0;
}
