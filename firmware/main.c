#include "uart.h"
#include "tpm.h"
#include <stdint.h>


// Enhanced TPM functions with logging


// Log TPM status register

int main(void) {
    UART_init();
    struct tpm_device tpm;

    UART_putstr("Initializing TPM...\n");
    tpm_init(&tpm, (void*)TPM_BASE_ADDRESS);
    log_tpm_status(&tpm);
    
    // Example: Self Test
    struct tpm_command_header cmd = {
        .tag = TAG_TPM_ST_NO_SESSIONS,      
        .command_code = TPM2_CC_SelfTest,
        .size = sizeof(struct tpm_command_header)
    };
    
    UART_putstr("\nSending SelfTest command...\n");
    tpm_send_command_with_log(&tpm, &cmd, cmd.size);
    log_tpm_status(&tpm);
    
    //uint8_t response[128];
    struct tpm_response_header *response = 0;
    tpm_receive_response_with_log(&tpm, response, sizeof(struct tpm_response_header));
    
    if(response->response_code == 0)
        UART_putstr("Success code received\n");
    else
        UART_putstr("Error code received\n");

    return 0;
}
