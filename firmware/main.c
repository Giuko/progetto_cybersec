#include "uart.h"
#include "tpm.h"
#include <stdint.h>

int main(void) {
    UART_init();
    struct tpm_device tpm;

    UART_putstr("Initializing TPM...\n");
    tpm_init(&tpm, (void*)TPM_BASE_ADDRESS);
    log_tpm_status(&tpm);
    
    struct tpm_command_header cmd_header = {
        .tag = TAG_TPM_ST_NO_SESSIONS,      
        .command_code = TPM2_CC_Startup,
        .size = sizeof(struct tpm_startup_command_header)
    };
    struct tpm_startup_command_header cmd = {
        .command_header = cmd_header,
        .startup_type = TPM_SU_CLEAR
    };
    
    UART_putstr("\nSending Startup command...\n");
    tpm_send_command_with_log(&tpm, &cmd, cmd.command_header.size);
    log_tpm_status(&tpm);
    
    //uint8_t response[128];
    struct tpm_response_header *response = 0;
    tpm_receive_response_with_log(&tpm, response, sizeof(struct tpm_response_header));
    
    if(response->response_code == 0)
        UART_putstr("Success code received\n");
    else
        UART_putstr("Error code received\n");


    // Trying self test
    cmd_header.command_code = TPM2_CC_SelfTest;
    cmd_header.size = sizeof(struct tpm_command_header);
 
    UART_putstr("\nSending SelfTest command...\n");
    tpm_send_command_with_log(&tpm, &cmd_header, cmd_header.size);
    log_tpm_status(&tpm);
     
    //uint8_t response[128];
    tpm_receive_response_with_log(&tpm, response, sizeof(struct tpm_response_header));
    
    if(response->response_code == 0)
        UART_putstr("Success code received\n");
    else
        UART_putstr("Error code received\n");


   
    return 0;
}
