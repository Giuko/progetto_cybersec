#include "uart.h"
#include "tpm.h"

#include <string.h>
#include <stdio.h>

uint8_t command_buffer[] = {
    0x80, 0x01,  // TPM_ST_NO_SESSIONS
    0x00, 0x00, 0x00, 0x0C,  // commandSize = 12 bytes
    0x00, 0x00, 0x01, 0x53   // TPM2_Hash command code
};

int main(void){
    int i = 5;
    UART_init();
    UART_printf("Hello board\n");

    volatile uint8_t *tpm = (volatile uint8_t *)TPM_ADDRESS;

    // Write a dumb byte (e.g., 0xAA) to the TPM base address
    tpm[0] = 0xAA;

    // Optional: read back (may not make sense depending on what TPM expects)
    uint8_t value = tpm[0];

    

    // uint32_t rc = validate_command_header(command_buffer, sizeof(command_buffer));
    // if (rc == TPM_RC_SUCCESS) {
    //     UART_printf("Command header is valid\n");
    // } else {
    //     char error_message[50];
    //     snprintf(error_message, sizeof(error_message), "Error: 0x%X\n", rc);
    //     UART_printf(error_message);
    // }

    return 0;
}
