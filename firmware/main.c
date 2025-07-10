#include "uart.h"
#include "tpm.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    UART_init();
    struct tpm_device tpm;

    UART_putstr("Initializing TPM...\n");
    tpm_init(&tpm, (void*)TPM_BASE_ADDRESS);
    log_tpm_status(&tpm);
    
    struct tpm_command_header cmd_header = {
        .tag = TPM_ST_NO_SESSION,      
        .command_code = TPM2_CC_Startup,
        .size = sizeof(struct tpm_startup_command_header)
    };
    struct tpm_startup_command_header cmd = {
        .command_header = cmd_header,
        .startup_type = TPM_SU_CLEAR
    };
    
    // Trying Startup command
    UART_putstr("\nSending Startup command...\n");
    tpm_send_command_with_log(&tpm, &cmd, cmd.command_header.size);
    log_tpm_status(&tpm);
    
    //uint8_t response[128];
    struct tpm_response_header *response_header = (struct tpm_response_header *)malloc(sizeof(struct tpm_response_header));
    tpm_receive_response_with_log(&tpm, response_header, sizeof(struct tpm_response_header));
    
    if(response_header->response_code == 0)
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
    tpm_receive_response_with_log(&tpm, response_header, sizeof(struct tpm_response_header));
    
    if(response_header->response_code == 0)
        UART_putstr("Success code received\n");
    else
        UART_putstr("Error code received\n");


    /* ***************************************************** */
    /*              Create Primary                           */

    struct tpm_createPrimary_response *createPrimary_response = createPrimary(&tpm);
    uint32_t primary_handle = createPrimary_response->objectHandle;

    /* ***************************************************** */
    /*                     Create                            */

    struct tpm_create_response *create_response = create(&tpm, primary_handle);
    /* ***************************************************** */
    /*                 RSA_Ecrypt                            */
   
    char text[] = "This is a text";
    size_t text_size = sizeof(text);
    struct TMP_RSA_encrypt_response *enc_response = encrypt(&tpm, primary_handle, text, text_size);
    
    uint8_t *cipherText = enc_response->outData.buffer;
    size_t cipherText_size = enc_response->outData.size;

    // Trying RSA_Dencrypt command
    cmd_header.tag = TPM_ST_SESSION;
    cmd_header.command_code = TPM2_CC_RSA_Decrypt;
    cmd_header.size = sizeof(struct tpm_create_command);
    const char *message_RCA_dec = "Hello, TPM!";
    size_t msg_len_dec = strlen(message_RCA_dec);
    struct TMP_RSA_decrypt_command RCA_dec_cmd = {
        .command_header = cmd_header,
        .keyHandle = createPrimary_response->objectHandle, 
        .cipherText = {
            .size = sizeof(message_RCA_dec), // Size of the message
            .buffer = {0} // Copying the message
        },
        .inScheme = {
            .scheme = TPM_ALG_NULL, // No scheme for RSA encryption  
            .details = {
                .rsaes = {
                    .empty = {0}      
                }
            }
        },
        .label = {
            .size = 64, // No label for RSA encryption
            .buffer = {0} // No label for RSA encryption
        }
    };

    memcpy(RCA_dec_cmd.cipherText.buffer, message_RCA_dec, msg_len_dec);
    

    UART_putstr("\nSending RSA_Dencrypt command...\n");
    tpm_send_command_with_log(&tpm, &RCA_dec_cmd, sizeof(RCA_dec_cmd));
    log_tpm_status(&tpm);   

    struct TMP_RSA_decrypt_response *RSA_dec_response = (struct TMP_RSA_decrypt_response *)malloc(sizeof(struct TMP_RSA_decrypt_response));
    tpm_receive_response_with_log(&tpm, RSA_dec_response, sizeof(struct TMP_RSA_decrypt_response));
    
    if(RSA_dec_response->response_header.response_code == 0)
        UART_putstr("Success code received\n");
    else
        UART_putstr("Error code received\n");


    // Trying Shutdown command
    cmd_header.tag = TPM_ST_SESSION;
    cmd_header.command_code = TPM2_CC_Shutdown;
    cmd_header.size = sizeof(struct tpm_create_command);
    struct TMP_shutdown_command shutdown_cmd = {
        .command_header = cmd_header,
        .shutdownType = TPM_SU_STATE // Shutdown type
    };


    UART_putstr("\nSending Shutdown command...\n");
    tpm_send_command_with_log(&tpm, &shutdown_cmd, sizeof(shutdown_cmd));
    log_tpm_status(&tpm);   

    struct TMP_shutdown_response *shutdown_response = (struct TMP_shutdown_response *)malloc(sizeof(struct TMP_shutdown_response));
    tpm_receive_response_with_log(&tpm, shutdown_response, sizeof(struct TMP_shutdown_response));
    
    if(shutdown_response->response_header.response_code == 0)
        UART_putstr("Success code received\n");
    else
        UART_putstr("Error code received\n");


    return 0;
}
