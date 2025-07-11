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
    
    /* ***************************************************** */
    /*                  Startup                              */

    struct tpm_response_header *startup_response = startup(&tpm);
    UART_puthex(sizeof(tpm.response_buffer));
    UART_println();
    if (startup_response != NULL) {
        UART_putstr("TPM started successfully.\n");
    }

    
    /* ***************************************************** */
    /*                  Self test                            */


    struct tpm_response_header *self_test_response = selfTest(&tpm);
    if (self_test_response != NULL) {
        UART_putstr("Self test completed successfully.\n");
    }

    
    /* ***************************************************** */
    /*              Create Primary                           */

    uint16_t keyBits = 2048;      // Needed this size to encrypt child key
    struct tpm_createPrimary_response *createPrimary_response = createPrimary(&tpm, keyBits);
    uint32_t primary_handle = createPrimary_response->objectHandle;
    UART_putstr("Created primary key with handle 0x");
    UART_puthex(primary_handle);
    UART_println();

    /* ***************************************************** */
    /*                     Create                            */

    keyBits = 2048;
    struct tpm_create_response *create_response = create(&tpm, primary_handle, keyBits);
    UART_putstr("Created key with handle, private size: ");
    UART_puthex(create_response->outPrivate.size);
    UART_println();

    

    /* ***************************************************** */
    /*                 RSA_Ecrypt                            */
   
    char text[] = "This is a text";
    size_t text_size = sizeof(text);
    struct TMP_RSA_encrypt_response *enc_response = encrypt(&tpm, primary_handle, text, text_size);
    
    /* ***************************************************** */
    /*                 RSA_Decrypt                           */

    uint8_t *cipherText = enc_response->outData.buffer;
    size_t cipherText_size = enc_response->outData.size;

    struct TMP_RSA_decrypt_response *dec_response = decrypt(&tpm, primary_handle, cipherText, cipherText_size);

    if (dec_response != NULL) {
        UART_putstr("Decrypted text: ");
        UART_putstr(dec_response->message.buffer);
        UART_println();
    } 
    
    /* ***************************************************** */
    /*                   Shutdown                            */

    struct TMP_shutdown_response *shutdown_response = shutdown(&tpm);

    if (shutdown_response != NULL) {
        UART_putstr("TPM shutdown successful.\n");
    }

    // Free allocated memory

    UART_putstr("TPM operations completed successfully.\n");
    
    // End of program
    UART_putstr("Exiting...\n");

    return 0;
}
