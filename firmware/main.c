#include "uart.h"
#include "tpm.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_KEYS 10
#define MAX_CIPHERTEXT_SIZE 256

static struct tpm_device tpm;
static uint32_t key_handles[MAX_KEYS];
static int key_count = 0;

// Store last ciphertext to decrypt later
static uint8_t last_ciphertext[MAX_CIPHERTEXT_SIZE];
static size_t last_ciphertext_size = 0;
static uint32_t last_cipher_handle = 0;

void wait_keypress(void) {
    UART_putstr("\nPress any key to continue...\n");
    UART_getc();
}

void do_startup(void) {
    UART_putstr("Starting up TPM...\n");
    struct tpm_response_header *resp = startup(&tpm);
    if (resp) UART_putstr("TPM started.\n");
    wait_keypress();
}

void do_selftest(void) {
    UART_putstr("Running self-test...\n");
    struct tpm_response_header *resp = selfTest(&tpm);
    if (resp) UART_putstr("Self-test completed.\n");
    wait_keypress();
}

void do_create_primary(void) {
    if (key_count >= MAX_KEYS) {
        UART_putstr("Key store full. Max handles reached.\n");
        return;
    }
    UART_putstr("Creating primary key (2048-bit)...\n");
    struct tpm_createPrimary_response *resp = createPrimary(&tpm, 2048);
    if (resp) {
        key_handles[key_count++] = resp->objectHandle;
        UART_putstr("Primary key created. Handle: 0x");
        UART_puthex(resp->objectHandle);
        UART_println();
        UART_putstr("Key index to use: ");
        UART_putdigit(key_count - 1);
        UART_println();
    }
    wait_keypress();
}

int select_key_index(void) {
    if (key_count == 0) {
        UART_putstr("No keys available. Create one first.\n");
        return -1;
    }

    UART_putstr("Choose key [0 - ");
    UART_putdigit(key_count - 1);
    UART_putstr("]: ");
    char ch = UART_getc();
    UART_putc(ch); UART_println();

    int idx = ch - '0';
    if (idx < 0 || idx >= key_count) {
        UART_putstr("Invalid key index.\n");
        return -1;
    }
    return idx;
}

void do_encrypt(void) {
    int idx = select_key_index();
    if (idx < 0) return;

    uint32_t handle = key_handles[idx];
    char text[100];
    UART_putstr("Enter message to encrypt:\n>> ");
    UART_gets(text, sizeof(text));

    struct TMP_RSA_encrypt_response *enc = encrypt(&tpm, handle, text, strlen(text));
    if (!enc) {
        UART_putstr("Encryption failed.\n");
        return;
    }

    // Store ciphertext for later decryption
    memcpy(last_ciphertext, enc->outData.buffer, enc->outData.size);
    last_ciphertext_size = enc->outData.size;
    last_cipher_handle = handle;

    UART_putstr("Message encrypted. Ciphertext size: ");
    UART_puthex(last_ciphertext_size);
    UART_println();

    wait_keypress();
}

void do_decrypt(void) {
    if (last_ciphertext_size == 0) {
        UART_putstr("No ciphertext available. Encrypt something first.\n");
        return;
    }

    UART_putstr("Decrypting last encrypted message...\n");
    struct TMP_RSA_decrypt_response *dec = decrypt(&tpm, last_cipher_handle, last_ciphertext, last_ciphertext_size);
    if (dec) {
        UART_putstr("Decrypted message: ");
        UART_putstr((char *)dec->message.buffer);
        UART_println();
    } else {
        UART_putstr("Decryption failed.\n");
    }

    wait_keypress();
}

void do_shutdown(void) {
    UART_putstr("Shutting down TPM...\n");
    struct TMP_shutdown_response *resp = shutdown(&tpm);
    if (resp) UART_putstr("TPM shutdown successful.\n");
    wait_keypress();
}

void print_menu(void) {
    UART_putstr("\n=== TPM DEMO MENU ===\n");
    UART_putstr("1. TPM Startup\n");
    UART_putstr("2. Self-Test\n");
    UART_putstr("3. Create Primary Key\n");
    UART_putstr("4. Encrypt Message\n");
    UART_putstr("5. Decrypt Last Message\n");
    UART_putstr("6. Shutdown TPM\n");
    UART_putstr("7. Exit\n");
    UART_putstr("Select option: ");
}

int main(void) {
    UART_init();
    UART_putstr("===== CyberSec TPM Demo =====\n");
    tpm_init(&tpm, (void *)TPM_BASE_ADDRESS);
    log_tpm_status(&tpm);

    while (1) {
        print_menu();
        char choice = UART_getc();
        UART_putc(choice); UART_println();

        switch (choice) {
            case '1': do_startup(); break;
            case '2': do_selftest(); break;
            case '3': do_create_primary(); break;
            case '4': do_encrypt(); break;
            case '5': do_decrypt(); break;
            case '6': do_shutdown(); break;
            case '7':
                UART_putstr("Exiting demo...\n");
                return 0;
            default:
                UART_putstr("Invalid selection.\n");
                break;
        }
    }
}

