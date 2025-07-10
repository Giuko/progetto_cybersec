#include "tpm.h"
#include "uart.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


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

struct tpm_createPrimary_response* createPrimary(struct tpm_device *tpm){
    struct tpm_command_header std_cmd_header = {
        .tag = TPM_ST_SESSION,
        .command_code = TPM2_CC_CreatePrimary,
        .size = sizeof(struct tpm_createPrimary_command)
    };

    struct tpm_createPrimary_command create_primary_cmd = {
        .command_header = std_cmd_header,
        .primaryHandle = TPM_RH_OWNER, // Using Owner hierarchy
        .inSensitive = {
            .size = 128+64 + 2 + 2,     // 2 byte for size of each 
            .sensitiveCreate = {
                .userAuth = {
                    .size = 128, // No user auth for primary key
                    .buffer = {0}
                },
                .data = {
                    .size = 64, // No additional data for primary key
                    .buffer = {0}
                }
            }
        },
        .inPublic = {
            .size = 2 + 2 + 4 + (2 + 64) + ((2 + 2 + 2 ) + (2 + 2) + 2 + 4) + (2 + 512),
            .publicArea = {
                .type = KEY_TYPE_RSA, // Using RSA for primary key
                .nameAlg = TPM_ALG_RSA, // Using SHA for name algorithm
                .objectAttributes = ST_CLEAR | FIXED_TPM | FIXED_PARENT | DECRYPT | SIGN,
                .authPolicy = {
                    .size = 64, // No auth policy for primary key
                    .buffer = {0}
                },
                .parameters = {
                    .symmetric = {
                        .algorithm = TPM_ALG_NULL, // No symmetric algorithm for primary key
                        .mode = 0, // Not used
                        .keyBits = 0 // Not used
                    },
                    .scheme = {
                        .scheme = TPM_ALG_NULL, // No scheme for primary key
                        .details = 0 // No details for primary key
                    },
                    .keyBits = 2048, // Using 2048 bits for RSA key size
                    .exponent = 0 // Default exponent (65537)
                },
                .unique = {
                    .size = 512, // No unique value for primary key
                    .buffer = {0} // No unique value for primary key
                }
            }
        },
        .outsideInfo = {
            .size = 64, // No outside info for primary key
            .buffer = {0} // No outside info for primary key
        },
        .creationPCR = {
            .count = 0, // No PCR selection for primary key
            .pcrSelections = {{0}} // No PCR selections for primary key
        }
    };
    
    UART_putstr("\nSending CreatePrimary command...\n");
    tpm_send_command_with_log(tpm, &create_primary_cmd, sizeof(create_primary_cmd));
    struct tpm_createPrimary_response *createPrimary_response = (struct tpm_createPrimary_response*)malloc(sizeof(struct tpm_createPrimary_response));
    tpm_receive_response_with_log(tpm, createPrimary_response, sizeof(struct tpm_create_response));
    
    if(createPrimary_response->response_header.response_code != 0){
        UART_putstr("Error code received (0x");
        UART_puthex(createPrimary_response->response_header.response_code);
        UART_putstr(")\n");
        return NULL;
    }
    
    return createPrimary_response;
}

struct tpm_create_response* create(struct tpm_device *tpm, uint32_t parent_handle){

    struct tpm_command_header std_cmd_header = {
        .tag = TPM_ST_SESSION,
        .command_code = TPM2_CC_Create,
        .size = sizeof(struct tpm_create_command)
    };
    struct tpm_create_command create_cmd = {
        .command_header = std_cmd_header,
        .parentHandle = parent_handle,
        .inSensitive = {
            .size = 128+64 + 2 + 2,
            .sensitiveCreate = {
                .userAuth = {
                    .size = 128, // No user auth for primary key
                    .buffer = {0}
                },
                .data = {
                    .size = 64, // No additional data for primary key
                    .buffer = {0}
                }
            }
        },
        .inPublic = {
            .size = 2 + 2 + 4 + (2 + 64) + ((2 + 2 + 2 ) + (2 + 2) + 2 + 4) + (2 + 512),
            .publicArea = {
                .type = TPM_ALG_RSA, // Using RSA for primary key
                .nameAlg = TPM_ALG_SHA, // Using SHA for name algorithm
                .objectAttributes = ST_CLEAR | FIXED_TPM | FIXED_PARENT | DECRYPT | SIGN,
                .authPolicy = {
                    .size = 64, // No auth policy for primary key
                    .buffer = {0}
                },
                .parameters = {
                    .symmetric = {
                        .algorithm = TPM_ALG_NULL, // No symmetric algorithm for primary key
                        .mode = 0, // Not used
                        .keyBits = 0 // Not used
                    },
                    .scheme = {
                        .scheme = TPM_ALG_NULL, // No scheme for primary key
                        .details = 0 // No details for primary key
                    },
                    .keyBits = 2048, // Using 2048 bits for RSA key size
                    .exponent = 0 // Default exponent (65537)
                },
                .unique = {
                    .size = 512, // No unique value for primary key
                    .buffer = {0} // No unique value for primary key
                }
            }
        },
        .outsideInfo = {
            .size = 64, // No outside info for primary key
            .buffer = {0} // No outside info for primary key
        },
        .creationPCR = {
            .count = 0, // No PCR selection for primary key
            .pcrSelections = {{0}} // No PCR selections for primary key
        }
    };
    
    UART_putstr("\nSending Create command...\n");
    tpm_send_command_with_log(tpm, &create_cmd, sizeof(create_cmd));
 
    struct tpm_create_response *create_response = (struct tpm_create_response *)malloc(sizeof(struct tpm_create_response));
    tpm_receive_response_with_log(tpm, create_response, sizeof(struct tpm_create_response));
    
    if(create_response->response_header.response_code != 0){
        return NULL;
    }

    return create_response;
}

struct TMP_RSA_encrypt_response* encrypt(struct tpm_device *tpm, uint32_t key_handle, uint8_t *plaintext, size_t plaintext_size){
    struct tpm_command_header std_cmd_header = {
        .tag = TPM_ST_NO_SESSION,
        .command_code = TPM2_CC_RSA_Encrypt,
        .size = sizeof(struct TMP_RSA_encrypt_command)
    };

    struct TMP_RSA_encrypt_command RCA_enc_cmd = {
        .command_header = std_cmd_header,
        .keyHandle = key_handle, 
        .message = {
            .size = plaintext_size, // Size of the message
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
    memcpy(RCA_enc_cmd.message.buffer, plaintext, plaintext_size);
    
    UART_putstr("\nSending RSA_Encrypt command...\n");
    tpm_send_command_with_log(tpm, &RCA_enc_cmd, sizeof(RCA_enc_cmd));
    
    struct TMP_RSA_encrypt_response *RSA_enc_response = (struct TMP_RSA_encrypt_response *)malloc(sizeof(struct TMP_RSA_encrypt_response));

    tpm_receive_response_with_log(tpm, RSA_enc_response, sizeof(struct TMP_RSA_encrypt_response));
    
    if(RSA_enc_response->response_header.response_code != 0){
        UART_putstr("Error code received (");
        UART_puthex(RSA_enc_response->response_header.response_code);
        UART_putstr(")\n");
        return NULL;
    }

    return RSA_enc_response;

}
