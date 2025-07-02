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



    // Trying CreatePrimary command
    cmd_header.tag = TPM_ST_SESSION;
    cmd_header.command_code = TPM2_CC_CreatePrimary;
    cmd_header.size = sizeof(struct tpm_createPrimary_command);
    struct tpm_createPrimary_command create_primary_cmd = {
        .command_header = cmd_header,
        .primaryHandle = TPM_RH_OWNER, // Using Owner hierarchy
        .inSensitive = {
            .size = 0, // No sensitive data for primary key
            .sensitiveCreate = {
                .userAuth = {
                    .size = 0, // No user auth for primary key
                    .buffer = {0}
                },
                .data = {
                    .size = 0, // No additional data for primary key
                    .buffer = {0}
                }
            }
        },
        .inPublic = {
            .size = 0, // Size will be set later
            .publicArea = {
                .type = TPM_ALG_RSA, // Using RSA for primary key
                .nameAlg = TPM_ALG_SHA, // Using SHA for name algorithm
                .objectAttributes = ST_CLEAR | FIXED_TPM | FIXED_PARENT | DECRYPT | SIGN,
                .authPolicy = {
                    .size = 0, // No auth policy for primary key
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
                    .size = 0, // No unique value for primary key
                    .buffer = {0} // No unique value for primary key
                }
            }
        },
        .outsideInfo = {
            .size = 0, // No outside info for primary key
            .buffer = {0} // No outside info for primary key
        },
        .creationPCR = {
            .count = 0, // No PCR selection for primary key
            .pcrSelections = {{0}} // No PCR selections for primary key
        }
    };

    UART_putstr("\nSending CreatePrimary command...\n");
    tpm_send_command_with_log(&tpm, &create_primary_cmd, sizeof(create_primary_cmd));
    log_tpm_status(&tpm);   

    struct tpm_createPrimary_response *createPrimary_response = (struct tpm_createPrimary_response *)malloc(sizeof(struct tpm_createPrimary_response));
    tpm_receive_response_with_log(&tpm, createPrimary_response, sizeof(struct tpm_createPrimary_response));
    
    if(createPrimary_response->response_header.response_code == 0)
        UART_putstr("Success code received\n");
    else
        UART_putstr("Error code received\n");



    // Trying Create command
    cmd_header.tag = TPM_ST_SESSION;
    cmd_header.command_code = TPM2_CC_Create;
    cmd_header.size = sizeof(struct tpm_create_command);
    struct tpm_create_command create_cmd = {
        .command_header = cmd_header,
        .parentHandle = 0, // Using NULL for parent handle
        .inSensitive = {
            .size = 0, // No sensitive data for primary key
            .sensitiveCreate = {
                .userAuth = {
                    .size = 0, // No user auth for primary key
                    .buffer = {0}
                },
                .data = {
                    .size = 0, // No additional data for primary key
                    .buffer = {0}
                }
            }
        },
        .inPublic = {
            .size = 0, // Size will be set later
            .publicArea = {
                .type = TPM_ALG_RSA, // Using RSA for primary key
                .nameAlg = TPM_ALG_SHA, // Using SHA for name algorithm
                .objectAttributes = ST_CLEAR | FIXED_TPM | FIXED_PARENT | DECRYPT | SIGN,
                .authPolicy = {
                    .size = 0, // No auth policy for primary key
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
                    .size = 0, // No unique value for primary key
                    .buffer = {0} // No unique value for primary key
                }
            }
        },
        .outsideInfo = {
            .size = 0, // No outside info for primary key
            .buffer = {0} // No outside info for primary key
        },
        .creationPCR = {
            .count = 0, // No PCR selection for primary key
            .pcrSelections = {{0}} // No PCR selections for primary key
        }
    };

    UART_putstr("\nSending Create command...\n");
    tpm_send_command_with_log(&tpm, &create_cmd, sizeof(create_cmd));
    log_tpm_status(&tpm);   

    struct tpm_createPrimary_response *create_response = (struct tpm_createPrimary_response *)malloc(sizeof(struct tpm_createPrimary_response));
    tpm_receive_response_with_log(&tpm, create_response, sizeof(struct tpm_createPrimary_response));
    
    if(create_response->response_header.response_code == 0)
        UART_putstr("Success code received\n");
    else
        UART_putstr("Error code received\n");

   
    // Trying RSA_Encrypt command
    cmd_header.tag = TPM_ST_NO_SESSION;
    cmd_header.command_code = TPM2_CC_RSA_Encrypt;
    cmd_header.size = sizeof(struct tpm_create_command);
    const char *message_RCA_enc = "Hello, TPM!";
    size_t msg_len_enc = strlen(message_RCA_enc);
    struct TMP_RSA_encrypt_command RCA_enc_cmd = {
        .command_header = cmd_header,
        .keyHandle = 0, 
        .message = {
            .size = sizeof(message_RCA_enc), // Size of the message
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
            .size = 0, // No label for RSA encryption
            .buffer = {0} // No label for RSA encryption
        }
    };

    memcpy(RCA_enc_cmd.message.buffer, message_RCA_enc, msg_len_enc);
    

    UART_putstr("\nSending RSA_Encrypt command...\n");
    tpm_send_command_with_log(&tpm, &RCA_enc_cmd, sizeof(RCA_enc_cmd));
    log_tpm_status(&tpm);   

    struct TMP_RSA_encrypt_response *RSA_enc_response = (struct TMP_RSA_encrypt_response *)malloc(sizeof(struct TMP_RSA_encrypt_response));
    tpm_receive_response_with_log(&tpm, RSA_enc_response, sizeof(struct TMP_RSA_encrypt_response));
    
    if(RSA_enc_response->response_header.response_code == 0)
        UART_putstr("Success code received\n");
    else
        UART_putstr("Error code received\n");


    // Trying RSA_Dencrypt command
    cmd_header.tag = TPM_ST_SESSION;
    cmd_header.command_code = TPM2_CC_RSA_Decrypt;
    cmd_header.size = sizeof(struct tpm_create_command);
    const char *message_RCA_dec = "Hello, TPM!";
    size_t msg_len_dec = strlen(message_RCA_dec);
    struct TMP_RSA_decrypt_command RCA_dec_cmd = {
        .command_header = cmd_header,
        .keyHandle = 0, 
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
            .size = 0, // No label for RSA encryption
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
