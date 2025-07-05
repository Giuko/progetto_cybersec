#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "hw/registerfields.h"
#include "hw/qdev-properties.h"
#include "qapi/error.h"
#include "qemu/log.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "hw/registerfields.h"

// For asynch behavior
#include "qemu/main-loop.h"

#include "tpm_types.h"
#include "tpm_command_handler.h"
#include "tpm_basic_crypto_rsa.h"

/*REGISTER DEFINITION*/
REG32(TPM_ACCESS, 0x00)
    FIELD(TPM_ACCESS, VALID, 1, 1)
    FIELD(TPM_ACCESS, ACTIVE, 5, 1)

REG32(TPM_INT_ENABLE, 0x08)

REG32(TPM_INT_VECTOR, 0x0C)

REG32(TPM_INT_STATUS, 0x10)

REG32(TPM_INTF_CAPABILITY, 0x14)
    FIELD(TPM_INTF_CAPABILITY, FIFO_IF, 0, 1)

REG32(TPM_STS, 0x18)
    FIELD(TPM_STS, ERROR, 1, 1)
    FIELD(TPM_STS, DATA_EXPECT, 3, 1)
    FIELD(TPM_STS, DATA_AVAIL, 4, 1)
    FIELD(TPM_STS, GO, 5, 1)
    FIELD(TPM_STS, CMD_READY, 6, 1)
    FIELD(TPM_STS, VALID, 7, 1)

REG32(TPM_DATA_FIFO, 0x24)

REG32(TPM_INTERFACE_ID, 0x30)

REG32(TPM_DID_VID, 0x48)


#define TYPE_CUSTOM_TPM "custom-tpm"
OBJECT_DECLARE_SIMPLE_TYPE(CustomTPMState,CUSTOM_TPM)

typedef enum{
    TPM_STATE_IDLE,
    TPM_STATE_READY
} TPMInternalState;

#define MAX_KEYS 4
#define KEY_HANDLE_BASE 0X81000000          // A generic (simplied) key handle base for everything

struct CustomTPMState {
    SysBusDevice parent_obj;

    MemoryRegion mmio;
    uint8_t fifo[1024];
    uint32_t fifo_pos;
        
    uint32_t regs[0x100/sizeof(uint32_t)];

    uint8_t command[1024];
    uint32_t command_size;
    uint32_t command_pos;

    uint8_t response[1024*1024];
    uint32_t response_size;
    uint32_t response_pos;

    TPM_Key keys[MAX_KEYS];
    uint32_t next_handle;

    TPMInternalState state;
    bool processing;

    QEMUBH *command_bh; // For async command execution
};

#define SUCCESS_CODE                0x00
#define ERROR_CODE                  0x01

static void tpm_reset_state(CustomTPMState *s){
    printf("[TPM] Performing state reset (CLEAR)\n");
    
    // Reset command/response state
    s->command_pos = 0;
    s->command_size = 0;
    s->response_pos = 0;
    s->response_size = 0;
    
    // Reset status register
    s->regs[R_TPM_STS] = R_TPM_STS_VALID_MASK | R_TPM_STS_CMD_READY_MASK;
    s->state = TPM_STATE_READY; 
    printf("[TPM] Reset complete\n");
}

/* Begin Commands */
static uint32_t SelfTest(CustomTPMState *s){
    // It should check a test of self function, but in this case it send only a response code
    printf("[TPM]: SelfTest Command execution\n");
    s->response_size = 10;
    if(s->state == TPM_STATE_IDLE) { return TPM_RC_INITIALIZE; } 
    return TPM_RC_SUCCESS;  
}

static uint32_t Startup(CustomTPMState *s){
    printf("[TPM]: Startup Command execution\n");
    // Startup command has 2-byte parameter (startupType)
    s->response_size = 10;
            
    if(s->command_size < 12){
        printf("[TPM] Startup command too small\n");
        return TPM_RC_SIZE;
    }
    // Parsing extra 2-byte
    uint16_t startup_type = (s->command[11] << 8) | s->command[10];
    printf("[TPM] Startup command, type: 0x%04x\n", startup_type);

    switch(startup_type){
        case TPM_SU_CLEAR:
            tpm_reset_state(s);
            return TPM_RC_SUCCESS;
        case TPM_SU_STATE:
            printf("[TPM] State restore not implemented\n");
            return TPM_RC_SUCCESS;
        default:
            printf("[TPM] Invalid startup type\n");
            return TPM_RC_VALUE;
    }
} 

static uint32_t Shutdown(CustomTPMState *s){
printf("[TPM]: Shutdown Command execution\n");
    // Startup command has 2-byte parameter (startupType)
    s->response_size = 10;
    if(s->state == TPM_STATE_IDLE) { return TPM_RC_INITIALIZE; } 
    if(s->command_size < 12){
    printf("[TPM] Startup command too small\n");
        return TPM_RC_SIZE;
    }
    // Parsing extra 2-byte
    uint16_t shutdown_type = (s->command[11] << 8) | s->command[10];
    printf("[TPM] Shutdown command, type: 0x%04x\n", shutdown_type);

    switch(shutdown_type){
        case TPM_SU_CLEAR:
            printf("[TPM]Not implemented");
            return TPM_RC_VALUE;
        case TPM_SU_STATE:
            s->regs[R_TPM_STS] &= ~R_TPM_STS_CMD_READY_MASK;
            s->state = TPM_STATE_IDLE;

            for(int i = 0; i < MAX_KEYS; i++){
                if(s->keys[i].attributes & ST_CLEAR)
                    memset(&(s->keys[i]), 0, sizeof(s->keys[i]));
            }

            return TPM_RC_SUCCESS;
        default:
            printf("[TPM] Invalid shutdown type\n");
            return TPM_RC_VALUE;
    } 
}

static uint32_t CreatePrimary(CustomTPMState *s){
    // To generate Primary key
    printf("[TPM]: CreatePrimary Command execution\n");
    s->response_size = 10;
    if(s->state == TPM_STATE_IDLE) { return TPM_RC_INITIALIZE; } 
    if(s->command_size < 29 ){  // 10 + 4 + 2 + 2 + 2 + 4 + 5
        printf("[TPM] CreatePrimary command too small, debug 1\n");
        return TPM_RC_SIZE;
    }

    // Extra field in command are:
    // TPMI_RH_HIERARCHY primaryHandle          (uint32_t)  4 bytes
    // TPM2B_SENSITIVE_CREATE inSensitive         2 bytes
    // TPM2B_PUBLIC inPublic                      2 bytes
    // TPM2B_DATA outsideInfo                     2 bytes
    // TPML_PCR_SELECTION creationPCR             4 bytes
    uint32_t primaryHandle;
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_PUBLIC inPublic;
    uint16_t outsideInfoSize;
    uint32_t creationPCRCount;
    int offset = 10;        // Aleeady analyzed field

    // Parsing command
    primaryHandle =  (s->command[offset+3] << 24)| (s->command[offset+2] << 16) | (s->command[offset+1] << 8) | s->command[offset];
    
    if(primaryHandle != TPM_RH_OWNER && primaryHandle != TPM_RH_ENDORSEMENT && primaryHandle != TPM_RH_PLATFORM && primaryHandle != TPM_RH_NULL){
        printf("[TPM]: Primary Handle: 0x%x, isn't a valid value, debug 2\n", primaryHandle);
        return TPM_RC_HANDLE;
    }
    
    printf("[TPM]: Primary Handle: 0x%x\n", primaryHandle);
    offset += 4;

    // inSensitive
    if(offset+2 > s->command_size){
        printf("[TPM]: Invalid command size: %d, debug 3\n", s->command_size);  
        return TPM_RC_SIZE;
    }
    inSensitive.size = (s->command[offset+1] << 8) | s->command[offset];
    offset += 2;
    if(offset + inSensitive.size > s->command_size){
        printf("[TPM]: Invalid inSensitive size: %d, debug 4\n", inSensitive.size);
        return TPM_RC_SIZE;
    }
    // Skip inSensitive Value 
    offset += inSensitive.size; 
    printf("[TPM]: inSensitive Size: %d\n", inSensitive.size);

    // inPublic
    if(offset+2 > s->command_size){
        printf("[TPM]: Invalid command size: %d, debug 5\n", s->command_size);
        return TPM_RC_SIZE;
    }

    printf("[TPM]: offset: %d\n", offset);
    inPublic.size = (s->command[offset+1] << 8) | s->command[offset];
    offset += 2;
    if(offset+inPublic.size > s->command_size){
        printf("[TPM] Invalid inPublic size: %d, debug 6\n", inPublic.size);
        return TPM_RC_SIZE;
    }
    
    if(inPublic.size < 8) {
        printf("[TPM] Invalid inPublic size: %d, debug 7\n", inPublic.size);
        return TPM_RC_SIZE;
    }
    inPublic.publicArea.type = (s->command[offset + 1] <<  8) | s->command[offset]; 
    inPublic.publicArea.nameAlg = (s->command[offset + 3] <<  8) | s->command[offset+2]; 
    inPublic.publicArea.objectAttributes = (s->command[offset + 7] << 24) | (s->command[offset + 6] << 16) | (s->command[offset + 5] << 8) | s->command[offset + 4]; 
    printf("[TPM] Algorithm: 0x%04x, NameAlg: 0x%04x, Attributes: 0x%08x\n", inPublic.publicArea.type, inPublic.publicArea.nameAlg, inPublic.publicArea.objectAttributes);

    printf("TPM_ALG_RSA: %d", TPM_ALG_RSA);
    // Skipping 
    //      AuthPolicy
    //      parameters

    offset += inPublic.size;

    if(offset+2 > s->command_size){
        printf("[TPM]: Invalid command size: %d, debug 8\n", s->command_size);
        return TPM_RC_SIZE;
    }
    
    outsideInfoSize = (s->command[offset+1] << 8) | s->command[offset];
    offset += 2;
    if(offset + outsideInfoSize > s->command_size){
        printf("[TPM] Invalid outSideInfo size: %d, debug 9\n", outsideInfoSize);
        return TPM_RC_SIZE;
    }
    // Skipping OutsideInfoSize
    offset += outsideInfoSize;

    if(offset+4 > s->command_size) {
        printf("[TPM]: Invalid command size: %d, debug 10\n", s->command_size);
        return TPM_RC_SIZE;
    }
    creationPCRCount =  (s->command[offset+3] << 24)| (s->command[offset+2] << 16) | (s->command[offset+1] << 8) | s->command[offset]; 
    // Skip PCR

    
    int slot = -1;
    for(int i = 0; i < MAX_KEYS; i++){
        if(!s->keys[i].loaded){
            slot = i;
            break;
        }
    }

    if(slot == -1){
        printf("[TPM]: KEY slot ended\n");
        return TPM_RC_OBJECT_MEMORY;
    }

    TPM_Key *key = (TPM_Key*)malloc(sizeof(TPM_Key));

    // Initialize key
    key->handle = KEY_HANDLE_BASE + s->next_handle++;

    switch (inPublic.publicArea.nameAlg){
        case TPM_ALG_RSA:
            key->type = KEY_TYPE_RSA;
            break;
        default:
            printf("[TPM] Unsupported algorithm: 0x%04X\n", inPublic.publicArea.type);
            return TPM_RC_ASYMMETRIC;
    }

    key->attributes = inPublic.publicArea.objectAttributes;
    // Generate key pair
    // Fixed size for simplicity 1024
    if(!generate_rsa_keys(key->ctx, 1024)){
        printf("[TPM]: key generation failed, debug 11\n");
        return TPM_RC_FAILURE;
    }
    key->loaded = true;
    key->hierarchy = primaryHandle;
    printf("[TPM] Created primary key with handle: 0x%08x\n", key->handle);
    if(!verify_key_integrity(&(key->ctx->data_key)))
        printf("[TPM]: Key generated isn't working properly\n"); 
    else
        printf("[TPM]: Key generated is working properly\n"); 
    s->keys[slot] = *key;
    
    // Prepare response
    int resp_offset = 10;
            
    s->response[resp_offset] = key->handle;
    s->response[resp_offset + 1] = key->handle >> 8;
    s->response[resp_offset + 2] = key->handle >> 16;
    s->response[resp_offset + 3] = key->handle >> 24;
    resp_offset += 4;

    uint16_t pubKeySize = sizeof(key->ctx->public_key);
    s->response[resp_offset] = pubKeySize;
    s->response[resp_offset + 1]  = pubKeySize >> 8;
    resp_offset += 2;

    if(resp_offset + pubKeySize > sizeof(s->response)){
        printf("[TPM]: Response buffer too small, debug 12\n");
        return TPM_RC_FAILURE;
    }
    memcpy(&s->response[resp_offset], &(key->ctx->public_key), sizeof(key->ctx->public_key));
    resp_offset += pubKeySize;

    // TPM2B_CREATION_DATA (simplified, empty for now)
    s->response[resp_offset] = 0x00; // size low
    s->response[resp_offset+1] = 0x00; // size high
    resp_offset += 2;

    // TPMT_TK_CREATION (simplified, null ticket)
    s->response[resp_offset] = 0x21; // TPM_ST_CREATION
    s->response[resp_offset+1] = 0x80;
    resp_offset += 2;
    s->response[resp_offset] =   0x07; // TPM_RH_NULL
    s->response[resp_offset+1] = 0x00;
    s->response[resp_offset+2] = 0x00;
    s->response[resp_offset+3] = 0x40;
    resp_offset += 4;
    
    // Empty digest
    s->response[resp_offset] = 0x00; // size low
    s->response[resp_offset+1] = 0x00; // size high  
    resp_offset += 2;
    
    // TPM2B_DIGEST name (simplified, empty for now)
    s->response[resp_offset] = 0x00; // size low
    s->response[resp_offset+1] = 0x00; // size high
    resp_offset += 2;
    
    s->response_size = resp_offset;

    printf("[TPM] CreatePrimary response prepared, size: %d bytes\n", s->response_size);
    return TPM_RC_SUCCESS;
}

static uint32_t Create(CustomTPMState *s){
    // To generate a key under an existing parent key
    printf("[TPM]: Create Command execution\n");
    s->response_size = 10;
    
    if(s->state == TPM_STATE_IDLE) { 
        return TPM_RC_INITIALIZE; 
    } 
    
    if(s->command_size < 25) {  // 10 + 4 + 2 + 2 + 2 + 4 + 1 (minimum)
        printf("[TPM] Create command too small\n");
        return TPM_RC_SIZE;
    }

    // Extra fields in command are:
    // TPMI_DH_OBJECT parentHandle             (uint32_t)  4 bytes
    // TPM2B_SENSITIVE_CREATE inSensitive       2 bytes + data
    // TPM2B_PUBLIC inPublic                    2 bytes + data
    // TPM2B_DATA outsideInfo                   2 bytes + data
    // TPML_PCR_SELECTION creationPCR           4 bytes + data
    
    uint32_t parentHandle;
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_PUBLIC inPublic;
    uint16_t outsideInfoSize;
    uint32_t creationPCRCount;
    int offset = 10;        // Already analyzed fields
    // Parse parentHandle
    parentHandle = (s->command[offset+3] << 24) | (s->command[offset+2] << 16) | 
                   (s->command[offset+1] << 8) | s->command[offset];
    offset += 4;
    
    printf("[TPM]: Parent Handle: 0x%x\n", parentHandle);
    
    // Find parent key
    TPM_Key *parentKey = NULL;
    for(int i = 0; i < MAX_KEYS; i++){
        if(s->keys[i].loaded && s->keys[i].handle == parentHandle){
            parentKey = &(s->keys[i]);
            break;
        }
    }

    if(parentKey == NULL){
        printf("[TPM]: Parent handle 0x%x not found\n", parentHandle);
        return TPM_RC_HANDLE;
    }

    // Check if parent has the right attributes (should be able to create children)
    // Not implemented this check always create a children
    //
    // Parse inSensitive
    if(offset + 2 > s->command_size) return TPM_RC_SIZE;
    inSensitive.size = (s->command[offset+1] << 8) | s->command[offset];
    offset += 2;
    
    if(offset + inSensitive.size > s->command_size){
        printf("[TPM] Invalid inSensitive size: %d\n", inSensitive.size);
        return TPM_RC_SIZE;
    }
    // Skip inSensitive data for now
    offset += inSensitive.size;

    // Parse inPublic
    if(offset + 2 > s->command_size) return TPM_RC_SIZE;
    inPublic.size = (s->command[offset+1] << 8) | s->command[offset];
    offset += 2;
    
    if(offset + inPublic.size > s->command_size){
        printf("[TPM] Invalid inPublic size: %d\n", inPublic.size);
        return TPM_RC_SIZE;
    }
    
    if(inPublic.size < 8) return TPM_RC_SIZE;

    // Parse public area
    inPublic.publicArea.type = (s->command[offset + 1] << 8) | s->command[offset]; 
    inPublic.publicArea.nameAlg = (s->command[offset + 3] << 8) | s->command[offset + 2]; 
    inPublic.publicArea.objectAttributes = (s->command[offset + 7] << 24) | 
                                          (s->command[offset + 6] << 16) | 
                                          (s->command[offset + 5] << 8) | 
                                          s->command[offset + 4]; 
    
    printf("[TPM] Algorithm: 0x%04x, NameAlg: 0x%04x, Attributes: 0x%08x\n", 
           inPublic.publicArea.type, inPublic.publicArea.nameAlg, inPublic.publicArea.objectAttributes);

    offset += inPublic.size;

    // Parse outsideInfo
    if(offset + 2 > s->command_size) return TPM_RC_SIZE;
    outsideInfoSize = (s->command[offset+1] << 8) | s->command[offset];
    offset += 2;
    
    if(offset + outsideInfoSize > s->command_size){
        printf("[TPM] Invalid outsideInfo size: %d\n", outsideInfoSize);
        return TPM_RC_SIZE;
    }
    offset += outsideInfoSize;

    // Parse creationPCR
    if(offset + 4 > s->command_size) return TPM_RC_SIZE;
    creationPCRCount = (s->command[offset+3] << 24) | (s->command[offset+2] << 16) | 
                       (s->command[offset+1] << 8) | s->command[offset];
    // Skip PCR data for now

    // Find available slot for the new key
    int slot = -1;
    for(int i = 0; i < MAX_KEYS; i++){
        if(!s->keys[i].loaded){
            slot = i;
            break;
        }
    }

    if(slot == -1){
        printf("[TPM]: No available key slots\n");
        return TPM_RC_OBJECT_MEMORY;
    }

    TPM_Key *newKey = &(s->keys[slot]);

    // Initialize new key
    newKey->handle = 0; // Create command doesn't assign handle immediately
    newKey->parent_handle = parentHandle;

    switch (inPublic.publicArea.type){
        case TPM_ALG_RSA:
            newKey->type = KEY_TYPE_RSA;
            break;
        default:
            printf("[TPM] Unsupported algorithm: 0x%04X\n", inPublic.publicArea.type);
            return TPM_RC_ASYMMETRIC;
    }

    newKey->attributes = inPublic.publicArea.objectAttributes;
    newKey->hierarchy = parentKey->hierarchy; // Inherit from parent

    // Generate key pair (for simplicity, using fixed 1024 bit)
    if(generate_rsa_keys(newKey->ctx, 1024)){
        printf("[TPM]: Failed to generate RSA key pair\n");
        return TPM_RC_FAILURE;
    }
    
    newKey->loaded = false; // Created but not loaded yet
    printf("[TPM] Created key under parent 0x%08x\n", parentHandle);

    // Prepare respons
    int resp_offset = 10;

    // TPM2B_PRIVATE outPrivate (simplified - in real TPM this would be encrypted)
    uint16_t privateSize = sizeof(newKey->ctx->private_key);
    s->response[resp_offset] = privateSize;
    s->response[resp_offset + 1] = (privateSize >> 8);
    resp_offset += 2;
    
    if(resp_offset + privateSize > sizeof(s->response)){
        printf("[TPM]: Response buffer too small for private key\n");
        return TPM_RC_FAILURE;
    }
    
    // In a real implementation, this should be encrypted with parent's key
    memcpy(&s->response[resp_offset], &(newKey->ctx->private_key), privateSize);
    resp_offset += privateSize;

    // TPM2B_PUBLIC outPublic
    uint16_t publicSize = sizeof(newKey->ctx->public_key) + 8; // +8 for the public area header
    s->response[resp_offset] = publicSize & 0xFF;
    s->response[resp_offset + 1] = (publicSize >> 8) & 0xFF;
    resp_offset += 2;
    
    if(resp_offset + publicSize > sizeof(s->response)){
        printf("[TPM]: Response buffer too small for public key\n");
        return TPM_RC_FAILURE;
    }

    // Add public area header
    s->response[resp_offset] = inPublic.publicArea.type;
    s->response[resp_offset + 1] = (inPublic.publicArea.type >> 8);
    s->response[resp_offset + 2] = inPublic.publicArea.nameAlg;
    s->response[resp_offset + 3] = (inPublic.publicArea.nameAlg >> 8);
    s->response[resp_offset + 4] = inPublic.publicArea.objectAttributes;
    s->response[resp_offset + 5] = (inPublic.publicArea.objectAttributes >> 8);
    s->response[resp_offset + 6] = (inPublic.publicArea.objectAttributes >> 16);
    s->response[resp_offset + 7] = (inPublic.publicArea.objectAttributes >> 24);
    resp_offset += 8;
    
    memcpy(&s->response[resp_offset], &(newKey->ctx->public_key), sizeof(newKey->ctx->public_key));
    resp_offset += sizeof(newKey->ctx->public_key);

        // TPM2B_CREATION_DATA (simplified, empty for now)
    s->response[resp_offset] = 0x00; // size low
    s->response[resp_offset + 1] = 0x00; // size high
    resp_offset += 2;

    // TPMT_TK_CREATION (simplified, null ticket)
    s->response[resp_offset] = 0x21; // TPM_ST_CREATION low
    s->response[resp_offset + 1] = 0x80; // TPM_ST_CREATION high
    resp_offset += 2;
    
    s->response[resp_offset] = 0x07; // TPM_RH_NULL
    s->response[resp_offset + 1] = 0x00;
    s->response[resp_offset + 2] = 0x00;
    s->response[resp_offset + 3] = 0x40;
    resp_offset += 4;
    
    // Empty digest for creation ticket
    s->response[resp_offset] = 0x00; // size low
    s->response[resp_offset + 1] = 0x00; // size high  
    resp_offset += 2;
    
    // TPM2B_DIGEST name (simplified, empty for now)
    s->response[resp_offset] = 0x00; // size low
    s->response[resp_offset + 1] = 0x00; // size high
    resp_offset += 2;
    
    s->response_size = resp_offset;

    printf("[TPM] Create response prepared, size: %d bytes\n", s->response_size);

    return TPM_RC_SUCCESS;
    

}

static uint32_t RSA_Decrypt(CustomTPMState *s){
    // TPM2_RSA_Decrypt command implementation
    printf("[TPM]: RSA_Decrypt Command execution\n");
    s->response_size = 10;
    
    if(s->state == TPM_STATE_IDLE) { 
        return TPM_RC_INITIALIZE; 
    } 
    
    if(s->command_size < 23) {  // 10 + 4 + 2 + 2 + 2 + 2 + 1 (minimum)
        printf("[TPM] RSA_Decrypt command too small\n");
        return TPM_RC_SIZE;
    }

    // Command structure:
    // TPMI_DH_OBJECT keyHandle                (uint32_t)  4 bytes
    // TPM2B_PUBLIC_KEY_RSA cipherText         2 bytes + data
    // TPMT_RSA_DECRYPT inScheme              2 bytes (simplified)
    // TPM2B_DATA label                       2 bytes + data
    
    uint32_t keyHandle;
    uint16_t cipherTextSize;
    uint16_t schemeAlg;
    uint16_t labelSize;
    int offset = 10;        // Skip TPM header

    // Parse keyHandle
    keyHandle = (s->command[offset+3] << 24) | (s->command[offset+2] << 16) | 
                (s->command[offset+1] << 8) | s->command[offset];
    offset += 4;
    
    printf("[TPM]: Key Handle: 0x%x\n", keyHandle);
    
    // Find the key - must be loaded
    TPM_Key *key = NULL;
    for(int i = 0; i < MAX_KEYS; i++){
        if(s->keys[i].loaded && s->keys[i].handle == keyHandle){
            key = &(s->keys[i]);
            break;
        }
    }
    
    if(key == NULL){
        printf("[TPM]: Key handle 0x%x not found or not loaded\n", keyHandle);
        return TPM_RC_HANDLE;
    }
    
    // Verify key type
    if(key->type != KEY_TYPE_RSA){
        printf("[TPM]: Key is not an RSA key\n");
        return TPM_RC_VALUE;
    }
    
    // Verify key can decrypt (must have DECRYPT attribute) Skipped

    // Parse cipherText
    if(offset + 2 > s->command_size) return TPM_RC_SIZE;
    cipherTextSize = (s->command[offset+1] << 8) | s->command[offset];
    offset += 2;
    
    if(cipherTextSize == 0) {
        printf("[TPM]: Cipher text size cannot be zero\n");
        return TPM_RC_SIZE;
    }
    
    if(cipherTextSize > 8) { // Our RSA functions work with uint64_t
        printf("[TPM]: Cipher text too large for simplified RSA implementation (max 8 bytes)\n");
        return TPM_RC_SIZE;
    }
    
    if(offset + cipherTextSize > s->command_size){
        printf("[TPM] Invalid cipher text size: %d\n", cipherTextSize);
        return TPM_RC_SIZE;
    }
    
    // Extract ciphertext (convert bytes to uint64_t)
    uint64_t ciphertext = 0;
    for(int i = 0; i < cipherTextSize; i++){
        ciphertext |= ((uint64_t)s->command[offset + i]) << (i * 8);
    }
    offset += cipherTextSize;
    
    printf("[TPM]: Ciphertext: 0x%016lx (size: %d bytes)\n", ciphertext, cipherTextSize);

    // Parse scheme (simplified - just read algorithm)
    if(offset + 2 > s->command_size) return TPM_RC_SIZE;
    schemeAlg = (s->command[offset+1] << 8) | s->command[offset];
    offset += 2;
    
    printf("[TPM]: Decrypt scheme: 0x%04x\n", schemeAlg);
    
    // Parse label
    if(offset + 2 > s->command_size) return TPM_RC_SIZE;
    labelSize = (s->command[offset+1] << 8) | s->command[offset];
    offset += 2;
    
    if(offset + labelSize > s->command_size){
        printf("[TPM] Invalid label size: %d\n", labelSize);
        return TPM_RC_SIZE;
    }
    
    // Skip label data
    offset += labelSize;
    
    printf("[TPM]: Label size: %d bytes\n", labelSize);

    // Perform RSA decryption using the custom function
    printf("[TPM]: Performing RSA decryption...\n");
    uint64_t plaintext = rsa_decrypt(ciphertext, &(key->ctx->private_key));
    
    printf("[TPM]: Decryption result: 0x%016lx\n", plaintext);
    
    // Prepare response
    int resp_offset = 10;
    
    // TPM2B_PUBLIC_KEY_RSA message (the decrypted plaintext)
    // Convert uint64_t back to bytes
    uint8_t plaintextBytes[8];
    int plaintextSize = 0;
    
    // Find actual size (remove leading zeros)
    uint64_t temp = plaintext;
    if(temp == 0) {
        plaintextSize = 1;
        plaintextBytes[0] = 0;
    } else {
        while(temp > 0) {
            plaintextBytes[plaintextSize] = temp;
            temp >>= 8;
            plaintextSize++;
        }
    }
    
    // Write size
    if(resp_offset + 2 + plaintextSize > sizeof(s->response)){
        printf("[TPM]: Response buffer too small\n");
        return TPM_RC_FAILURE;
    }
    
    s->response[resp_offset] = plaintextSize;
    s->response[resp_offset + 1] = (plaintextSize >> 8);
    resp_offset += 2;
    
    // Write plaintext bytes
    memcpy(&s->response[resp_offset], plaintextBytes, plaintextSize);
    resp_offset += plaintextSize;
    
    s->response_size = resp_offset;

    printf("[TPM] RSA_Decrypt response prepared, size: %d bytes, plaintext size: %d\n", 
           s->response_size, plaintextSize);

    return TPM_RC_SUCCESS;
}

static uint32_t RSA_Encrypt(CustomTPMState *s){
    // TPM2_RSA_Encrypt command implementation
    printf("[TPM]: RSA_Encrypt Command execution\n");
    s->response_size = 10;
    
    if(s->state == TPM_STATE_IDLE) { 
        return TPM_RC_INITIALIZE; 
    } 
    
    if(s->command_size < 23) {  // 10 + 4 + 2 + 2 + 2 + 2 + 1 (minimum)
        printf("[TPM] RSA_Encrypt command too small\n");
        return TPM_RC_SIZE;
    }

    // Command structure:
    // TPMI_DH_OBJECT keyHandle                (uint32_t)  4 bytes
    // TPM2B_PUBLIC_KEY_RSA message            2 bytes + data
    // TPMT_RSA_DECRYPT inScheme              2 bytes (simplified)
    // TPM2B_DATA label                       2 bytes + data
    
    uint32_t keyHandle;
    uint16_t messageSize;
    uint16_t schemeAlg;
    uint16_t labelSize;
    int offset = 10;        // Skip TPM header

    // Parse keyHandle
    keyHandle = (s->command[offset+3] << 24) | (s->command[offset+2] << 16) | 
                (s->command[offset+1] << 8) | s->command[offset];
    offset += 4;
    
    printf("[TPM]: Key Handle: 0x%x\n", keyHandle);
    
    // Find the key - must be loaded
    TPM_Key *key = NULL;
    for(int i = 0; i < MAX_KEYS; i++){
        if(s->keys[i].loaded && s->keys[i].handle == keyHandle){
            key = &(s->keys[i]);
            break;
        }
    }
    
    if(key == NULL){
        printf("[TPM]: Key handle 0x%x not found or not loaded\n", keyHandle);
        return TPM_RC_HANDLE;
    }
    
    // Verify key type
    if(key->type != KEY_TYPE_RSA){
        printf("[TPM]: Key is not an RSA key\n");
        return TPM_RC_VALUE;
    }
    
    // For encrypt, we typically use the public key
    // Verify key can encrypt - skipped for simplicity

    // Parse message (plaintext to encrypt)
    if(offset + 2 > s->command_size) return TPM_RC_SIZE;
    messageSize = (s->command[offset+1] << 8) | s->command[offset];
    offset += 2;
    
    if(messageSize == 0) {
        printf("[TPM]: Message size cannot be zero\n");
        return TPM_RC_SIZE;
    }
    
    if(messageSize > 8) { // Our RSA functions work with uint64_t
        printf("[TPM]: Message too large for simplified RSA implementation (max 8 bytes)\n");
        return TPM_RC_SIZE;
    }
    
    if(offset + messageSize > s->command_size){
        printf("[TPM] Invalid message size: %d\n", messageSize);
        return TPM_RC_SIZE;
    }
    
    // Extract message (convert bytes to uint64_t)
    uint64_t message = 0;
    for(int i = 0; i < messageSize; i++){
        message |= ((uint64_t)s->command[offset + i]) << (i * 8);
    }
    offset += messageSize;
    
    printf("[TPM]: Message: 0x%016lx (size: %d bytes)\n", message, messageSize);

    // Parse scheme (simplified - just read algorithm)
    if(offset + 2 > s->command_size) return TPM_RC_SIZE;
    schemeAlg = (s->command[offset+1] << 8) | s->command[offset];
    offset += 2;
    
    printf("[TPM]: Encrypt scheme: 0x%04x\n", schemeAlg);
    
    // Parse label
    if(offset + 2 > s->command_size) return TPM_RC_SIZE;
    labelSize = (s->command[offset+1] << 8) | s->command[offset];
    offset += 2;
    
    if(offset + labelSize > s->command_size){
        printf("[TPM] Invalid label size: %d\n", labelSize);
        return TPM_RC_SIZE;
    }
    
    // Skip label data
    offset += labelSize;
    
    printf("[TPM]: Label size: %d bytes\n", labelSize);

    // Perform RSA encryption using the custom function
    printf("[TPM]: Performing RSA encryption...\n");
    uint64_t ciphertext = rsa_encrypt(message, &(key->ctx->public_key));
    
    printf("[TPM]: Encryption result: 0x%016lx\n", ciphertext);
    
    // Prepare response
    int resp_offset = 10;
    
    // TPM2B_PUBLIC_KEY_RSA outData (the encrypted ciphertext)
    // Convert uint64_t back to bytes
    uint8_t ciphertextBytes[8];
    int ciphertextSize = 0;
    
    // Find actual size (remove leading zeros)
    uint64_t temp = ciphertext;
    if(temp == 0) {
        ciphertextSize = 1;
        ciphertextBytes[0] = 0;
    } else {
        while(temp > 0) {
            ciphertextBytes[ciphertextSize] = temp;
            temp >>= 8;
            ciphertextSize++;
        }
    }
    
    // Write size
    if(resp_offset + 2 + ciphertextSize > sizeof(s->response)){
        printf("[TPM]: Response buffer too small\n");
        return TPM_RC_FAILURE;
    }
    
    s->response[resp_offset] = ciphertextSize;
    s->response[resp_offset + 1] = (ciphertextSize >> 8);
    resp_offset += 2;
    
    // Write ciphertext bytes
    memcpy(&s->response[resp_offset], ciphertextBytes, ciphertextSize);
    resp_offset += ciphertextSize;
    
    s->response_size = resp_offset;

    printf("[TPM] RSA_Encrypt response prepared, size: %d bytes, ciphertext size: %d\n", 
           s->response_size, ciphertextSize);

    return TPM_RC_SUCCESS;
}

/*  End  Commands */
static void process_command(CustomTPMState *s){
    // Parsing TPM header
    // +---------------+----------------+------------------------+
    // | Tag (2 bytes) | Size (4 bytes) | Command Code (4 bytes) |
    // +---------------+----------------+------------------------+
    
    uint16_t tag = (s->command[1] << 8) | s->command[0];
    uint32_t size = (s->command[5] << 24) | (s->command[4] << 16) | (s->command[3] << 8) | s->command[2];
    uint32_t command_code = (s->command[9] << 24) | (s->command[8] << 16) | (s->command[7] << 8) | s->command[6];
    uint32_t rc = 0;            // Response code
 
    printf("[TPM]: Processing command: Tag: 0x%04x, Size: %d, Command Code: 0x%08x\n", tag, size, command_code);

    switch (command_code){
        case TPM2_CC_SelfTest:
            rc = SelfTest(s); 
            break;
        case TPM2_CC_Startup:
            rc = Startup(s);
            break;
        case TPM2_CC_Shutdown:
            rc = Shutdown(s); 
            break;
        case TPM2_CC_CreatePrimary:
            rc = CreatePrimary(s);
            break;
        case TPM2_CC_Create:
            rc = Create(s);
            break;
        case TPM2_CC_Load:
            printf("[TPM]: Load Command not implemented");
            break;
        case TPM2_CC_StartAuthSession:
            printf("[TPM]: StartAuthSession Command execution\n");
            rc = SUCCESS_CODE;     
            break;
        case TPM2_CC_GetCapability:
            printf("[TPM]: GetCapability Command execution\n");
            rc = SUCCESS_CODE;     
            break;
        case TPM2_CC_GetRandom:
            printf("[TPM]: GetRandom Command execution\n");
            rc = SUCCESS_CODE;     
            break;
        default:
            printf("[TPM]: Command not recognized\n");
            rc = ERROR_CODE;
            break;
    }

    // +---------------+----------------+-------------------------+
    // | Tag (2 bytes) | Size (4 bytes) | Response Code (4 bytes) |
    // +---------------+----------------+-------------------------+
   
    // Setting response tag field   
    s->response[1] = (tag >> 8);
    s->response[0] = (tag >> 0);
    
    // Setting response size field
    s->response[5] = (s->response_size >> 24);
    s->response[4] = (s->response_size >> 16);
    s->response[3] = (s->response_size >>  8);
    s->response[2] = (s->response_size >>  0);

    // Setting response code filed
    s->response[9] = (rc >> 24);
    s->response[8] = (rc >> 16);
    s->response[7] = (rc >>  8);
    s->response[6] = (rc >>  0);

    s->regs[R_TPM_STS] |= R_TPM_STS_DATA_AVAIL_MASK;
}

static void process_command_bh(void *opaque){
    CustomTPMState *s = opaque;
    process_command(s);
    s->processing = false;
    s->regs[R_TPM_STS] &= ~R_TPM_STS_GO_MASK;
}

static uint64_t custom_tpm_mmio_read(void *opaque, hwaddr addr, unsigned size){
    CustomTPMState *s = opaque;
    uint32_t val = 0;
   
    //printf("[TPM]: Reading address: 0x%lx\n", addr);

    switch(addr){
        case A_TPM_ACCESS:
            // Reports TPM accessibility status
            return s->regs[R_TPM_ACCESS];
        case A_TPM_STS:
            // Reports Status register
            return s->regs[R_TPM_STS];
        case A_TPM_DATA_FIFO:
            if(s->response_pos < s->response_size){
                val = s->response[s->response_pos++];
                if(s->response_pos == s->response_size){
                    s->response_pos = s->response_size = 0;
                    s->regs[R_TPM_STS] &= ~R_TPM_STS_DATA_AVAIL_MASK;
                }
            }
            return val;
        default:
            qemu_log_mask(LOG_UNIMP, "%s: Unhandled read at 0x%" HWADDR_PRIx "\n", __func__, addr);
    }
    return val;
}

static void custom_tpm_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size){
    CustomTPMState *s = opaque;
    
    switch (addr){
        case A_TPM_STS:
            if ((val & R_TPM_STS_DATA_AVAIL_MASK) | (val & R_TPM_STS_DATA_EXPECT_MASK)){
                printf("[TPM]: It is not possible to write this/these bit/s on status register\n");
                break;
            }
            s->regs[R_TPM_STS] = s->regs[R_TPM_STS] | val;
            if(val & R_TPM_STS_GO_MASK){
                // To trigger data execution
                printf("[TPM]: Triggering command execution\n");
                s->processing = true;
                //qemu_bh_schedule(s->command_bh);
                process_command(s);
            }
            break;
        case A_TPM_DATA_FIFO:
            // Accumulate commands
            if(s->command_pos < sizeof(s->command)) {
                // +---------------+----------------+------------------------+
                // | Tag (2 bytes) | Size (4 bytes) | Command Code (4 bytes) |
                // +---------------+----------------+------------------------+
                s->command[s->command_pos++] = val; 
                
                if (s->command_pos >= 6){   
                    // Waiting 6 bytes to have the size and to check it 
                    // Parsing size 
                    
                    s->command_size = (s->command[5] << 24) | (s->command[4] << 16) | (s->command[3] << 8) | s->command[2];
                    if(s->command_size > sizeof(s->command)){
                        // Command size too big, return error
                        printf("[TPM]: Command size too big: %d\n", s->command_size);
                        s->regs[R_TPM_STS] |= R_TPM_STS_ERROR_MASK; 
                        s->command_pos = s->command_size = 0;
                    }
                }
            }
            break;
        default:
            qemu_log_mask(LOG_UNIMP, "%s: Unhandled write at 0x%" HWADDR_PRIx "\n", __func__, addr);
    }
}



static const MemoryRegionOps custom_tpm_mmio_ops = {
    .read = custom_tpm_mmio_read,
    .write = custom_tpm_mmio_write,
};

static void custom_tpm_init(Object *obj){
    CustomTPMState *s = CUSTOM_TPM(obj);

    // Clear registers
    memset(s->regs, 0, sizeof(s->regs)); 
    
    // Initialize command state
    memset(s->command, 0, sizeof(s->command));
    s->command_size = 0;
    s->command_pos = 0;
    
    // Initialize response state
    memset(s->response, 0, sizeof(s->response));
    s->response_size = 0;
    s->response_pos = 0;

    // Initialize FIFO state
    memset(s->fifo, 0, sizeof(s->fifo));
    s->fifo_pos = 0;

    s->processing = false;

    /* Initialize register values */
    // Set interface capabilities (FIFO interface)
    s->regs[R_TPM_INTF_CAPABILITY] = R_TPM_INTF_CAPABILITY_FIFO_IF_MASK;

    // Set device and vendor id
    s->regs[R_TPM_DID_VID] = 0x00000000;

    // Initialize TPM_STS to ready state 
    s->regs[R_TPM_STS] = R_TPM_STS_VALID_MASK;

    // Initialize TPM_ACCESS to ready state 
    s->regs[R_TPM_ACCESS] = R_TPM_ACCESS_VALID_MASK | R_TPM_ACCESS_ACTIVE_MASK;
    
    s->state = TPM_STATE_IDLE;
    
    memset(s->keys, 0, sizeof(s->keys));
    s->next_handle = KEY_HANDLE_BASE;

    printf("[TPM] awaiting startup command");
}

static void custom_tpm_realize(DeviceState *dev, Error **errp){
    CustomTPMState *s = CUSTOM_TPM(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);

    s->command_bh = qemu_bh_new(process_command_bh, s);

    /* Initialize MMIO region */
    memory_region_init_io(&s->mmio, OBJECT(dev), &custom_tpm_mmio_ops, s, "custom-tpm-mmio", 0x100);
    sysbus_init_mmio(sbd, &s->mmio);

}

static void custom_tpm_finalize(Object *obj){
    CustomTPMState *s = CUSTOM_TPM(obj);

    if(s->command_bh){
        qemu_bh_delete(s->command_bh);
        s->command_bh = NULL;
    }
}

static void custom_tpm_class_init(ObjectClass *klass, void *data){
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = custom_tpm_realize;

    //device_class_set_parent_realize(dc, custom_tpm_realize, &SYS_BUS_DEVICE_CLASS(klass)->parent_realize);
}

static const TypeInfo custom_tpm_info = {
    .name          = TYPE_CUSTOM_TPM,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(CustomTPMState),
    .instance_init = custom_tpm_init,
    .instance_finalize = custom_tpm_finalize,
    .class_init    = custom_tpm_class_init,
};

static void custom_tpm_register_types(void){
    type_register_static(&custom_tpm_info);        
}

type_init(custom_tpm_register_types);
