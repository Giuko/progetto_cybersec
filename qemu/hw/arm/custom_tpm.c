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
#include "openssl/core_names.h"

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

/**/
static int build_tpm2b_public_response(CustomTPMState *s, TPM_Key *key, TPM2B_PUBLIC *inPublic, int *resp_offset) {
    int start_offset = *resp_offset;
    
    // Size space
    *resp_offset += 2;
    
    // TPMT_PUBLIC
    
    // Type (2 bytes)
    s->response[*resp_offset] = inPublic->publicArea.type;
    s->response[*resp_offset+1] = inPublic->publicArea.type >> 8;
    *resp_offset += 2;

    // NameAlg (2 bytes)
    s->response[*resp_offset] = inPublic->publicArea.nameAlg;
    s->response[*resp_offset+1] = inPublic->publicArea.nameAlg >> 8;
    *resp_offset += 2;

    // Object Attributes (4 bytes)
    s->response[*resp_offset] = key->attributes;
    s->response[*resp_offset+1] = key->attributes >> 8;
    s->response[*resp_offset+2] = key->attributes >> 16;
    s->response[*resp_offset+3] = key->attributes >> 24;
    *resp_offset += 4;

    // Auth Policy 
    uint16_t authPolicySize = inPublic->publicArea.authPolicy.size;
    s->response[*resp_offset] = authPolicySize;
    s->response[*resp_offset+1] = authPolicySize >> 8;
    *resp_offset += 2;
    
    if (authPolicySize > 0) {
        memcpy(&s->response[*resp_offset], inPublic->publicArea.authPolicy.buffer, authPolicySize);
        *resp_offset += authPolicySize;
    }

    // Parameters (TPMU_PUBLIC_PARMS)
    if (inPublic->publicArea.type == TPM_ALG_RSA) {
        // RSA Parameters
        
        // Symmetric (TPMT_SYM_DEF_OBJECT) - NULL
        s->response[*resp_offset] = 0x00; // TPM_ALG_NULL
        s->response[*resp_offset + 1] = 0x10;
        *resp_offset += 2;
        
        // Scheme (TPMT_RSA_SCHEME) - NULL
        s->response[*resp_offset] = 0x00; // TPM_ALG_NULL
        s->response[*resp_offset + 1] = 0x10;
        *resp_offset += 2;
        
        // Key Bits (2 bytes)
        uint16_t keyBits = inPublic->publicArea.parameters.keyBits;
        s->response[*resp_offset] = keyBits;
        s->response[*resp_offset + 1] = (keyBits >> 8);
        *resp_offset += 2;
        
        // Exponent (4 bytes) - default 65537
        uint32_t exponent = inPublic->publicArea.parameters.exponent;
        s->response[*resp_offset] = exponent & 0xFF;
        s->response[*resp_offset + 1] = (exponent >> 8);
        s->response[*resp_offset + 2] = (exponent >> 16);
        s->response[*resp_offset + 3] = (exponent >> 24);
        *resp_offset += 4;
    }
    
    // Unique (TPMU_PUBLIC_ID) - Contains pub key
    if (inPublic->publicArea.type == TPM_ALG_RSA && key->key && key->key->pkey) {
        // Estrai il modulo RSA
        EVP_PKEY *pkey = key->key->pkey;
        BIGNUM *n = NULL;
        
        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) == 1) {
            int n_size = BN_num_bytes(n);
            
            // Dimensione del modulo (2 bytes)
            s->response[*resp_offset] = n_size & 0xFF;
            s->response[*resp_offset + 1] = (n_size >> 8) & 0xFF;
            *resp_offset += 2;
            
            // Modulo RSA
            if (*resp_offset + n_size <= sizeof(s->response)) {
                BN_bn2bin(n, &s->response[*resp_offset]);
                *resp_offset += n_size;
            }
            
            BN_free(n);
        } else {
            // Se non riesci a estrarre il modulo, metti dimensione 0
            s->response[*resp_offset] = 0x00;
            s->response[*resp_offset + 1] = 0x00;
            *resp_offset += 2;
        }
    } else {
        // Nessuna chiave pubblica disponibile
        s->response[*resp_offset] = 0x00;
        s->response[*resp_offset + 1] = 0x00;
        *resp_offset += 2;
    }

    uint16_t total_size = *resp_offset - start_offset - 2;
    
    s->response[start_offset] = total_size;
    s->response[start_offset + 1] = (total_size >> 8);

    return 0;
}

static int build_creation_data(CustomTPMState *s, TPM_Key *key, int *resp_offset) {
    int start_offset = *resp_offset;
    
    // Size space (2 bytes)
    *resp_offset += 2;
    
    // TPML_PCR_SELECTION pcrSelect (NULL)
    s->response[*resp_offset] = 0x00; // count = 0
    s->response[*resp_offset + 1] = 0x00;
    s->response[*resp_offset + 2] = 0x00;
    s->response[*resp_offset + 3] = 0x00;
    *resp_offset += 4;
    
    // TPM2B_DIGEST pcrDigest (NULL)
    s->response[*resp_offset] = 0x00; // size = 0
    s->response[*resp_offset + 1] = 0x00;
    *resp_offset += 2;
    
    // TPMA_LOCALITY locality (0)
    s->response[*resp_offset] = 0x00;
    *resp_offset += 1;
    
    // TPM_ALG_ID parentNameAlg (TPM_ALG_NULL)
    s->response[*resp_offset] = 0x00;
    s->response[*resp_offset + 1] = 0x10;
    *resp_offset += 2;
    
    // TPM2B_NAME parentName (NULL)
    s->response[*resp_offset] = 0x00; // size = 0
    s->response[*resp_offset + 1] = 0x00;
    *resp_offset += 2;
    
    // TPM2B_NAME parentQualifiedName (NULL)
    s->response[*resp_offset] = 0x00; // size = 0
    s->response[*resp_offset + 1] = 0x00;
    *resp_offset += 2;
    
    // TPM2B_DATA outsideInfo (vuoto)
    s->response[*resp_offset] = 0x00; // size = 0
    s->response[*resp_offset + 1] = 0x00;
    *resp_offset += 2;
    
    uint16_t total_size = *resp_offset - start_offset - 2;
    s->response[start_offset] = total_size;
    s->response[start_offset + 1] = (total_size >> 8);
    
    return 0;
}

static int build_creation_hash(CustomTPMState *s, TPM_Key *key, int *resp_offset) {
    // Null for simplicity
    s->response[*resp_offset] = 0x00; // size = 0
    s->response[*resp_offset + 1] = 0x00;
    *resp_offset += 2;
    
    return 0;
}

static int build_creation_ticket(CustomTPMState *s, TPM_Key *key, int *resp_offset) {
    // Tag (2 bytes)
    s->response[*resp_offset] = 0x21; // TPM_ST_CREATION low byte
    s->response[*resp_offset + 1] = 0x80; // TPM_ST_CREATION high byte
    *resp_offset += 2;
    
    // Hierarchy (4 bytes)
    s->response[*resp_offset] = key->hierarchy;
    s->response[*resp_offset + 1] = (key->hierarchy >> 8);
    s->response[*resp_offset + 2] = (key->hierarchy >> 16);
    s->response[*resp_offset + 3] = (key->hierarchy >> 24);
    *resp_offset += 4;
    
    // Digest (TPM2B_DIGEST) - NULL
    s->response[*resp_offset] = 0x00; // size = 0
    s->response[*resp_offset + 1] = 0x00;
    *resp_offset += 2;
    
    return 0;
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
    //uint32_t creationPCRCount;
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
   

    offset += 8;
    inPublic.publicArea.authPolicy.size = (s->command[offset + 1] << 8) | s->command[offset];
    offset += 2;

    // Skipping AuthPolicy
    offset += inPublic.publicArea.authPolicy.size;
    printf("[TPM]: authPolicy size: %d\n", inPublic.publicArea.authPolicy.size);

    // Skipping symmetric
    offset += 2+2+2;

    // Skipping scheme
    offset += 2+2;

    inPublic.publicArea.parameters.keyBits = (s->command[offset + 1] << 8) | s->command[offset];
    offset += 2;
    printf("[TPM]: rsa key bit size: %d\n", inPublic.publicArea.parameters.keyBits);
    // Using the standard
    inPublic.publicArea.parameters.exponent =  (s->command[offset + 3] << 24) | (s->command[offset + 2] << 16) | (s->command[offset + 1] << 8) | s->command[offset];
    offset += 4;
    
    inPublic.publicArea.unique.size = (s->command[offset + 1] << 8) | s->command[offset];
    offset += 2;
    offset += inPublic.publicArea.unique.size;


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
    //creationPCRCount =  (s->command[offset+3] << 24)| (s->command[offset+2] << 16) | (s->command[offset+1] << 8) | s->command[offset]; 
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
    key->type = KEY_TYPE_RSA;
    key->attributes = inPublic.publicArea.objectAttributes;
    key->algorithm = inPublic.publicArea.type;
    
    key->usage_count = 0;
    key->status = KEY_STATUS_ACTIVE;

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
    if(!(key->key = qemu_generate_rsa_key(inPublic.publicArea.parameters.keyBits))){
        printf("[TPM]: key generation failed, debug 11\n");
        return TPM_RC_FAILURE;
    }
    key->loaded = true;
    key->hierarchy = primaryHandle;
    
    if(key->key->public_key_der && key->key->public_key_len > 0){
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if(ctx){
            unsigned char hash[32];
            unsigned int hash_len;
           
            EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
            EVP_DigestUpdate(ctx, key->key->public_key_der, key->key->public_key_len);
            EVP_DigestFinal_ex(ctx, hash, &hash_len);

            memcpy(key->fingerprint, hash, 8);
            EVP_MD_CTX_free(ctx);
        }
    }
    

    printf("[TPM] Created primary key with handle: 0x%08x\n", key->handle);
    s->keys[slot] = *key;
    
    // Prepare response
    int resp_offset = 10;
    
    // Object Handle 4 bytes
    s->response[resp_offset] = key->handle;
    s->response[resp_offset + 1] = key->handle >> 8;
    s->response[resp_offset + 2] = key->handle >> 16;
    s->response[resp_offset + 3] = key->handle >> 24;
    resp_offset += 4;

    printf("Handle: %02x %02x %02x %02x\n", key->handle, key->handle >> 8, key->handle >> 16, key->handle >> 24);

    // TPM2B_PUBLIC outPublic
    if (build_tpm2b_public_response(s, key, &inPublic, &resp_offset) != 0){
        printf("[TPM]: Failed to build TPM2B_PUBLIC\n");
        free(key);
        return TPM_RC_FAILURE;
    }

    // TPM2B_CREATION_DATA creationData
    if (build_creation_data(s, key, &resp_offset) != 0) {
        printf("[TPM]: Failed to build creation data\n");
        free(key);
        return TPM_RC_FAILURE;
    }

    // TPM2B_DIGEST creationHash
    if (build_creation_hash(s, key, &resp_offset) != 0) {
        printf("[TPM]: Failed to build creation hash\n");
        free(key);
        return TPM_RC_FAILURE;
    }

    // TPMT_TK_CREATION creationTicket
    if (build_creation_ticket(s, key, &resp_offset) != 0) {
        printf("[TPM]: Failed to build creation ticket\n");
        free(key);
        return TPM_RC_FAILURE;
    }
    s->response_size = resp_offset;
    
    printf("[TPM] CreatePrimary response prepared, size: %d bytes\n", s->response_size);
    printf("[TPM] Key handle: 0x%08x, Type: %d, Bits: %d\n", 
           key->handle, key->type, inPublic.publicArea.parameters.keyBits);
    
    free(key); // La chiave è già copiata in s->keys[slot]
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
    if(offset + 2 > s->command_size) {
        printf("[TPM]: Invalid command size: %d, debug 3\n", s->command_size);
        return TPM_RC_SIZE;
    }
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
    
    if(inPublic.size < 8) {
        printf("[TPM] Invalid inPublic size: %d, debug 7\n", inPublic.size);
        return TPM_RC_SIZE;
    }

    // Parse public area
    inPublic.publicArea.type = (s->command[offset + 1] << 8) | s->command[offset]; 
    inPublic.publicArea.nameAlg = (s->command[offset + 3] << 8) | s->command[offset + 2]; 
    inPublic.publicArea.objectAttributes = (s->command[offset + 7] << 24) | 
                                          (s->command[offset + 6] << 16) | 
                                          (s->command[offset + 5] << 8) | 
                                          s->command[offset + 4]; 
    
    printf("[TPM] Algorithm: 0x%04x, NameAlg: 0x%04x, Attributes: 0x%08x\n", 
           inPublic.publicArea.type, inPublic.publicArea.nameAlg, inPublic.publicArea.objectAttributes);

    offset += 8;
    // Parse authPolicy
    inPublic.publicArea.authPolicy.size = (s->command[offset + 1] << 8) | s->command[offset];
    offset += 2;
    
    // Skip AuthPolicy
    offset += inPublic.publicArea.authPolicy.size;
    printf("[TPM]: authPolicy size: %d\n", inPublic.publicArea.authPolicy.size);

    // Skip symmetric
    offset += 2+2+2;

    // Skip scheme
    offset += 2+2;

    // Parse key parameters
    inPublic.publicArea.parameters.keyBits = (s->command[offset + 1] << 8) | s->command[offset];
    offset += 2;
    printf("[TPM]: rsa key bit size: %d\n", inPublic.publicArea.parameters.keyBits);
    
    // Parse exponent
    inPublic.publicArea.parameters.exponent = (s->command[offset + 3] << 24) | 
                                             (s->command[offset + 2] << 16) | 
                                             (s->command[offset + 1] << 8) | 
                                             s->command[offset];
    offset += 4;
    
    // Parse unique
    inPublic.publicArea.unique.size = (s->command[offset + 1] << 8) | s->command[offset];
    offset += 2;
    offset += inPublic.publicArea.unique.size;

    // Parse outsideInfo
    if(offset + 2 > s->command_size){
        printf("[TPM]: Invalid command size: %d, debug 8\n", s->command_size);
        return TPM_RC_SIZE;
    }
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

    TPM_Key *key = (TPM_Key*)malloc(sizeof(TPM_Key));
    if(!key){
        printf("[TPM]: Memory allocation failed\n");
        return TPM_RC_FAILURE;        
    }
    key->handle = 0; // Create command doesn't assign handle immediately
    key->parent_handle = parentHandle;
    key->type = KEY_TYPE_RSA;
    key->attributes = inPublic.publicArea.objectAttributes;
    key->algorithm = inPublic.publicArea.type;
    key->usage_count = 0;
    key->status = KEY_STATUS_ACTIVE;
    
    switch (inPublic.publicArea.type){
        case TPM_ALG_RSA:
            key->type = KEY_TYPE_RSA;
            break;
        default:
            printf("[TPM] Unsupported algorithm: 0x%04X\n", inPublic.publicArea.type);
            return TPM_RC_ASYMMETRIC;
    }
    
    key->hierarchy = parentKey->hierarchy;
    
    if(!(key->key = qemu_generate_rsa_key(inPublic.publicArea.parameters.keyBits))){
        printf("[TPM]: key generation failed, debug 11\n");
        free(key);
        return TPM_RC_FAILURE;
    }
   
    if(key->key->public_key_der && key->key->public_key_len > 0){
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if(ctx){
            unsigned char hash[32];
            unsigned int hash_len;
           
            EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
            EVP_DigestUpdate(ctx, key->key->public_key_der, key->key->public_key_len);
            EVP_DigestFinal_ex(ctx, hash, &hash_len);

            memcpy(key->fingerprint, hash, 8);
            EVP_MD_CTX_free(ctx);
        }
    }

    printf("[TPM] Created key under parent 0x%08x\n", parentHandle);

    // Store the key in the slot
    s->keys[slot] = *key;

    key->loaded = true;

    // Prepare response - improved response building
    int resp_offset = 10;

    // TPM2B_PRIVATE outPrivate (simplified - in real TPM this would be encrypted)
    uint16_t privateSize = key->key->private_key_len;
    if(privateSize == 0) {
        privateSize = sizeof(key->key->private_key_der); // fallback
    }
    
    s->response[resp_offset] = privateSize & 0xFF;
    s->response[resp_offset + 1] = (privateSize >> 8) & 0xFF;
    resp_offset += 2;
    
    if(resp_offset + privateSize > sizeof(s->response)){
        printf("[TPM]: Response buffer too small for private key\n");
        free(key);
        return TPM_RC_FAILURE;
    }
    



    // In a real implementation, this should be encrypted with parent's key
    if(key->key->private_key_der && key->key->private_key_len > 0) {
        memcpy(&s->response[resp_offset], key->key->private_key_der, privateSize);
    }
    
    /* Encrypt private key */
    uint8_t *private_key_data = NULL;
    private_key_data = key->key->private_key_der;
    printf("[TPM]: Encrypting private key with parent's public key...\n");

    size_t ciphertext_buffer_size = parentKey->key->public_key_len;
    uint8_t *ciphertext_buffer = malloc(ciphertext_buffer_size);
    if(!ciphertext_buffer){
        printf("[TPM]: Failed to allocate ciphertext buffer for private key encryption\n");
        free(key);
        return TPM_RC_FAILURE;
    }

    int ciphertext_len = 0;
    ciphertext_len = qemu_rsa_encrypt(parentKey->key, private_key_data, privateSize, &ciphertext_buffer, &ciphertext_buffer_size);
    
    if(ciphertext_len <= 0) {
        printf("[TPM]: Failed to encrypt private key with parent's public key\n");
        free(ciphertext_buffer);
        free(key);
        return TPM_RC_FAILURE;
    }

    // Store encrypted private key size in response
    s->response[resp_offset] = ciphertext_len & 0xFF;
    s->response[resp_offset + 1] = (ciphertext_len >> 8) & 0xFF;
    resp_offset += 2;
    if(resp_offset + ciphertext_len > sizeof(s->response)){
        printf("[TPM]: Response buffer too small for encrypted private key\n");
        free(ciphertext_buffer);
        free(key);
        return TPM_RC_FAILURE;
    }
    
    // Copy encrypted private key to response
    memcpy(&s->response[resp_offset], ciphertext_buffer, ciphertext_len);
    resp_offset += ciphertext_len;
    // Clean up encryption buffer
    free(ciphertext_buffer);
    printf("[TPM]: Private key encrypted successfully, size: %d bytes\n", ciphertext_len);

    // TPM2B_PUBLIC outPublic - use helper function like CreatePrimary
    if (build_tpm2b_public_response(s, key, &inPublic, &resp_offset) != 0){
        printf("[TPM]: Failed to build TPM2B_PUBLIC\n");
        free(key);
        return TPM_RC_FAILURE;
    }

    // TPM2B_CREATION_DATA creationData
    if (build_creation_data(s, key, &resp_offset) != 0) {
        printf("[TPM]: Failed to build creation data\n");
        free(key);
        return TPM_RC_FAILURE;
    }

    // TPMT_TK_CREATION creationTicket
    if (build_creation_ticket(s, key, &resp_offset) != 0) {
        printf("[TPM]: Failed to build creation ticket\n");
        free(key);
        return TPM_RC_FAILURE;
    }

    // TPM2B_DIGEST name (simplified, empty for now)
    s->response[resp_offset] = 0x00; // size low
    s->response[resp_offset + 1] = 0x00; // size high
    resp_offset += 2;
    
    s->response_size = resp_offset;

    printf("[TPM] Create response prepared, size: %d bytes\n", s->response_size);
    printf("[TPM] Key handle: 0x%08x, Type: %d, Bits: %d\n", 
           key->handle, key->type, inPublic.publicArea.parameters.keyBits);

    free(key); // The key is already copied to s->keys[slot]
    return TPM_RC_SUCCESS;
    return creationPCRCount;    // To remove unused warning
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
    
    
    if(offset + cipherTextSize > s->command_size){
        printf("[TPM] Invalid cipher text size: %d\n", cipherTextSize);
        return TPM_RC_SIZE;
    }
   
    // Store ciphertext as byte array
    uint8_t *ciphertext = &s->command[offset];
    offset += cipherTextSize;
    printf("[TPM]: Ciphertext size: %d bytes\n", cipherTextSize);
    
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
    uint8_t *plaintext_buffer;
    size_t plaintext_len = 0;
   
    plaintext_len = qemu_rsa_decrypt(key->key, ciphertext, cipherTextSize, &plaintext_buffer, &plaintext_len);

    printf("[TPM]: Decryption result size: 0x%016lx\n", plaintext_len);
   
    key->usage_count++;
    // Prepare response
    int resp_offset = 10;
    
    // TPM2B_PUBLIC_KEY_RSA message (the decrypted plaintext)
    if(resp_offset + 2 + plaintext_len > sizeof(s->response)){
        printf("[TPM]: Response buffer too small (need %ld bytes)\n", resp_offset + 2 + plaintext_len);
        return TPM_RC_FAILURE;
    }

    s->response[resp_offset] = plaintext_len;
    s->response[resp_offset + 1] = (plaintext_len >> 8);
    resp_offset += 2;

    memcpy(&s->response[resp_offset], plaintext_buffer, plaintext_len);
    resp_offset += plaintext_len;
    s->response_size = resp_offset;

    printf("[TPM] RSA_Decrypt response prepared, size: %d bytes, plaintext size: %ld\n", s->response_size, plaintext_len);
    printf("[TPM] Key handle: 0x%08x, Usage count: %d\n", key->handle, key->usage_count);


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
   
    int keyByteSize = (EVP_PKEY_bits(key->key->pkey)+7)/8;
    // We're using PKCS#1 1.5
    int maxMessageSize = keyByteSize - 11;  // Overhead
    if(messageSize > maxMessageSize) { 
        printf("[TPM]: Message too large for simplified RSA implementation size: %d bytes (max %d bytes)\n", messageSize, maxMessageSize);
        return TPM_RC_SIZE;
    }
    
    if(offset + messageSize > s->command_size){
        printf("[TPM] Invalid message size: %d\n", messageSize);
        return TPM_RC_SIZE;
    }
    
    uint8_t *message = &s->command[offset];
    offset += messageSize;

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
   
    size_t ciphertext_buffer_size = keyByteSize;
    uint8_t *ciphertext_buffer = malloc(ciphertext_buffer_size);
    if(!ciphertext_buffer){
        printf("[TPM]: Failed to allocate ciphertext buffer\n");
        return TPM_RC_FAILURE;
    }
   
    int ciphertext_len = 0;
    ciphertext_len = qemu_rsa_encrypt(key->key, message, messageSize, &ciphertext_buffer, &ciphertext_buffer_size);

    // Prepare response
    int resp_offset = 10;
   
    // TPM2B_PUBLIC_KEY_RSA
    s->response[resp_offset] = ciphertext_len;
    s->response[resp_offset + 1] = (ciphertext_len >> 8);
    resp_offset += 2;

    // Write ciphertext bytes
    memcpy(&s->response[resp_offset], ciphertext_buffer, ciphertext_buffer_size);
    resp_offset += ciphertext_buffer_size;
    
    s->response_size = resp_offset;

    printf("[TPM] RSA_Encrypt response prepared, size: %d bytes, ciphertext size: %ld\n", s->response_size, ciphertext_buffer_size);

    free(ciphertext_buffer);
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
        case TPM2_CC_RSA_Encrypt:
            rc = RSA_Encrypt(s);
            break;
        case TPM2_CC_RSA_Decrypt:
            rc = RSA_Decrypt(s);
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
                s->command_pos = 0;
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
                //printf("0x%lx | 0x%lx\n", s->command[s->command_pos-1], val); 
                if (s->command_pos == 6){
                    s->command_size = (s->command[5] << 24) | (s->command[4] << 16) | (s->command[3] << 8) | s->command[2];
                    //printf("Command size: %lx\n", s->command_size);
                }
                
                if (s->command_pos >= 6){   
                    // Waiting 6 bytes to have the size and to check it 
                    // Parsing size 
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
