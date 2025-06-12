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
REG32(TPM_ACCESS, 0X00)
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
    uint8_t fifo[256];
    uint32_t fifo_pos;
        
    uint32_t regs[0x100/sizeof(uint32_t)];

    uint8_t command[256];
    uint32_t command_size;
    uint32_t command_pos;

    uint8_t response[265];
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
        printf("[TPM] CreatePrimary command too small\n");
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
        printf("[TPM]: Primary Handle: 0x%x, isn't a valid value\n", primaryHandle);
        return TPM_RC_HANDLE;
    }
    
    printf("[TPM]: Primary Handle: 0x%x\n", primaryHandle);
    offset += 4;
    if(offset+2 > s->command_size) return TPM_RC_SIZE;
    
    inSensitive.size = (s->command[offset+1] << 8) | s->command[offset];
    offset += 2;
    if(offset + inSensitive.size > s->command_size){
        printf("[TPM] Invalid inSensitive size: %d\n", inSensitive.size);
        return TPM_RC_SIZE;
    }
    // Skip inSensitive Value 

    offset += inSensitive.size;
    if(offset+2 > s->command_size) return TPM_RC_SIZE;

    inPublic.size = (s->command[offset+1] << 8) | s->command[offset];
    offset += 2;
    if(offset+inPublic.size > s->command_size){
        printf("[TPM] Invalid inPublic size: %d\n", inPublic.size);
        return TPM_RC_SIZE;
    }
    
    if(inPublic.size < 8) return TPM_RC_SIZE;
    inPublic.publicArea.type = (s->command[offset + 1] <<  8) | s->command[offset]; 
    inPublic.publicArea.nameAlg = (s->command[offset + 3] <<  8) | s->command[offset+2]; 
    inPublic.publicArea.objectAttributes = (s->command[offset + 7] << 24) | (s->command[offset + 6] << 16) | (s->command[offset + 5] << 8) | s->command[offset + 4]; 
    printf("[TPM] Algorithm: 0x%04x, NameAlg: 0x%04x, Attributes: 0x%08x\n", inPublic.publicArea.type, inPublic.publicArea.nameAlg, inPublic.publicArea.objectAttributes);

    // Skipping 
    //      AuthPolicy
    //      parameters

    offset += inPublic.size;

    if(offset+2 > s->command_size) return TPM_RC_SIZE;
    
    outsideInfoSize = (s->command[offset+1] << 8) | s->command[offset];
    offset += 2;
    if(offset + outsideInfoSize > s->command_size){
        printf("[TPM] Invalid outSideInfo size: %d\n", outsideInfoSize);
        return TPM_RC_SIZE;
    }
    // Skipping OutsideInfoSize
    offset += outsideInfoSize;

    if(offset+4 > s->command_size) return TPM_RC_SIZE;

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
        return TPM_RC_OBJECT_MEMORY;
    }

    TPM_Key *key = &(s->keys[slot]);

    // Initialize key
    key->handle = KEY_HANDLE_BASE + s->next_handle++;

    switch (inPublic.publicArea.type){
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
    if(generate_rsa_keys(key->ctx, 1024)){
        return TPM_RC_FAILURE;
    }
    key->loaded = true;
    key->hierarchy = primaryHandle;
    printf("[TPM] Created primary key with handle: 0x%08x\n", key->handle);

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
        printf("[TPM]: Response buffer too small\n");
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
   
    printf("[TPM]: Reading address: 0x%lx\n", addr);

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
                qemu_bh_schedule(s->command_bh);
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
