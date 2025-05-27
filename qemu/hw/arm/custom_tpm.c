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

    bool processing;
};

/* COMMAND DEFINITION */
/* https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-2-Version-184_pub.pdf */
/* 6.5.2 TPM_CC Listing*/
#define TPM2_CC_NV_DefineSpace      0x0000012A
#define TPM2_CC_SelfTest            0x00000143
#define TPM2_CC_Startup             0x00000144
#define TPM2_CC_Shatdown            0x00000145
#define TPM2_CC_StartAuthSession    0x00000176
#define TPM2_CC_GetCapability       0x0000017A
#define TPM2_CC_GetRandom           0x0000017B

#define SUCCESS_CODE                0x00
#define ERROR_CODE                  0x01
static void process_command(CustomTPMState *s){
    // Parsing TPM header (big-endian)
    uint16_t tag = (s->command[0] << 8) | s->command[1];
    uint32_t size = (s->command[2] << 24) | (s->command[3] << 16) | (s->command[4] << 8) | s->command[5];
    uint32_t command_code = (s->command[6] << 24) | (s->command[7] << 16) | (s->command[8] << 8) | s->command[9];
    
    s->response[0] = tag >> 8;
    s->response[1] = tag & 0xFF;
    s->response_size = 10;
    
    switch (command_code){
        case TPM2_CC_SelfTest:
            s->response[6] = SUCCESS_CODE;     
            break;
        default:
            s->response[6] = ERROR_CODE;      
            break;
    }

    // Update response size field (big-endian)
    s->response[2] = (s->response_size >> 24) & 0xFF;
    s->response[3] = (s->response_size >> 16) & 0xFF;
    s->response[4] = (s->response_size >> 8) & 0xFF;
    s->response[5] = s->response_size & 0xFF;

    s->response_pos = 0;
    s->regs[R_TPM_STS] |= R_TPM_STS_DATA_AVAIL_MASK;

    
}

static uint64_t custom_tpm_mmio_read(void *opaque, hwaddr addr, unsigned size){
    CustomTPMState *s = opaque;
    uint32_t val = 0;
    
    switch(addr){
        case A_TPM_ACCESS:
            // Reports TPM accessibility status
            printf("Reading TPM_ACCESS\n");
            return R_TPM_ACCESS_VALID_MASK | R_TPM_ACCESS_ACTIVE_MASK;
        case A_TPM_STS:
            // Reports Status register
            printf("Reading TPM_STS\n");
            if(s->response_size > 0 && s -> response_pos < s->response_size)
                val |= R_TPM_STS_DATA_AVAIL_MASK;
            if(s->command_pos >= s->command_size && !s->processing)
                val |= R_TPM_STS_CMD_READY_MASK;
            val |= R_TPM_STS_VALID_MASK;
            break;
        case A_TPM_DATA_FIFO:
            if(s->response_pos < s->response_size){
                val = s->response[s->response_pos++];
                if(s->response_pos == s->response_size){
                    s->response_pos = s->response_size = 0;
                    s->regs[R_TPM_STS] &= ~R_TPM_STS_DATA_AVAIL_MASK;
                }
            }
            break;
        default:
            qemu_log_mask(LOG_UNIMP, "%s: Unhandled read at 0x%" HWADDR_PRIx "\n", __func__, addr);
    }
    return val;
}



static void custom_tpm_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size){
    CustomTPMState *s = opaque;
    
    switch (addr){
        case A_TPM_STS:
            // To trigger data execution
            if(val & R_TPM_STS_GO_MASK){
                s->processing = true;
                process_command(s);
                s->processing = false;
                //s->regs[R_TPM_STS] &= ~R_TPM_STS_GO_MASK;
            }
            break;
        case A_TPM_DATA_FIFO:
            // Accumulate commands
            if(s->command_pos < sizeof(s->command)) {
                s->command[s->command_pos++] = val;
                if (s->command_pos >= 6){   // Waiting 6 bytes
                    s->command_size = (s->command[2] << 24) | (s->command[3] << 16) | (s->command[4] << 8) | s->command[5];
                    if(s->command_size > sizeof(s->command)){
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
    memset(s->regs, 0, sizeof(s->regs)); 
}

static void custom_tpm_realize(DeviceState *dev, Error **errp){
    CustomTPMState *s = CUSTOM_TPM(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);

    /* Initialize MMIO region */
    memory_region_init_io(&s->mmio, OBJECT(dev), &custom_tpm_mmio_ops, s, "custom-tpm-mmio", 0x100);
    sysbus_init_mmio(sbd, &s->mmio);

    /* Initialize register values */
    // Set interface capabilities (FIFO interface)
    s->regs[R_TPM_INTF_CAPABILITY / sizeof(uint32_t)] = R_TPM_INTF_CAPABILITY_FIFO_IF_MASK;

    // Set device and vendor id
    s->regs[R_TPM_DID_VID / sizeof(uint32_t)] = 0x00000000;

    // Initialize TPM_STS to ready state 
    s->regs[R_TPM_STS / sizeof(uint32_t)] = R_TPM_STS_VALID_MASK | R_TPM_STS_CMD_READY_MASK;
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
    .class_init    = custom_tpm_class_init,
};

static void custom_tpm_register_types(void){
    type_register_static(&custom_tpm_info);        
}

type_init(custom_tpm_register_types);
