#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "hw/registerfields.h"
#include "hw/qdev-properties.h"
#include "qapi/error.h"
#include "qemu/log.h"
#include <string.h>
#include <stdio.h>

#define TYPE_CUSTOM_TPM "custom-tpm"
OBJECT_DECLARE_SIMPLE_TYPE(CustomTPMState,CUSTOM_TPM)

#define TPM_ACCESS_VALID  (1 << 5)
#define TPM_ACCESS_ACTIVE (1 << 1)

struct CustomTPMState {
    SysBusDevice parent_obj;

    MemoryRegion mmio;
    uint8_t regs[0x100]; // spazio di registri virtuali

    uint8_t fifo[256];
    uint32_t fifo_pos;

    uint8_t response[256];
    uint32_t response_size;
    uint32_t response_pos;
};


static uint64_t custom_tpm_mmio_read(void *opaque, hwaddr addr, unsigned size){
    
    switch(addr){
        case 0x00:
            // handle TPM_ACCESS
            printf("Reading TPM Access register");
            return 3;
            break;
        default:
            return -1;
    }
}



static void custom_tpm_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size){
    CustomTPMState *s = opaque;
    if (addr < sizeof(s->regs)) {
        s->regs[addr] = val;
        printf("Writing at addres: %lx, value: %ld", addr, val);
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

    memory_region_init_io(&s->mmio, OBJECT(dev), &custom_tpm_mmio_ops, s, "custom-tpm-mmio", 0x100);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->mmio);
}

static void custom_tpm_class_init(ObjectClass *klass, void *data){
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = custom_tpm_realize;
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
