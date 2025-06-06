/* This file is autogenerated by tracetool, do not edit. */

#include "qemu/osdep.h"
#include "qemu/module.h"
#include "trace-hw_s390x.h"

uint16_t _TRACE_CSS_ENABLE_FACILITY_DSTATE;
uint16_t _TRACE_CSS_CRW_DSTATE;
uint16_t _TRACE_CSS_CHPID_ADD_DSTATE;
uint16_t _TRACE_CSS_NEW_IMAGE_DSTATE;
uint16_t _TRACE_CSS_ASSIGN_SUBCH_DSTATE;
uint16_t _TRACE_CSS_IO_INTERRUPT_DSTATE;
uint16_t _TRACE_CSS_ADAPTER_INTERRUPT_DSTATE;
uint16_t _TRACE_CSS_DO_SIC_DSTATE;
uint16_t _TRACE_VIRTIO_CCW_INTERPRET_CCW_DSTATE;
uint16_t _TRACE_VIRTIO_CCW_NEW_DEVICE_DSTATE;
uint16_t _TRACE_VIRTIO_CCW_SET_IND_DSTATE;
uint16_t _TRACE_S390_PCI_CLP_CAP_DSTATE;
uint16_t _TRACE_S390_PCI_CLP_CAP_SIZE_DSTATE;
uint16_t _TRACE_S390_PCI_CLP_DEV_INFO_DSTATE;
uint16_t _TRACE_S390_PCI_SCLP_NODEV_DSTATE;
uint16_t _TRACE_S390_PCI_IOMMU_XLATE_DSTATE;
uint16_t _TRACE_S390_PCI_MSI_CTRL_WRITE_DSTATE;
uint16_t _TRACE_S390_PCIHOST_DSTATE;
uint16_t _TRACE_S390_PCI_IRQS_DSTATE;
uint16_t _TRACE_S390_PCI_KVM_AIF_DSTATE;
uint16_t _TRACE_S390_PCI_LIST_ENTRY_DSTATE;
uint16_t _TRACE_S390_PCI_LIST_DSTATE;
uint16_t _TRACE_S390_PCI_UNKNOWN_DSTATE;
uint16_t _TRACE_S390_PCI_BAR_DSTATE;
uint16_t _TRACE_S390_PCI_NODEV_DSTATE;
uint16_t _TRACE_S390_PCI_INVALID_DSTATE;
uint16_t _TRACE_S390_SKEYS_GET_NONZERO_DSTATE;
uint16_t _TRACE_S390_SKEYS_SET_NONZERO_DSTATE;
TraceEvent _TRACE_CSS_ENABLE_FACILITY_EVENT = {
    .id = 0,
    .name = "css_enable_facility",
    .sstate = TRACE_CSS_ENABLE_FACILITY_ENABLED,
    .dstate = &_TRACE_CSS_ENABLE_FACILITY_DSTATE 
};
TraceEvent _TRACE_CSS_CRW_EVENT = {
    .id = 0,
    .name = "css_crw",
    .sstate = TRACE_CSS_CRW_ENABLED,
    .dstate = &_TRACE_CSS_CRW_DSTATE 
};
TraceEvent _TRACE_CSS_CHPID_ADD_EVENT = {
    .id = 0,
    .name = "css_chpid_add",
    .sstate = TRACE_CSS_CHPID_ADD_ENABLED,
    .dstate = &_TRACE_CSS_CHPID_ADD_DSTATE 
};
TraceEvent _TRACE_CSS_NEW_IMAGE_EVENT = {
    .id = 0,
    .name = "css_new_image",
    .sstate = TRACE_CSS_NEW_IMAGE_ENABLED,
    .dstate = &_TRACE_CSS_NEW_IMAGE_DSTATE 
};
TraceEvent _TRACE_CSS_ASSIGN_SUBCH_EVENT = {
    .id = 0,
    .name = "css_assign_subch",
    .sstate = TRACE_CSS_ASSIGN_SUBCH_ENABLED,
    .dstate = &_TRACE_CSS_ASSIGN_SUBCH_DSTATE 
};
TraceEvent _TRACE_CSS_IO_INTERRUPT_EVENT = {
    .id = 0,
    .name = "css_io_interrupt",
    .sstate = TRACE_CSS_IO_INTERRUPT_ENABLED,
    .dstate = &_TRACE_CSS_IO_INTERRUPT_DSTATE 
};
TraceEvent _TRACE_CSS_ADAPTER_INTERRUPT_EVENT = {
    .id = 0,
    .name = "css_adapter_interrupt",
    .sstate = TRACE_CSS_ADAPTER_INTERRUPT_ENABLED,
    .dstate = &_TRACE_CSS_ADAPTER_INTERRUPT_DSTATE 
};
TraceEvent _TRACE_CSS_DO_SIC_EVENT = {
    .id = 0,
    .name = "css_do_sic",
    .sstate = TRACE_CSS_DO_SIC_ENABLED,
    .dstate = &_TRACE_CSS_DO_SIC_DSTATE 
};
TraceEvent _TRACE_VIRTIO_CCW_INTERPRET_CCW_EVENT = {
    .id = 0,
    .name = "virtio_ccw_interpret_ccw",
    .sstate = TRACE_VIRTIO_CCW_INTERPRET_CCW_ENABLED,
    .dstate = &_TRACE_VIRTIO_CCW_INTERPRET_CCW_DSTATE 
};
TraceEvent _TRACE_VIRTIO_CCW_NEW_DEVICE_EVENT = {
    .id = 0,
    .name = "virtio_ccw_new_device",
    .sstate = TRACE_VIRTIO_CCW_NEW_DEVICE_ENABLED,
    .dstate = &_TRACE_VIRTIO_CCW_NEW_DEVICE_DSTATE 
};
TraceEvent _TRACE_VIRTIO_CCW_SET_IND_EVENT = {
    .id = 0,
    .name = "virtio_ccw_set_ind",
    .sstate = TRACE_VIRTIO_CCW_SET_IND_ENABLED,
    .dstate = &_TRACE_VIRTIO_CCW_SET_IND_DSTATE 
};
TraceEvent _TRACE_S390_PCI_CLP_CAP_EVENT = {
    .id = 0,
    .name = "s390_pci_clp_cap",
    .sstate = TRACE_S390_PCI_CLP_CAP_ENABLED,
    .dstate = &_TRACE_S390_PCI_CLP_CAP_DSTATE 
};
TraceEvent _TRACE_S390_PCI_CLP_CAP_SIZE_EVENT = {
    .id = 0,
    .name = "s390_pci_clp_cap_size",
    .sstate = TRACE_S390_PCI_CLP_CAP_SIZE_ENABLED,
    .dstate = &_TRACE_S390_PCI_CLP_CAP_SIZE_DSTATE 
};
TraceEvent _TRACE_S390_PCI_CLP_DEV_INFO_EVENT = {
    .id = 0,
    .name = "s390_pci_clp_dev_info",
    .sstate = TRACE_S390_PCI_CLP_DEV_INFO_ENABLED,
    .dstate = &_TRACE_S390_PCI_CLP_DEV_INFO_DSTATE 
};
TraceEvent _TRACE_S390_PCI_SCLP_NODEV_EVENT = {
    .id = 0,
    .name = "s390_pci_sclp_nodev",
    .sstate = TRACE_S390_PCI_SCLP_NODEV_ENABLED,
    .dstate = &_TRACE_S390_PCI_SCLP_NODEV_DSTATE 
};
TraceEvent _TRACE_S390_PCI_IOMMU_XLATE_EVENT = {
    .id = 0,
    .name = "s390_pci_iommu_xlate",
    .sstate = TRACE_S390_PCI_IOMMU_XLATE_ENABLED,
    .dstate = &_TRACE_S390_PCI_IOMMU_XLATE_DSTATE 
};
TraceEvent _TRACE_S390_PCI_MSI_CTRL_WRITE_EVENT = {
    .id = 0,
    .name = "s390_pci_msi_ctrl_write",
    .sstate = TRACE_S390_PCI_MSI_CTRL_WRITE_ENABLED,
    .dstate = &_TRACE_S390_PCI_MSI_CTRL_WRITE_DSTATE 
};
TraceEvent _TRACE_S390_PCIHOST_EVENT = {
    .id = 0,
    .name = "s390_pcihost",
    .sstate = TRACE_S390_PCIHOST_ENABLED,
    .dstate = &_TRACE_S390_PCIHOST_DSTATE 
};
TraceEvent _TRACE_S390_PCI_IRQS_EVENT = {
    .id = 0,
    .name = "s390_pci_irqs",
    .sstate = TRACE_S390_PCI_IRQS_ENABLED,
    .dstate = &_TRACE_S390_PCI_IRQS_DSTATE 
};
TraceEvent _TRACE_S390_PCI_KVM_AIF_EVENT = {
    .id = 0,
    .name = "s390_pci_kvm_aif",
    .sstate = TRACE_S390_PCI_KVM_AIF_ENABLED,
    .dstate = &_TRACE_S390_PCI_KVM_AIF_DSTATE 
};
TraceEvent _TRACE_S390_PCI_LIST_ENTRY_EVENT = {
    .id = 0,
    .name = "s390_pci_list_entry",
    .sstate = TRACE_S390_PCI_LIST_ENTRY_ENABLED,
    .dstate = &_TRACE_S390_PCI_LIST_ENTRY_DSTATE 
};
TraceEvent _TRACE_S390_PCI_LIST_EVENT = {
    .id = 0,
    .name = "s390_pci_list",
    .sstate = TRACE_S390_PCI_LIST_ENABLED,
    .dstate = &_TRACE_S390_PCI_LIST_DSTATE 
};
TraceEvent _TRACE_S390_PCI_UNKNOWN_EVENT = {
    .id = 0,
    .name = "s390_pci_unknown",
    .sstate = TRACE_S390_PCI_UNKNOWN_ENABLED,
    .dstate = &_TRACE_S390_PCI_UNKNOWN_DSTATE 
};
TraceEvent _TRACE_S390_PCI_BAR_EVENT = {
    .id = 0,
    .name = "s390_pci_bar",
    .sstate = TRACE_S390_PCI_BAR_ENABLED,
    .dstate = &_TRACE_S390_PCI_BAR_DSTATE 
};
TraceEvent _TRACE_S390_PCI_NODEV_EVENT = {
    .id = 0,
    .name = "s390_pci_nodev",
    .sstate = TRACE_S390_PCI_NODEV_ENABLED,
    .dstate = &_TRACE_S390_PCI_NODEV_DSTATE 
};
TraceEvent _TRACE_S390_PCI_INVALID_EVENT = {
    .id = 0,
    .name = "s390_pci_invalid",
    .sstate = TRACE_S390_PCI_INVALID_ENABLED,
    .dstate = &_TRACE_S390_PCI_INVALID_DSTATE 
};
TraceEvent _TRACE_S390_SKEYS_GET_NONZERO_EVENT = {
    .id = 0,
    .name = "s390_skeys_get_nonzero",
    .sstate = TRACE_S390_SKEYS_GET_NONZERO_ENABLED,
    .dstate = &_TRACE_S390_SKEYS_GET_NONZERO_DSTATE 
};
TraceEvent _TRACE_S390_SKEYS_SET_NONZERO_EVENT = {
    .id = 0,
    .name = "s390_skeys_set_nonzero",
    .sstate = TRACE_S390_SKEYS_SET_NONZERO_ENABLED,
    .dstate = &_TRACE_S390_SKEYS_SET_NONZERO_DSTATE 
};
TraceEvent *hw_s390x_trace_events[] = {
    &_TRACE_CSS_ENABLE_FACILITY_EVENT,
    &_TRACE_CSS_CRW_EVENT,
    &_TRACE_CSS_CHPID_ADD_EVENT,
    &_TRACE_CSS_NEW_IMAGE_EVENT,
    &_TRACE_CSS_ASSIGN_SUBCH_EVENT,
    &_TRACE_CSS_IO_INTERRUPT_EVENT,
    &_TRACE_CSS_ADAPTER_INTERRUPT_EVENT,
    &_TRACE_CSS_DO_SIC_EVENT,
    &_TRACE_VIRTIO_CCW_INTERPRET_CCW_EVENT,
    &_TRACE_VIRTIO_CCW_NEW_DEVICE_EVENT,
    &_TRACE_VIRTIO_CCW_SET_IND_EVENT,
    &_TRACE_S390_PCI_CLP_CAP_EVENT,
    &_TRACE_S390_PCI_CLP_CAP_SIZE_EVENT,
    &_TRACE_S390_PCI_CLP_DEV_INFO_EVENT,
    &_TRACE_S390_PCI_SCLP_NODEV_EVENT,
    &_TRACE_S390_PCI_IOMMU_XLATE_EVENT,
    &_TRACE_S390_PCI_MSI_CTRL_WRITE_EVENT,
    &_TRACE_S390_PCIHOST_EVENT,
    &_TRACE_S390_PCI_IRQS_EVENT,
    &_TRACE_S390_PCI_KVM_AIF_EVENT,
    &_TRACE_S390_PCI_LIST_ENTRY_EVENT,
    &_TRACE_S390_PCI_LIST_EVENT,
    &_TRACE_S390_PCI_UNKNOWN_EVENT,
    &_TRACE_S390_PCI_BAR_EVENT,
    &_TRACE_S390_PCI_NODEV_EVENT,
    &_TRACE_S390_PCI_INVALID_EVENT,
    &_TRACE_S390_SKEYS_GET_NONZERO_EVENT,
    &_TRACE_S390_SKEYS_SET_NONZERO_EVENT,
  NULL,
};

static void trace_hw_s390x_register_events(void)
{
    trace_event_register_group(hw_s390x_trace_events);
}
trace_init(trace_hw_s390x_register_events)
