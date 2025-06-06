/* This file is autogenerated by tracetool, do not edit. */

#include "qemu/osdep.h"
#include "qemu/module.h"
#include "trace-hw_riscv.h"

uint16_t _TRACE_RISCV_IOMMU_NEW_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_FLT_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_PRI_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_DMA_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_MSI_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_MRIF_NOTIFICATION_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_CMD_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_NOTIFIER_ADD_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_NOTIFIER_DEL_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_NOTIFY_INT_VECTOR_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_ICVEC_WRITE_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_ATS_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_ATS_INVAL_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_ATS_PRGR_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_SYS_IRQ_SENT_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_SYS_MSI_SENT_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_SYS_RESET_HOLD_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_PCI_RESET_HOLD_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_HPM_READ_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_HPM_INCR_CTR_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_HPM_IOCNTINH_CY_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_HPM_CYCLE_WRITE_DSTATE;
uint16_t _TRACE_RISCV_IOMMU_HPM_EVT_WRITE_DSTATE;
TraceEvent _TRACE_RISCV_IOMMU_NEW_EVENT = {
    .id = 0,
    .name = "riscv_iommu_new",
    .sstate = TRACE_RISCV_IOMMU_NEW_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_NEW_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_FLT_EVENT = {
    .id = 0,
    .name = "riscv_iommu_flt",
    .sstate = TRACE_RISCV_IOMMU_FLT_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_FLT_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_PRI_EVENT = {
    .id = 0,
    .name = "riscv_iommu_pri",
    .sstate = TRACE_RISCV_IOMMU_PRI_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_PRI_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_DMA_EVENT = {
    .id = 0,
    .name = "riscv_iommu_dma",
    .sstate = TRACE_RISCV_IOMMU_DMA_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_DMA_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_MSI_EVENT = {
    .id = 0,
    .name = "riscv_iommu_msi",
    .sstate = TRACE_RISCV_IOMMU_MSI_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_MSI_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_MRIF_NOTIFICATION_EVENT = {
    .id = 0,
    .name = "riscv_iommu_mrif_notification",
    .sstate = TRACE_RISCV_IOMMU_MRIF_NOTIFICATION_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_MRIF_NOTIFICATION_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_CMD_EVENT = {
    .id = 0,
    .name = "riscv_iommu_cmd",
    .sstate = TRACE_RISCV_IOMMU_CMD_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_CMD_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_NOTIFIER_ADD_EVENT = {
    .id = 0,
    .name = "riscv_iommu_notifier_add",
    .sstate = TRACE_RISCV_IOMMU_NOTIFIER_ADD_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_NOTIFIER_ADD_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_NOTIFIER_DEL_EVENT = {
    .id = 0,
    .name = "riscv_iommu_notifier_del",
    .sstate = TRACE_RISCV_IOMMU_NOTIFIER_DEL_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_NOTIFIER_DEL_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_NOTIFY_INT_VECTOR_EVENT = {
    .id = 0,
    .name = "riscv_iommu_notify_int_vector",
    .sstate = TRACE_RISCV_IOMMU_NOTIFY_INT_VECTOR_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_NOTIFY_INT_VECTOR_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_ICVEC_WRITE_EVENT = {
    .id = 0,
    .name = "riscv_iommu_icvec_write",
    .sstate = TRACE_RISCV_IOMMU_ICVEC_WRITE_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_ICVEC_WRITE_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_ATS_EVENT = {
    .id = 0,
    .name = "riscv_iommu_ats",
    .sstate = TRACE_RISCV_IOMMU_ATS_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_ATS_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_ATS_INVAL_EVENT = {
    .id = 0,
    .name = "riscv_iommu_ats_inval",
    .sstate = TRACE_RISCV_IOMMU_ATS_INVAL_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_ATS_INVAL_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_ATS_PRGR_EVENT = {
    .id = 0,
    .name = "riscv_iommu_ats_prgr",
    .sstate = TRACE_RISCV_IOMMU_ATS_PRGR_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_ATS_PRGR_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_SYS_IRQ_SENT_EVENT = {
    .id = 0,
    .name = "riscv_iommu_sys_irq_sent",
    .sstate = TRACE_RISCV_IOMMU_SYS_IRQ_SENT_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_SYS_IRQ_SENT_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_SYS_MSI_SENT_EVENT = {
    .id = 0,
    .name = "riscv_iommu_sys_msi_sent",
    .sstate = TRACE_RISCV_IOMMU_SYS_MSI_SENT_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_SYS_MSI_SENT_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_SYS_RESET_HOLD_EVENT = {
    .id = 0,
    .name = "riscv_iommu_sys_reset_hold",
    .sstate = TRACE_RISCV_IOMMU_SYS_RESET_HOLD_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_SYS_RESET_HOLD_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_PCI_RESET_HOLD_EVENT = {
    .id = 0,
    .name = "riscv_iommu_pci_reset_hold",
    .sstate = TRACE_RISCV_IOMMU_PCI_RESET_HOLD_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_PCI_RESET_HOLD_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_HPM_READ_EVENT = {
    .id = 0,
    .name = "riscv_iommu_hpm_read",
    .sstate = TRACE_RISCV_IOMMU_HPM_READ_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_HPM_READ_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_HPM_INCR_CTR_EVENT = {
    .id = 0,
    .name = "riscv_iommu_hpm_incr_ctr",
    .sstate = TRACE_RISCV_IOMMU_HPM_INCR_CTR_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_HPM_INCR_CTR_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_HPM_IOCNTINH_CY_EVENT = {
    .id = 0,
    .name = "riscv_iommu_hpm_iocntinh_cy",
    .sstate = TRACE_RISCV_IOMMU_HPM_IOCNTINH_CY_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_HPM_IOCNTINH_CY_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_HPM_CYCLE_WRITE_EVENT = {
    .id = 0,
    .name = "riscv_iommu_hpm_cycle_write",
    .sstate = TRACE_RISCV_IOMMU_HPM_CYCLE_WRITE_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_HPM_CYCLE_WRITE_DSTATE 
};
TraceEvent _TRACE_RISCV_IOMMU_HPM_EVT_WRITE_EVENT = {
    .id = 0,
    .name = "riscv_iommu_hpm_evt_write",
    .sstate = TRACE_RISCV_IOMMU_HPM_EVT_WRITE_ENABLED,
    .dstate = &_TRACE_RISCV_IOMMU_HPM_EVT_WRITE_DSTATE 
};
TraceEvent *hw_riscv_trace_events[] = {
    &_TRACE_RISCV_IOMMU_NEW_EVENT,
    &_TRACE_RISCV_IOMMU_FLT_EVENT,
    &_TRACE_RISCV_IOMMU_PRI_EVENT,
    &_TRACE_RISCV_IOMMU_DMA_EVENT,
    &_TRACE_RISCV_IOMMU_MSI_EVENT,
    &_TRACE_RISCV_IOMMU_MRIF_NOTIFICATION_EVENT,
    &_TRACE_RISCV_IOMMU_CMD_EVENT,
    &_TRACE_RISCV_IOMMU_NOTIFIER_ADD_EVENT,
    &_TRACE_RISCV_IOMMU_NOTIFIER_DEL_EVENT,
    &_TRACE_RISCV_IOMMU_NOTIFY_INT_VECTOR_EVENT,
    &_TRACE_RISCV_IOMMU_ICVEC_WRITE_EVENT,
    &_TRACE_RISCV_IOMMU_ATS_EVENT,
    &_TRACE_RISCV_IOMMU_ATS_INVAL_EVENT,
    &_TRACE_RISCV_IOMMU_ATS_PRGR_EVENT,
    &_TRACE_RISCV_IOMMU_SYS_IRQ_SENT_EVENT,
    &_TRACE_RISCV_IOMMU_SYS_MSI_SENT_EVENT,
    &_TRACE_RISCV_IOMMU_SYS_RESET_HOLD_EVENT,
    &_TRACE_RISCV_IOMMU_PCI_RESET_HOLD_EVENT,
    &_TRACE_RISCV_IOMMU_HPM_READ_EVENT,
    &_TRACE_RISCV_IOMMU_HPM_INCR_CTR_EVENT,
    &_TRACE_RISCV_IOMMU_HPM_IOCNTINH_CY_EVENT,
    &_TRACE_RISCV_IOMMU_HPM_CYCLE_WRITE_EVENT,
    &_TRACE_RISCV_IOMMU_HPM_EVT_WRITE_EVENT,
  NULL,
};

static void trace_hw_riscv_register_events(void)
{
    trace_event_register_group(hw_riscv_trace_events);
}
trace_init(trace_hw_riscv_register_events)
