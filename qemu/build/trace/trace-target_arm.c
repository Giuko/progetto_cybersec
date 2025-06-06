/* This file is autogenerated by tracetool, do not edit. */

#include "qemu/osdep.h"
#include "qemu/module.h"
#include "trace-target_arm.h"

uint16_t _TRACE_ARM_GT_RECALC_DSTATE;
uint16_t _TRACE_ARM_GT_RECALC_DISABLED_DSTATE;
uint16_t _TRACE_ARM_GT_CVAL_WRITE_DSTATE;
uint16_t _TRACE_ARM_GT_TVAL_WRITE_DSTATE;
uint16_t _TRACE_ARM_GT_CTL_WRITE_DSTATE;
uint16_t _TRACE_ARM_GT_IMASK_TOGGLE_DSTATE;
uint16_t _TRACE_ARM_GT_CNTVOFF_WRITE_DSTATE;
uint16_t _TRACE_ARM_GT_CNTPOFF_WRITE_DSTATE;
uint16_t _TRACE_ARM_GT_UPDATE_IRQ_DSTATE;
uint16_t _TRACE_KVM_ARM_FIXUP_MSI_ROUTE_DSTATE;
TraceEvent _TRACE_ARM_GT_RECALC_EVENT = {
    .id = 0,
    .name = "arm_gt_recalc",
    .sstate = TRACE_ARM_GT_RECALC_ENABLED,
    .dstate = &_TRACE_ARM_GT_RECALC_DSTATE 
};
TraceEvent _TRACE_ARM_GT_RECALC_DISABLED_EVENT = {
    .id = 0,
    .name = "arm_gt_recalc_disabled",
    .sstate = TRACE_ARM_GT_RECALC_DISABLED_ENABLED,
    .dstate = &_TRACE_ARM_GT_RECALC_DISABLED_DSTATE 
};
TraceEvent _TRACE_ARM_GT_CVAL_WRITE_EVENT = {
    .id = 0,
    .name = "arm_gt_cval_write",
    .sstate = TRACE_ARM_GT_CVAL_WRITE_ENABLED,
    .dstate = &_TRACE_ARM_GT_CVAL_WRITE_DSTATE 
};
TraceEvent _TRACE_ARM_GT_TVAL_WRITE_EVENT = {
    .id = 0,
    .name = "arm_gt_tval_write",
    .sstate = TRACE_ARM_GT_TVAL_WRITE_ENABLED,
    .dstate = &_TRACE_ARM_GT_TVAL_WRITE_DSTATE 
};
TraceEvent _TRACE_ARM_GT_CTL_WRITE_EVENT = {
    .id = 0,
    .name = "arm_gt_ctl_write",
    .sstate = TRACE_ARM_GT_CTL_WRITE_ENABLED,
    .dstate = &_TRACE_ARM_GT_CTL_WRITE_DSTATE 
};
TraceEvent _TRACE_ARM_GT_IMASK_TOGGLE_EVENT = {
    .id = 0,
    .name = "arm_gt_imask_toggle",
    .sstate = TRACE_ARM_GT_IMASK_TOGGLE_ENABLED,
    .dstate = &_TRACE_ARM_GT_IMASK_TOGGLE_DSTATE 
};
TraceEvent _TRACE_ARM_GT_CNTVOFF_WRITE_EVENT = {
    .id = 0,
    .name = "arm_gt_cntvoff_write",
    .sstate = TRACE_ARM_GT_CNTVOFF_WRITE_ENABLED,
    .dstate = &_TRACE_ARM_GT_CNTVOFF_WRITE_DSTATE 
};
TraceEvent _TRACE_ARM_GT_CNTPOFF_WRITE_EVENT = {
    .id = 0,
    .name = "arm_gt_cntpoff_write",
    .sstate = TRACE_ARM_GT_CNTPOFF_WRITE_ENABLED,
    .dstate = &_TRACE_ARM_GT_CNTPOFF_WRITE_DSTATE 
};
TraceEvent _TRACE_ARM_GT_UPDATE_IRQ_EVENT = {
    .id = 0,
    .name = "arm_gt_update_irq",
    .sstate = TRACE_ARM_GT_UPDATE_IRQ_ENABLED,
    .dstate = &_TRACE_ARM_GT_UPDATE_IRQ_DSTATE 
};
TraceEvent _TRACE_KVM_ARM_FIXUP_MSI_ROUTE_EVENT = {
    .id = 0,
    .name = "kvm_arm_fixup_msi_route",
    .sstate = TRACE_KVM_ARM_FIXUP_MSI_ROUTE_ENABLED,
    .dstate = &_TRACE_KVM_ARM_FIXUP_MSI_ROUTE_DSTATE 
};
TraceEvent *target_arm_trace_events[] = {
    &_TRACE_ARM_GT_RECALC_EVENT,
    &_TRACE_ARM_GT_RECALC_DISABLED_EVENT,
    &_TRACE_ARM_GT_CVAL_WRITE_EVENT,
    &_TRACE_ARM_GT_TVAL_WRITE_EVENT,
    &_TRACE_ARM_GT_CTL_WRITE_EVENT,
    &_TRACE_ARM_GT_IMASK_TOGGLE_EVENT,
    &_TRACE_ARM_GT_CNTVOFF_WRITE_EVENT,
    &_TRACE_ARM_GT_CNTPOFF_WRITE_EVENT,
    &_TRACE_ARM_GT_UPDATE_IRQ_EVENT,
    &_TRACE_KVM_ARM_FIXUP_MSI_ROUTE_EVENT,
  NULL,
};

static void trace_target_arm_register_events(void)
{
    trace_event_register_group(target_arm_trace_events);
}
trace_init(trace_target_arm_register_events)
