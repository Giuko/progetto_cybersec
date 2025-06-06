/* This file is autogenerated by tracetool, do not edit. */

#include "qemu/osdep.h"
#include "qemu/module.h"
#include "trace-system.h"

uint16_t _TRACE_BALLOON_EVENT_DSTATE;
uint16_t _TRACE_DMA_BLK_IO_DSTATE;
uint16_t _TRACE_DMA_AIO_CANCEL_DSTATE;
uint16_t _TRACE_DMA_COMPLETE_DSTATE;
uint16_t _TRACE_DMA_BLK_CB_DSTATE;
uint16_t _TRACE_DMA_MAP_WAIT_DSTATE;
uint16_t _TRACE_CPU_IN_DSTATE;
uint16_t _TRACE_CPU_OUT_DSTATE;
uint16_t _TRACE_MEMORY_REGION_OPS_READ_DSTATE;
uint16_t _TRACE_MEMORY_REGION_OPS_WRITE_DSTATE;
uint16_t _TRACE_MEMORY_REGION_SUBPAGE_READ_DSTATE;
uint16_t _TRACE_MEMORY_REGION_SUBPAGE_WRITE_DSTATE;
uint16_t _TRACE_MEMORY_REGION_RAM_DEVICE_READ_DSTATE;
uint16_t _TRACE_MEMORY_REGION_RAM_DEVICE_WRITE_DSTATE;
uint16_t _TRACE_MEMORY_REGION_SYNC_DIRTY_DSTATE;
uint16_t _TRACE_FLATVIEW_NEW_DSTATE;
uint16_t _TRACE_FLATVIEW_DESTROY_DSTATE;
uint16_t _TRACE_FLATVIEW_DESTROY_RCU_DSTATE;
uint16_t _TRACE_GLOBAL_DIRTY_CHANGED_DSTATE;
uint16_t _TRACE_ADDRESS_SPACE_MAP_DSTATE;
uint16_t _TRACE_FIND_RAM_OFFSET_DSTATE;
uint16_t _TRACE_FIND_RAM_OFFSET_LOOP_DSTATE;
uint16_t _TRACE_RAM_BLOCK_DISCARD_RANGE_DSTATE;
uint16_t _TRACE_QEMU_RAM_ALLOC_SHARED_DSTATE;
uint16_t _TRACE_VM_STOP_FLUSH_ALL_DSTATE;
uint16_t _TRACE_VM_STATE_NOTIFY_DSTATE;
uint16_t _TRACE_LOAD_FILE_DSTATE;
uint16_t _TRACE_RUNSTATE_SET_DSTATE;
uint16_t _TRACE_SYSTEM_WAKEUP_REQUEST_DSTATE;
uint16_t _TRACE_QEMU_SYSTEM_SHUTDOWN_REQUEST_DSTATE;
uint16_t _TRACE_QEMU_SYSTEM_POWERDOWN_REQUEST_DSTATE;
uint16_t _TRACE_DIRTYLIMIT_STATE_INITIALIZE_DSTATE;
uint16_t _TRACE_DIRTYLIMIT_STATE_FINALIZE_DSTATE;
uint16_t _TRACE_DIRTYLIMIT_THROTTLE_PCT_DSTATE;
uint16_t _TRACE_DIRTYLIMIT_SET_VCPU_DSTATE;
uint16_t _TRACE_DIRTYLIMIT_VCPU_EXECUTE_DSTATE;
TraceEvent _TRACE_BALLOON_EVENT_EVENT = {
    .id = 0,
    .name = "balloon_event",
    .sstate = TRACE_BALLOON_EVENT_ENABLED,
    .dstate = &_TRACE_BALLOON_EVENT_DSTATE 
};
TraceEvent _TRACE_DMA_BLK_IO_EVENT = {
    .id = 0,
    .name = "dma_blk_io",
    .sstate = TRACE_DMA_BLK_IO_ENABLED,
    .dstate = &_TRACE_DMA_BLK_IO_DSTATE 
};
TraceEvent _TRACE_DMA_AIO_CANCEL_EVENT = {
    .id = 0,
    .name = "dma_aio_cancel",
    .sstate = TRACE_DMA_AIO_CANCEL_ENABLED,
    .dstate = &_TRACE_DMA_AIO_CANCEL_DSTATE 
};
TraceEvent _TRACE_DMA_COMPLETE_EVENT = {
    .id = 0,
    .name = "dma_complete",
    .sstate = TRACE_DMA_COMPLETE_ENABLED,
    .dstate = &_TRACE_DMA_COMPLETE_DSTATE 
};
TraceEvent _TRACE_DMA_BLK_CB_EVENT = {
    .id = 0,
    .name = "dma_blk_cb",
    .sstate = TRACE_DMA_BLK_CB_ENABLED,
    .dstate = &_TRACE_DMA_BLK_CB_DSTATE 
};
TraceEvent _TRACE_DMA_MAP_WAIT_EVENT = {
    .id = 0,
    .name = "dma_map_wait",
    .sstate = TRACE_DMA_MAP_WAIT_ENABLED,
    .dstate = &_TRACE_DMA_MAP_WAIT_DSTATE 
};
TraceEvent _TRACE_CPU_IN_EVENT = {
    .id = 0,
    .name = "cpu_in",
    .sstate = TRACE_CPU_IN_ENABLED,
    .dstate = &_TRACE_CPU_IN_DSTATE 
};
TraceEvent _TRACE_CPU_OUT_EVENT = {
    .id = 0,
    .name = "cpu_out",
    .sstate = TRACE_CPU_OUT_ENABLED,
    .dstate = &_TRACE_CPU_OUT_DSTATE 
};
TraceEvent _TRACE_MEMORY_REGION_OPS_READ_EVENT = {
    .id = 0,
    .name = "memory_region_ops_read",
    .sstate = TRACE_MEMORY_REGION_OPS_READ_ENABLED,
    .dstate = &_TRACE_MEMORY_REGION_OPS_READ_DSTATE 
};
TraceEvent _TRACE_MEMORY_REGION_OPS_WRITE_EVENT = {
    .id = 0,
    .name = "memory_region_ops_write",
    .sstate = TRACE_MEMORY_REGION_OPS_WRITE_ENABLED,
    .dstate = &_TRACE_MEMORY_REGION_OPS_WRITE_DSTATE 
};
TraceEvent _TRACE_MEMORY_REGION_SUBPAGE_READ_EVENT = {
    .id = 0,
    .name = "memory_region_subpage_read",
    .sstate = TRACE_MEMORY_REGION_SUBPAGE_READ_ENABLED,
    .dstate = &_TRACE_MEMORY_REGION_SUBPAGE_READ_DSTATE 
};
TraceEvent _TRACE_MEMORY_REGION_SUBPAGE_WRITE_EVENT = {
    .id = 0,
    .name = "memory_region_subpage_write",
    .sstate = TRACE_MEMORY_REGION_SUBPAGE_WRITE_ENABLED,
    .dstate = &_TRACE_MEMORY_REGION_SUBPAGE_WRITE_DSTATE 
};
TraceEvent _TRACE_MEMORY_REGION_RAM_DEVICE_READ_EVENT = {
    .id = 0,
    .name = "memory_region_ram_device_read",
    .sstate = TRACE_MEMORY_REGION_RAM_DEVICE_READ_ENABLED,
    .dstate = &_TRACE_MEMORY_REGION_RAM_DEVICE_READ_DSTATE 
};
TraceEvent _TRACE_MEMORY_REGION_RAM_DEVICE_WRITE_EVENT = {
    .id = 0,
    .name = "memory_region_ram_device_write",
    .sstate = TRACE_MEMORY_REGION_RAM_DEVICE_WRITE_ENABLED,
    .dstate = &_TRACE_MEMORY_REGION_RAM_DEVICE_WRITE_DSTATE 
};
TraceEvent _TRACE_MEMORY_REGION_SYNC_DIRTY_EVENT = {
    .id = 0,
    .name = "memory_region_sync_dirty",
    .sstate = TRACE_MEMORY_REGION_SYNC_DIRTY_ENABLED,
    .dstate = &_TRACE_MEMORY_REGION_SYNC_DIRTY_DSTATE 
};
TraceEvent _TRACE_FLATVIEW_NEW_EVENT = {
    .id = 0,
    .name = "flatview_new",
    .sstate = TRACE_FLATVIEW_NEW_ENABLED,
    .dstate = &_TRACE_FLATVIEW_NEW_DSTATE 
};
TraceEvent _TRACE_FLATVIEW_DESTROY_EVENT = {
    .id = 0,
    .name = "flatview_destroy",
    .sstate = TRACE_FLATVIEW_DESTROY_ENABLED,
    .dstate = &_TRACE_FLATVIEW_DESTROY_DSTATE 
};
TraceEvent _TRACE_FLATVIEW_DESTROY_RCU_EVENT = {
    .id = 0,
    .name = "flatview_destroy_rcu",
    .sstate = TRACE_FLATVIEW_DESTROY_RCU_ENABLED,
    .dstate = &_TRACE_FLATVIEW_DESTROY_RCU_DSTATE 
};
TraceEvent _TRACE_GLOBAL_DIRTY_CHANGED_EVENT = {
    .id = 0,
    .name = "global_dirty_changed",
    .sstate = TRACE_GLOBAL_DIRTY_CHANGED_ENABLED,
    .dstate = &_TRACE_GLOBAL_DIRTY_CHANGED_DSTATE 
};
TraceEvent _TRACE_ADDRESS_SPACE_MAP_EVENT = {
    .id = 0,
    .name = "address_space_map",
    .sstate = TRACE_ADDRESS_SPACE_MAP_ENABLED,
    .dstate = &_TRACE_ADDRESS_SPACE_MAP_DSTATE 
};
TraceEvent _TRACE_FIND_RAM_OFFSET_EVENT = {
    .id = 0,
    .name = "find_ram_offset",
    .sstate = TRACE_FIND_RAM_OFFSET_ENABLED,
    .dstate = &_TRACE_FIND_RAM_OFFSET_DSTATE 
};
TraceEvent _TRACE_FIND_RAM_OFFSET_LOOP_EVENT = {
    .id = 0,
    .name = "find_ram_offset_loop",
    .sstate = TRACE_FIND_RAM_OFFSET_LOOP_ENABLED,
    .dstate = &_TRACE_FIND_RAM_OFFSET_LOOP_DSTATE 
};
TraceEvent _TRACE_RAM_BLOCK_DISCARD_RANGE_EVENT = {
    .id = 0,
    .name = "ram_block_discard_range",
    .sstate = TRACE_RAM_BLOCK_DISCARD_RANGE_ENABLED,
    .dstate = &_TRACE_RAM_BLOCK_DISCARD_RANGE_DSTATE 
};
TraceEvent _TRACE_QEMU_RAM_ALLOC_SHARED_EVENT = {
    .id = 0,
    .name = "qemu_ram_alloc_shared",
    .sstate = TRACE_QEMU_RAM_ALLOC_SHARED_ENABLED,
    .dstate = &_TRACE_QEMU_RAM_ALLOC_SHARED_DSTATE 
};
TraceEvent _TRACE_VM_STOP_FLUSH_ALL_EVENT = {
    .id = 0,
    .name = "vm_stop_flush_all",
    .sstate = TRACE_VM_STOP_FLUSH_ALL_ENABLED,
    .dstate = &_TRACE_VM_STOP_FLUSH_ALL_DSTATE 
};
TraceEvent _TRACE_VM_STATE_NOTIFY_EVENT = {
    .id = 0,
    .name = "vm_state_notify",
    .sstate = TRACE_VM_STATE_NOTIFY_ENABLED,
    .dstate = &_TRACE_VM_STATE_NOTIFY_DSTATE 
};
TraceEvent _TRACE_LOAD_FILE_EVENT = {
    .id = 0,
    .name = "load_file",
    .sstate = TRACE_LOAD_FILE_ENABLED,
    .dstate = &_TRACE_LOAD_FILE_DSTATE 
};
TraceEvent _TRACE_RUNSTATE_SET_EVENT = {
    .id = 0,
    .name = "runstate_set",
    .sstate = TRACE_RUNSTATE_SET_ENABLED,
    .dstate = &_TRACE_RUNSTATE_SET_DSTATE 
};
TraceEvent _TRACE_SYSTEM_WAKEUP_REQUEST_EVENT = {
    .id = 0,
    .name = "system_wakeup_request",
    .sstate = TRACE_SYSTEM_WAKEUP_REQUEST_ENABLED,
    .dstate = &_TRACE_SYSTEM_WAKEUP_REQUEST_DSTATE 
};
TraceEvent _TRACE_QEMU_SYSTEM_SHUTDOWN_REQUEST_EVENT = {
    .id = 0,
    .name = "qemu_system_shutdown_request",
    .sstate = TRACE_QEMU_SYSTEM_SHUTDOWN_REQUEST_ENABLED,
    .dstate = &_TRACE_QEMU_SYSTEM_SHUTDOWN_REQUEST_DSTATE 
};
TraceEvent _TRACE_QEMU_SYSTEM_POWERDOWN_REQUEST_EVENT = {
    .id = 0,
    .name = "qemu_system_powerdown_request",
    .sstate = TRACE_QEMU_SYSTEM_POWERDOWN_REQUEST_ENABLED,
    .dstate = &_TRACE_QEMU_SYSTEM_POWERDOWN_REQUEST_DSTATE 
};
TraceEvent _TRACE_DIRTYLIMIT_STATE_INITIALIZE_EVENT = {
    .id = 0,
    .name = "dirtylimit_state_initialize",
    .sstate = TRACE_DIRTYLIMIT_STATE_INITIALIZE_ENABLED,
    .dstate = &_TRACE_DIRTYLIMIT_STATE_INITIALIZE_DSTATE 
};
TraceEvent _TRACE_DIRTYLIMIT_STATE_FINALIZE_EVENT = {
    .id = 0,
    .name = "dirtylimit_state_finalize",
    .sstate = TRACE_DIRTYLIMIT_STATE_FINALIZE_ENABLED,
    .dstate = &_TRACE_DIRTYLIMIT_STATE_FINALIZE_DSTATE 
};
TraceEvent _TRACE_DIRTYLIMIT_THROTTLE_PCT_EVENT = {
    .id = 0,
    .name = "dirtylimit_throttle_pct",
    .sstate = TRACE_DIRTYLIMIT_THROTTLE_PCT_ENABLED,
    .dstate = &_TRACE_DIRTYLIMIT_THROTTLE_PCT_DSTATE 
};
TraceEvent _TRACE_DIRTYLIMIT_SET_VCPU_EVENT = {
    .id = 0,
    .name = "dirtylimit_set_vcpu",
    .sstate = TRACE_DIRTYLIMIT_SET_VCPU_ENABLED,
    .dstate = &_TRACE_DIRTYLIMIT_SET_VCPU_DSTATE 
};
TraceEvent _TRACE_DIRTYLIMIT_VCPU_EXECUTE_EVENT = {
    .id = 0,
    .name = "dirtylimit_vcpu_execute",
    .sstate = TRACE_DIRTYLIMIT_VCPU_EXECUTE_ENABLED,
    .dstate = &_TRACE_DIRTYLIMIT_VCPU_EXECUTE_DSTATE 
};
TraceEvent *system_trace_events[] = {
    &_TRACE_BALLOON_EVENT_EVENT,
    &_TRACE_DMA_BLK_IO_EVENT,
    &_TRACE_DMA_AIO_CANCEL_EVENT,
    &_TRACE_DMA_COMPLETE_EVENT,
    &_TRACE_DMA_BLK_CB_EVENT,
    &_TRACE_DMA_MAP_WAIT_EVENT,
    &_TRACE_CPU_IN_EVENT,
    &_TRACE_CPU_OUT_EVENT,
    &_TRACE_MEMORY_REGION_OPS_READ_EVENT,
    &_TRACE_MEMORY_REGION_OPS_WRITE_EVENT,
    &_TRACE_MEMORY_REGION_SUBPAGE_READ_EVENT,
    &_TRACE_MEMORY_REGION_SUBPAGE_WRITE_EVENT,
    &_TRACE_MEMORY_REGION_RAM_DEVICE_READ_EVENT,
    &_TRACE_MEMORY_REGION_RAM_DEVICE_WRITE_EVENT,
    &_TRACE_MEMORY_REGION_SYNC_DIRTY_EVENT,
    &_TRACE_FLATVIEW_NEW_EVENT,
    &_TRACE_FLATVIEW_DESTROY_EVENT,
    &_TRACE_FLATVIEW_DESTROY_RCU_EVENT,
    &_TRACE_GLOBAL_DIRTY_CHANGED_EVENT,
    &_TRACE_ADDRESS_SPACE_MAP_EVENT,
    &_TRACE_FIND_RAM_OFFSET_EVENT,
    &_TRACE_FIND_RAM_OFFSET_LOOP_EVENT,
    &_TRACE_RAM_BLOCK_DISCARD_RANGE_EVENT,
    &_TRACE_QEMU_RAM_ALLOC_SHARED_EVENT,
    &_TRACE_VM_STOP_FLUSH_ALL_EVENT,
    &_TRACE_VM_STATE_NOTIFY_EVENT,
    &_TRACE_LOAD_FILE_EVENT,
    &_TRACE_RUNSTATE_SET_EVENT,
    &_TRACE_SYSTEM_WAKEUP_REQUEST_EVENT,
    &_TRACE_QEMU_SYSTEM_SHUTDOWN_REQUEST_EVENT,
    &_TRACE_QEMU_SYSTEM_POWERDOWN_REQUEST_EVENT,
    &_TRACE_DIRTYLIMIT_STATE_INITIALIZE_EVENT,
    &_TRACE_DIRTYLIMIT_STATE_FINALIZE_EVENT,
    &_TRACE_DIRTYLIMIT_THROTTLE_PCT_EVENT,
    &_TRACE_DIRTYLIMIT_SET_VCPU_EVENT,
    &_TRACE_DIRTYLIMIT_VCPU_EXECUTE_EVENT,
  NULL,
};

static void trace_system_register_events(void)
{
    trace_event_register_group(system_trace_events);
}
trace_init(trace_system_register_events)
