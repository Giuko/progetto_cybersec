/* This file is autogenerated by tracetool, do not edit. */

#ifndef TRACE_HW_VMAPPLE_GENERATED_TRACERS_H
#define TRACE_HW_VMAPPLE_GENERATED_TRACERS_H

#include "trace/control.h"

extern TraceEvent _TRACE_AES_READ_EVENT;
extern TraceEvent _TRACE_AES_CMD_KEY_SELECT_BUILTIN_EVENT;
extern TraceEvent _TRACE_AES_CMD_KEY_SELECT_NEW_EVENT;
extern TraceEvent _TRACE_AES_CMD_IV_EVENT;
extern TraceEvent _TRACE_AES_CMD_DATA_EVENT;
extern TraceEvent _TRACE_AES_CMD_STORE_IV_EVENT;
extern TraceEvent _TRACE_AES_CMD_FLAG_EVENT;
extern TraceEvent _TRACE_AES_FIFO_PROCESS_EVENT;
extern TraceEvent _TRACE_AES_WRITE_EVENT;
extern TraceEvent _TRACE_AES_2_READ_EVENT;
extern TraceEvent _TRACE_AES_2_WRITE_EVENT;
extern TraceEvent _TRACE_AES_DUMP_DATA_EVENT;
extern TraceEvent _TRACE_BDIF_READ_EVENT;
extern TraceEvent _TRACE_BDIF_WRITE_EVENT;
extern TraceEvent _TRACE_BDIF_VBLK_READ_EVENT;
extern uint16_t _TRACE_AES_READ_DSTATE;
extern uint16_t _TRACE_AES_CMD_KEY_SELECT_BUILTIN_DSTATE;
extern uint16_t _TRACE_AES_CMD_KEY_SELECT_NEW_DSTATE;
extern uint16_t _TRACE_AES_CMD_IV_DSTATE;
extern uint16_t _TRACE_AES_CMD_DATA_DSTATE;
extern uint16_t _TRACE_AES_CMD_STORE_IV_DSTATE;
extern uint16_t _TRACE_AES_CMD_FLAG_DSTATE;
extern uint16_t _TRACE_AES_FIFO_PROCESS_DSTATE;
extern uint16_t _TRACE_AES_WRITE_DSTATE;
extern uint16_t _TRACE_AES_2_READ_DSTATE;
extern uint16_t _TRACE_AES_2_WRITE_DSTATE;
extern uint16_t _TRACE_AES_DUMP_DATA_DSTATE;
extern uint16_t _TRACE_BDIF_READ_DSTATE;
extern uint16_t _TRACE_BDIF_WRITE_DSTATE;
extern uint16_t _TRACE_BDIF_VBLK_READ_DSTATE;
#define TRACE_AES_READ_ENABLED 1
#define TRACE_AES_CMD_KEY_SELECT_BUILTIN_ENABLED 1
#define TRACE_AES_CMD_KEY_SELECT_NEW_ENABLED 1
#define TRACE_AES_CMD_IV_ENABLED 1
#define TRACE_AES_CMD_DATA_ENABLED 1
#define TRACE_AES_CMD_STORE_IV_ENABLED 1
#define TRACE_AES_CMD_FLAG_ENABLED 1
#define TRACE_AES_FIFO_PROCESS_ENABLED 1
#define TRACE_AES_WRITE_ENABLED 1
#define TRACE_AES_2_READ_ENABLED 1
#define TRACE_AES_2_WRITE_ENABLED 1
#define TRACE_AES_DUMP_DATA_ENABLED 1
#define TRACE_BDIF_READ_ENABLED 1
#define TRACE_BDIF_WRITE_ENABLED 1
#define TRACE_BDIF_VBLK_READ_ENABLED 1
#include "qemu/log-for-trace.h"
#include "qemu/error-report.h"


#define TRACE_AES_READ_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_AES_READ) || \
    false)

static inline void _nocheck__trace_aes_read(uint64_t offset, uint64_t res)
{
    if (trace_event_get_state(TRACE_AES_READ) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 5 "../hw/vmapple/trace-events"
            qemu_log("%d@%zu.%06zu:aes_read " "offset=0x%"PRIx64" res=0x%"PRIx64 "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , offset, res);
#line 73 "trace/trace-hw_vmapple.h"
        } else {
#line 5 "../hw/vmapple/trace-events"
            qemu_log("aes_read " "offset=0x%"PRIx64" res=0x%"PRIx64 "\n", offset, res);
#line 77 "trace/trace-hw_vmapple.h"
        }
    }
}

static inline void trace_aes_read(uint64_t offset, uint64_t res)
{
    if (true) {
        _nocheck__trace_aes_read(offset, res);
    }
}

#define TRACE_AES_CMD_KEY_SELECT_BUILTIN_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_AES_CMD_KEY_SELECT_BUILTIN) || \
    false)

static inline void _nocheck__trace_aes_cmd_key_select_builtin(uint32_t ctx, uint32_t key_id, const char * direction, const char * cipher)
{
    if (trace_event_get_state(TRACE_AES_CMD_KEY_SELECT_BUILTIN) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 6 "../hw/vmapple/trace-events"
            qemu_log("%d@%zu.%06zu:aes_cmd_key_select_builtin " "[%d] Selecting builtin key %d to %scrypt with %s" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , ctx, key_id, direction, cipher);
#line 104 "trace/trace-hw_vmapple.h"
        } else {
#line 6 "../hw/vmapple/trace-events"
            qemu_log("aes_cmd_key_select_builtin " "[%d] Selecting builtin key %d to %scrypt with %s" "\n", ctx, key_id, direction, cipher);
#line 108 "trace/trace-hw_vmapple.h"
        }
    }
}

static inline void trace_aes_cmd_key_select_builtin(uint32_t ctx, uint32_t key_id, const char * direction, const char * cipher)
{
    if (true) {
        _nocheck__trace_aes_cmd_key_select_builtin(ctx, key_id, direction, cipher);
    }
}

#define TRACE_AES_CMD_KEY_SELECT_NEW_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_AES_CMD_KEY_SELECT_NEW) || \
    false)

static inline void _nocheck__trace_aes_cmd_key_select_new(uint32_t ctx, uint32_t key_len, const char * direction, const char * cipher)
{
    if (trace_event_get_state(TRACE_AES_CMD_KEY_SELECT_NEW) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 7 "../hw/vmapple/trace-events"
            qemu_log("%d@%zu.%06zu:aes_cmd_key_select_new " "[%d] Selecting new key size=%d to %scrypt with %s" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , ctx, key_len, direction, cipher);
#line 135 "trace/trace-hw_vmapple.h"
        } else {
#line 7 "../hw/vmapple/trace-events"
            qemu_log("aes_cmd_key_select_new " "[%d] Selecting new key size=%d to %scrypt with %s" "\n", ctx, key_len, direction, cipher);
#line 139 "trace/trace-hw_vmapple.h"
        }
    }
}

static inline void trace_aes_cmd_key_select_new(uint32_t ctx, uint32_t key_len, const char * direction, const char * cipher)
{
    if (true) {
        _nocheck__trace_aes_cmd_key_select_new(ctx, key_len, direction, cipher);
    }
}

#define TRACE_AES_CMD_IV_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_AES_CMD_IV) || \
    false)

static inline void _nocheck__trace_aes_cmd_iv(uint32_t ctx, uint32_t iv0, uint32_t iv1, uint32_t iv2, uint32_t iv3)
{
    if (trace_event_get_state(TRACE_AES_CMD_IV) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 8 "../hw/vmapple/trace-events"
            qemu_log("%d@%zu.%06zu:aes_cmd_iv " "[%d] 0x%08x 0x%08x 0x%08x 0x%08x" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , ctx, iv0, iv1, iv2, iv3);
#line 166 "trace/trace-hw_vmapple.h"
        } else {
#line 8 "../hw/vmapple/trace-events"
            qemu_log("aes_cmd_iv " "[%d] 0x%08x 0x%08x 0x%08x 0x%08x" "\n", ctx, iv0, iv1, iv2, iv3);
#line 170 "trace/trace-hw_vmapple.h"
        }
    }
}

static inline void trace_aes_cmd_iv(uint32_t ctx, uint32_t iv0, uint32_t iv1, uint32_t iv2, uint32_t iv3)
{
    if (true) {
        _nocheck__trace_aes_cmd_iv(ctx, iv0, iv1, iv2, iv3);
    }
}

#define TRACE_AES_CMD_DATA_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_AES_CMD_DATA) || \
    false)

static inline void _nocheck__trace_aes_cmd_data(uint32_t key, uint32_t iv, uint64_t src, uint64_t dst, uint32_t len)
{
    if (trace_event_get_state(TRACE_AES_CMD_DATA) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 9 "../hw/vmapple/trace-events"
            qemu_log("%d@%zu.%06zu:aes_cmd_data " "[key=%d iv=%d] src=0x%"PRIx64" dst=0x%"PRIx64" len=0x%x" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , key, iv, src, dst, len);
#line 197 "trace/trace-hw_vmapple.h"
        } else {
#line 9 "../hw/vmapple/trace-events"
            qemu_log("aes_cmd_data " "[key=%d iv=%d] src=0x%"PRIx64" dst=0x%"PRIx64" len=0x%x" "\n", key, iv, src, dst, len);
#line 201 "trace/trace-hw_vmapple.h"
        }
    }
}

static inline void trace_aes_cmd_data(uint32_t key, uint32_t iv, uint64_t src, uint64_t dst, uint32_t len)
{
    if (true) {
        _nocheck__trace_aes_cmd_data(key, iv, src, dst, len);
    }
}

#define TRACE_AES_CMD_STORE_IV_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_AES_CMD_STORE_IV) || \
    false)

static inline void _nocheck__trace_aes_cmd_store_iv(uint32_t ctx, uint64_t addr, uint32_t iv0, uint32_t iv1, uint32_t iv2, uint32_t iv3)
{
    if (trace_event_get_state(TRACE_AES_CMD_STORE_IV) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 10 "../hw/vmapple/trace-events"
            qemu_log("%d@%zu.%06zu:aes_cmd_store_iv " "[%d] addr=0x%"PRIx64"x -> 0x%08x 0x%08x 0x%08x 0x%08x" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , ctx, addr, iv0, iv1, iv2, iv3);
#line 228 "trace/trace-hw_vmapple.h"
        } else {
#line 10 "../hw/vmapple/trace-events"
            qemu_log("aes_cmd_store_iv " "[%d] addr=0x%"PRIx64"x -> 0x%08x 0x%08x 0x%08x 0x%08x" "\n", ctx, addr, iv0, iv1, iv2, iv3);
#line 232 "trace/trace-hw_vmapple.h"
        }
    }
}

static inline void trace_aes_cmd_store_iv(uint32_t ctx, uint64_t addr, uint32_t iv0, uint32_t iv1, uint32_t iv2, uint32_t iv3)
{
    if (true) {
        _nocheck__trace_aes_cmd_store_iv(ctx, addr, iv0, iv1, iv2, iv3);
    }
}

#define TRACE_AES_CMD_FLAG_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_AES_CMD_FLAG) || \
    false)

static inline void _nocheck__trace_aes_cmd_flag(uint32_t raise, uint32_t flag_info)
{
    if (trace_event_get_state(TRACE_AES_CMD_FLAG) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 11 "../hw/vmapple/trace-events"
            qemu_log("%d@%zu.%06zu:aes_cmd_flag " "raise=%d flag_info=0x%x" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , raise, flag_info);
#line 259 "trace/trace-hw_vmapple.h"
        } else {
#line 11 "../hw/vmapple/trace-events"
            qemu_log("aes_cmd_flag " "raise=%d flag_info=0x%x" "\n", raise, flag_info);
#line 263 "trace/trace-hw_vmapple.h"
        }
    }
}

static inline void trace_aes_cmd_flag(uint32_t raise, uint32_t flag_info)
{
    if (true) {
        _nocheck__trace_aes_cmd_flag(raise, flag_info);
    }
}

#define TRACE_AES_FIFO_PROCESS_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_AES_FIFO_PROCESS) || \
    false)

static inline void _nocheck__trace_aes_fifo_process(uint32_t cmd, bool success)
{
    if (trace_event_get_state(TRACE_AES_FIFO_PROCESS) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 12 "../hw/vmapple/trace-events"
            qemu_log("%d@%zu.%06zu:aes_fifo_process " "cmd=%d success=%d" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , cmd, success);
#line 290 "trace/trace-hw_vmapple.h"
        } else {
#line 12 "../hw/vmapple/trace-events"
            qemu_log("aes_fifo_process " "cmd=%d success=%d" "\n", cmd, success);
#line 294 "trace/trace-hw_vmapple.h"
        }
    }
}

static inline void trace_aes_fifo_process(uint32_t cmd, bool success)
{
    if (true) {
        _nocheck__trace_aes_fifo_process(cmd, success);
    }
}

#define TRACE_AES_WRITE_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_AES_WRITE) || \
    false)

static inline void _nocheck__trace_aes_write(uint64_t offset, uint64_t val)
{
    if (trace_event_get_state(TRACE_AES_WRITE) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 13 "../hw/vmapple/trace-events"
            qemu_log("%d@%zu.%06zu:aes_write " "offset=0x%"PRIx64" val=0x%"PRIx64 "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , offset, val);
#line 321 "trace/trace-hw_vmapple.h"
        } else {
#line 13 "../hw/vmapple/trace-events"
            qemu_log("aes_write " "offset=0x%"PRIx64" val=0x%"PRIx64 "\n", offset, val);
#line 325 "trace/trace-hw_vmapple.h"
        }
    }
}

static inline void trace_aes_write(uint64_t offset, uint64_t val)
{
    if (true) {
        _nocheck__trace_aes_write(offset, val);
    }
}

#define TRACE_AES_2_READ_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_AES_2_READ) || \
    false)

static inline void _nocheck__trace_aes_2_read(uint64_t offset, uint64_t res)
{
    if (trace_event_get_state(TRACE_AES_2_READ) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 14 "../hw/vmapple/trace-events"
            qemu_log("%d@%zu.%06zu:aes_2_read " "offset=0x%"PRIx64" res=0x%"PRIx64 "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , offset, res);
#line 352 "trace/trace-hw_vmapple.h"
        } else {
#line 14 "../hw/vmapple/trace-events"
            qemu_log("aes_2_read " "offset=0x%"PRIx64" res=0x%"PRIx64 "\n", offset, res);
#line 356 "trace/trace-hw_vmapple.h"
        }
    }
}

static inline void trace_aes_2_read(uint64_t offset, uint64_t res)
{
    if (true) {
        _nocheck__trace_aes_2_read(offset, res);
    }
}

#define TRACE_AES_2_WRITE_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_AES_2_WRITE) || \
    false)

static inline void _nocheck__trace_aes_2_write(uint64_t offset, uint64_t val)
{
    if (trace_event_get_state(TRACE_AES_2_WRITE) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 15 "../hw/vmapple/trace-events"
            qemu_log("%d@%zu.%06zu:aes_2_write " "offset=0x%"PRIx64" val=0x%"PRIx64 "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , offset, val);
#line 383 "trace/trace-hw_vmapple.h"
        } else {
#line 15 "../hw/vmapple/trace-events"
            qemu_log("aes_2_write " "offset=0x%"PRIx64" val=0x%"PRIx64 "\n", offset, val);
#line 387 "trace/trace-hw_vmapple.h"
        }
    }
}

static inline void trace_aes_2_write(uint64_t offset, uint64_t val)
{
    if (true) {
        _nocheck__trace_aes_2_write(offset, val);
    }
}

#define TRACE_AES_DUMP_DATA_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_AES_DUMP_DATA) || \
    false)

static inline void _nocheck__trace_aes_dump_data(const char * desc, const char * hex)
{
    if (trace_event_get_state(TRACE_AES_DUMP_DATA) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 16 "../hw/vmapple/trace-events"
            qemu_log("%d@%zu.%06zu:aes_dump_data " "%s%s" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , desc, hex);
#line 414 "trace/trace-hw_vmapple.h"
        } else {
#line 16 "../hw/vmapple/trace-events"
            qemu_log("aes_dump_data " "%s%s" "\n", desc, hex);
#line 418 "trace/trace-hw_vmapple.h"
        }
    }
}

static inline void trace_aes_dump_data(const char * desc, const char * hex)
{
    if (true) {
        _nocheck__trace_aes_dump_data(desc, hex);
    }
}

#define TRACE_BDIF_READ_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_BDIF_READ) || \
    false)

static inline void _nocheck__trace_bdif_read(uint64_t offset, uint32_t size, uint64_t value)
{
    if (trace_event_get_state(TRACE_BDIF_READ) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 19 "../hw/vmapple/trace-events"
            qemu_log("%d@%zu.%06zu:bdif_read " "offset=0x%"PRIx64" size=0x%x value=0x%"PRIx64 "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , offset, size, value);
#line 445 "trace/trace-hw_vmapple.h"
        } else {
#line 19 "../hw/vmapple/trace-events"
            qemu_log("bdif_read " "offset=0x%"PRIx64" size=0x%x value=0x%"PRIx64 "\n", offset, size, value);
#line 449 "trace/trace-hw_vmapple.h"
        }
    }
}

static inline void trace_bdif_read(uint64_t offset, uint32_t size, uint64_t value)
{
    if (true) {
        _nocheck__trace_bdif_read(offset, size, value);
    }
}

#define TRACE_BDIF_WRITE_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_BDIF_WRITE) || \
    false)

static inline void _nocheck__trace_bdif_write(uint64_t offset, uint32_t size, uint64_t value)
{
    if (trace_event_get_state(TRACE_BDIF_WRITE) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 20 "../hw/vmapple/trace-events"
            qemu_log("%d@%zu.%06zu:bdif_write " "offset=0x%"PRIx64" size=0x%x value=0x%"PRIx64 "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , offset, size, value);
#line 476 "trace/trace-hw_vmapple.h"
        } else {
#line 20 "../hw/vmapple/trace-events"
            qemu_log("bdif_write " "offset=0x%"PRIx64" size=0x%x value=0x%"PRIx64 "\n", offset, size, value);
#line 480 "trace/trace-hw_vmapple.h"
        }
    }
}

static inline void trace_bdif_write(uint64_t offset, uint32_t size, uint64_t value)
{
    if (true) {
        _nocheck__trace_bdif_write(offset, size, value);
    }
}

#define TRACE_BDIF_VBLK_READ_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_BDIF_VBLK_READ) || \
    false)

static inline void _nocheck__trace_bdif_vblk_read(const char * dev, uint64_t addr, uint64_t offset, uint32_t len, int r)
{
    if (trace_event_get_state(TRACE_BDIF_VBLK_READ) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 21 "../hw/vmapple/trace-events"
            qemu_log("%d@%zu.%06zu:bdif_vblk_read " "dev=%s addr=0x%"PRIx64" off=0x%"PRIx64" size=0x%x r=%d" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , dev, addr, offset, len, r);
#line 507 "trace/trace-hw_vmapple.h"
        } else {
#line 21 "../hw/vmapple/trace-events"
            qemu_log("bdif_vblk_read " "dev=%s addr=0x%"PRIx64" off=0x%"PRIx64" size=0x%x r=%d" "\n", dev, addr, offset, len, r);
#line 511 "trace/trace-hw_vmapple.h"
        }
    }
}

static inline void trace_bdif_vblk_read(const char * dev, uint64_t addr, uint64_t offset, uint32_t len, int r)
{
    if (true) {
        _nocheck__trace_bdif_vblk_read(dev, addr, offset, len, r);
    }
}
#endif /* TRACE_HW_VMAPPLE_GENERATED_TRACERS_H */
