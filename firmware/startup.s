.word stack_top
.word _start

.thumb_func

.global _start

_start:
    mov r0, #0x5
    BL main
    B .
