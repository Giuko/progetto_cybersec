MEMORY
{
    ITCM (xr) : ORIGIN = 0x00000000, LENGTH = 64K
    SRAM (rw) : ORIGIN = 0x20400000, LENGTH = 758K
}

ENTRY(_start)

SECTIONS
{
    .text : {
        *(.text*)
    } > ITCM

    .data : {
        *(.data)
    } > SRAM

    .bss : {
        *(.bss*)
    } > SRAM

    stack_top = ORIGIN(SRAM) + LENGTH(SRAM);
}
