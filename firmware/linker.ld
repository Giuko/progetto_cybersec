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
        end = .;
        PROVIDE(end = end);
    } > SRAM

    stack_top = ORIGIN(SRAM) + LENGTH(SRAM);

    _end = .;
    PROVIDE(end = .);
}
