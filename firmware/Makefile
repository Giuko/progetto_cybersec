ARM_GNU ?= arm-none-eabi

# Files
ld_script = linker
startup = startup
main = main

# Compiler flags
AARCH = -mcpu=cortex-m7
CFLAGS = -c -Wall $(AARCH) -mthumb
ASFLAGS = $(AARCH)
LDFLAGS = -T $(ld_script).ld
DEBUG_FLAGS = -g -s -S

# QEMU configuration
QEMU_FLAGS = -M nxps32k3x8evb -nographic -kernel $(main).elf
qemu_exec = ../qemu/build/qemu-system-arm $(QEMU_FLAGS)

# Normal compilation
OBJS = $(startup).o $(main).o

all: $(OBJS) link

%.o: %.c
	$(ARM_GNU)-gcc $(CFLAGS) $< -o $@

%.o: %.s
	$(ARM_GNU)-as $(ASFLAGS) $< -o $@

link: 
	$(ARM_GNU)-ld $(LDFLAGS) $(OBJS) -o $(main).elf


# Debug version
OBJS_DBG = $(startup)_dbg.o $(main)_dbg.o

debug: $(OBJS_DBG) link_dbg

%_dbg.o: %.c
	$(ARM_GNU)-gcc $(DEBUG_FLAGS) $(CFLAGS) $< -o $@

%_dbg.o: %.s
	$(ARM_GNU)-as $(ASFLAGS) $(DEBUG_FLAGS) $< -o $@

link_dbg: 
	$(ARM_GNU)-ld $(LDFLAGS) $(OBJS_DBG) -o $(main).elf



# Run QEMU
qemu_start:
	$(qemu_exec)

qemu_debug:
	$(qemu_exec) -s -S

# GDB
gdb_start:
	gdb-multiarch $(main).elf

# Clean up all the .o and .elf files 
clean:
	rm -f *.o *.elf




