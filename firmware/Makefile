ARM_GNU ?= arm-none-eabi

# Files
ld_script = linker
startup = startup
main = main
uart = uart

# Compiler flags
AARCH = -mcpu=cortex-m7
CFLAGS = -c -Wall $(AARCH) -mthumb
ASFLAGS = $(AARCH)
LDFLAGS = -T $(ld_script).ld
DEBUG_FLAGS = -g 

# QEMU configuration
QEMU_FLAGS = -M nxps32k3x8evb \
    -nographic \
    -kernel $(main).elf \
    -nographic \
    -chardev socket,id=chrtpm,path=/tmp/swtpm-sock \
    -tpmdev emulator,id=tpm0,chardev=chrtpm


qemu_exec = ../qemu/build/qemu-system-arm $(QEMU_FLAGS)

# SWTPM directory
TPM_DIR = /tmp/tpm
SOCKET_PATH = /tmp/swtpm-sock


# SWTPM configuration
SWTPM_FLAGS = --tpmstate dir=$(TPM_DIR) \
             --ctrl type=unixio,path=$(SOCKET_PATH) \
             --tpm2 --server type=tcp,port=2321 \
             --ctrl type=tcp,port=2322 \
             --flags startup-clear 

# Normal compilation
OBJS = $(startup).o $(main).o $(uart).o

all: $(OBJS) link

%.o: %.c
	$(ARM_GNU)-gcc $(CFLAGS) $< -o $@

%.o: %.s
	$(ARM_GNU)-as $(ASFLAGS) $< -o $@

link: 
	$(ARM_GNU)-ld $(LDFLAGS) $(OBJS) -o $(main).elf


# Debug version
OBJS_DBG = $(startup)_dbg.o $(main)_dbg.o $(uart)_dbg.o

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

# TPM execution command
clean_tpm:
	killall swtpm 2>/dev/null
	rm -rf $(TPM_DIR)
	rm -f $(SOCKET_PATH)

start_tpm:	
	killall swtpm 2>/dev/null
	rm -rf $(TPM_DIR)
	mkdir -p $(TPM_DIR)
	chmod 777 $(TPM_DIR)

	swtpm socket $(SWTPM_FLAGS)
	export TPM2TOOLS_TCTI="swtpm:port=2321"
