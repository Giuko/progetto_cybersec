ARM_GNU ?= arm-none-eabi

# Files
ld_script = linker
startup = startup
main = main
uart = uart
tpm = tpm

# Compiler flags
AARCH = -mcpu=cortex-m7
CFLAGS = -c -Wall $(AARCH) -mthumb
ASFLAGS = $(AARCH)
LDFLAGS = -T $(ld_script).ld -Wl,--gc-sections       
LIBS    = -lc -lgcc -lnosys 
DEBUG_FLAGS = -g 

# QEMU configuration
QEMU_FLAGS = -M nxps32k3x8evb \
    -nographic \
	-kernel $(main).elf \
    -nographic 


qemu_exec = ../qemu/build/qemu-system-arm $(QEMU_FLAGS)

# Normal compilation
OBJS = $(startup).o $(main).o $(uart).o $(tpm).o syscall.o

all: $(OBJS) link

%.o: %.c
	$(ARM_GNU)-gcc $(CFLAGS) $< -o $@

%.o: %.s
	$(ARM_GNU)-as $(ASFLAGS) $< -o $@

link:
	$(ARM_GNU)-gcc $(AARCH) -mthumb -nostartfiles $(LDFLAGS) $(OBJS) $(LIBS) -o $(main).elf
 

# Debug version
OBJS_DBG = $(startup)_dbg.o $(main)_dbg.o $(uart)_dbg.o $(tpm)_dbg.o

debug: $(OBJS_DBG) link_dbg

%_dbg.o: %.c
	$(ARM_GNU)-gcc $(DEBUG_FLAGS) $(CFLAGS) $< -o $@

%_dbg.o: %.s
	$(ARM_GNU)-as $(ASFLAGS) $(DEBUG_FLAGS) $< -o $@

link_dbg:
	$(ARM_GNU)-gcc $(AARCH) -mthumb -nostartfiles $(DEBUG_FLAGS) $(LDFLAGS) \
    	$(OBJS_DBG) $(LIBS) -o $(main).elf

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


# Target to prepare the system to execute build/run QEMU and cross-compile
init:
	@echo "Installing required packages..."
	sudo apt update
	sudo apt install -y \
		build-essential \
		python3 \
		python3-pip \
		git \
		flex \
		bison \
		libglib2.0-dev \
		libpixman-1-dev \
		zlib1g-dev \
		libfdt-dev \
		libtool \
		autoconf \
		automake \
		pkg-config \
		libsdl2-dev \
		libsdl2-image-dev \
		ninja-build \
		python3-sphinx \
		gcc-arm-linux-gnueabi\
		gcc-arm-none-eabi\
		gdb-multiarch \
		virt-what
	pip3 install tomli
