# CyberSec Project

## Directory Structure

### 🔧 QEMU Customization Files

**Core board and peripheral setup:**

* `qemu/hw/arm/nxps32k3x8evb.c` — Base board definition and peripheral connections
* `qemu/hw/arm/nxps32k3x8evb_mcu.c` — MCU-specific implementation

**Custom TPM implementation:**

* `qemu/hw/arm/custom_tpm.c` — TPM logic and core implementation
* `qemu/hw/arm/tpm_command_handler.h` — TPM command structure definitions
* `qemu/hw/arm/tpm_types.h` — TPM specification types and constants
* `qemu/hw/arm/tpm_basic_crypto_rsa.c` — RSA cryptographic operations for TPM
* `qemu/hw/arm/tpm_basic_crypto_rsa.h` — Header file for RSA crypto functions

---

### 🧪 Demo Testing Files

**Bare-metal setup (firmware):**

* `firmware/linker.ld` — Linker script
* `firmware/startup.s` — Startup assembly code
* `firmware/syscall.c` — System call stubs
* `firmware/tpm.c` — TPM communication logic
* `firmware/tpm.h` — TPM interface and definitions

**TPM driver code:**

* `firmware/tpm.c` — TPM driver implementation
* `firmware/tpm.h` — TPM driver interface

---

## 🚀 How to Run

To run the project, you first need to build a custom version of QEMU and compile the firmware. Follow the steps below:

### 1. Prepare the Environment

Navigate to the firmware directory and initialize the environment:

```bash
cd firmware
make init
```

### 2. Build Custom QEMU

Next, build the custom QEMU from source:

```bash
cd ../qemu
# (Optional) Clean previous build if needed
rm -rf build/

# Create and enter build directory
mkdir build && cd build

# Configure for minimal ARM support
../configure --target-list=arm-softmmu

# Build QEMU
make
```

### 3. Compile the Firmware

Once QEMU is built, return to the firmware directory and build the firmware:

```bash
cd ../../firmware
make all
```

### 4. Run the Firmware with QEMU

Finally, start QEMU with the compiled firmware:

```bash
make qemu_start
```

---

## 🧩 Project Recap

The project currently includes a basic implementation of the base board. While the UART and TPM functionalities are in place, some components are still under development.

We're targeting the `nxps32k3x8evb` board located in `qemu/hw/arm/`. The main C file responsible for this board is `nxps32k3x8evb.c`.

The `firmware/` folder contains a minimal firmware that runs on the board for demo and testing purposes.

---

## ✅ TODO List

* [x] UART support for output
* [x] TPM Command Chain Implementation

  * [x] Command preparation
  * [x] Command transmission
  * [x] Response handling
  * [x] Error management
* [x] Cryptographic Key Management

  * [x] Asymmetric key pair generation
  * [x] Basic cryptographic operations

