# CyberSec project
---
# How to Run

To run the project, you first need to build a custom version of QEMU and compile the firmware. Follow the steps below:
1. Prepare the Environment

Navigate to the firmware directory and initialize the environment:

cd firmware
make init

2. Build Custom QEMU

Next, build the custom QEMU from source:

cd ../qemu
## (Optional) Clean previous build if needed
rm -rf build/

## Create and enter build directory
mkdir build && cd build

## Configure for minimal ARM support
../configure --target-list=arm-softmmu

## Build QEMU
make

3. Compile the Firmware

Once QEMU is built, return to the firmware directory and build the firmware:

cd ../../firmware
make all

4. Run the Firmware with QEMU

Finally, start QEMU with the compiled firmware:

make qemu_start
---
### Recap
What have been done until now is the base board (basic functionalities, not even UART already done), which we should add the required device to meet the required functionalities

We're working on the nxps32k3x8evb board, which can be found on qemu/hw/arm/ 
The C file which describes it is nxps32k3x8evb.c
Another folder is present firmware/ this contains a little firmware that runs on a board.

TODO List
- [x] UART to print result
- [x] TPM Command Chain Implementation
    - [x] Command preparation
    - [x] Command transmission
    - [x] Response handling
    - [x] Error management
- [x] Cryptographic Key Management
    - [x] Asymmetric key pair generation
    - [ ] Secure key storage
    - [ ] Key Lifecycle management
    - [x] Basic Cryptographic Operations
- [ ] Recommended Additional Modules (Optional) (hardware)
    - [ ] Platform Configuration Registers (PCR)
    - [ ] Attestation Functionality
    - [ ] Sealed Storage Mechanism
