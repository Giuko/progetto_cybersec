# CyberSec project

---
### Recap
What have been done until now is the base board (basic functionalities, not even UART already done), which we should add the required device to meet the required functionalities

We're working on the nxps32k3x8evb board, which can be found on qemu/hw/arm/ 
The C file which describes it is nxps32k3x8evb.c
Another folder is present firmware/ this contains a little firmware that runs on a board.

TODO List
- [x] UART to print result
- [ ] TPM Command Chain Implementation (firmware)
    - [ ] Command preparation
    - [ ] Command transmission
    - [ ] Response handling
    - [ ] Error management
- [ ] Cryptographic Key Management (hardware)
    - [x] Asymmetric key pair generation
    - [ ] Secure key storage
    - [ ] Key Lifecycle management
    - [ ] Basic Cryptographic Operations
- [ ] Recommended Additional Modules (Optional) (hardware)
    - [ ] Platform Configuration Registers (PCR)
    - [ ] Attestation Functionality
    - [ ] Sealed Storage Mechanism
