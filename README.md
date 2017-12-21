Orbital
=======

Virtualization-based PlayStation 4 emulator.

## Roadmap

- [x] Boot kernel.
- [x] Kernel debugging with symbols.
- [x] Support for Orbis kernels with KASLR.
- [x] Emulating Aeolia's UART device (partial).
- [x] Successful driver initialization.
- [ ] Fix Starsha DCE initialization.
- [ ] Adding Vulkan support to QEMU.
- [ ] Process Starsha FIFO commands with a Vulkan backend.
- [ ] ...

## Remarks

- Until keys are dump, decryption with SAMU will be "_emulated_" by hashing encrypted input blobs and returning decrypted blobs previously obtained from the actual console.
- Kernel ELFs generated from memory dumps will **not** work since R/W segments might have been modified into a state where booting is not possible. Please generate proper binaries offline by decrypting ELF segments with SAMU, not by dumping memory.

## Status

This is the current state of Orbital on publicly available kernels along with the date in which the tests were made:

* __0.82__ (_2017-11-29_): Will run fine until `hrtimer` initialization and then crash.
* __4.55__ (_2017-12-21_): (Needs testing).
* __5.00__ (_2017-12-21_): All drivers initialize correctly. Later during system initialization, the kernel gets stuck at an endless loops during `dce_flip_init`.

