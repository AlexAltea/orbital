Orbital
=======

Virtualization-based PlayStation 4 emulator.

## Roadmap

- [x] Boot kernel.
- [x] Kernel debugging with symbols.
- [x] Load GDT/GIT and initialize segment registers.
- [x] Emulating Aeolia's UART device (partial).
- [ ] Survive FreeBSD system startup (stuck at `scheduler`).
- [ ] Support for Orbis kernels with KASLR.
- [ ] ...

## Remarks

- Until keys are dump, decryption with SAMU will be "_emulated_" by hashing encrypted input blobs and returning decrypted blobs previously obtained from the actual console.
- Kernel ELFs generated from memory dumps will **not** work since R/W segments might have been modified into a state where booting is not possible. Please generate proper binaries offline by decrypting ELF segments with SAMU, not by dumping memory.

## Status

This is the current state of Orbital on publicly available kernels along with the date in which the tests were made:

* __0.82__ (_2017-11-29_): Will run fine until `hrtimer` initialization and then crash.
* __1.76__ (_2017-12-08_): Will run fine until `scheduler` where it will attempt to work with mysteriously uninitialized data as if it were initialized.
* __4.55__ (_2017-11-29_): This kernel uses KASLR, the initial `rsp` value that should be specified by the bootloader into a specific kernel segment remains zero-initialized in Orbital, causing issues in the first `pusb ebp`.
* __5.00__ (_2017-11-29_): Same as 4.55. Additionally, this kernel uses x86 extensions not supported by QEMU, e.g. AVX. On appropriate hosts, KVM/HAXM acceleration will solve this issue but will render debugging impossible since breakpoints will no longer work.
