Orbital
=======

Virtualization-based PlayStation 4 emulator.

## Roadmap

The roadmap has been relocated to the following Wiki page: https://github.com/AlexAltea/orbital/wiki/Roadmap

## Remarks

- Until keys are dump, decryption with SAMU will be "_emulated_" by hashing encrypted input blobs and returning decrypted blobs previously obtained from the actual console.
- Kernel ELFs generated from memory dumps will **not** work since R/W segments might have been modified into a state where booting is not possible. Please generate proper binaries offline by decrypting ELF segments with SAMU, not by dumping memory.

## Status

The current state of Orbital at booting decrypted kernels can be followed in the issue tracker:

* [PS4 4.55](https://github.com/AlexAltea/orbital/issues/3)
* [PS4 5.00](https://github.com/AlexAltea/orbital/issues/4)
