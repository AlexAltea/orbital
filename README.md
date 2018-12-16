Orbital
=======

Virtualization-based PlayStation 4 emulator.

## Status

The current state of Orbital at booting decrypted kernels can be followed in the issue tracker: both [PS4 4.55](https://github.com/AlexAltea/orbital/issues/3) and [PS4 5.00](https://github.com/AlexAltea/orbital/issues/4) have been tested. You can also get occasional updates and news via [Twitter](https://twitter.com/AlexAltea). Support this project at [Patreon](https://www.patreon.com/AlexAltea).

Future plans for the emulator can be found at the [Roadmap](https://github.com/AlexAltea/orbital/wiki/Roadmap) page.

## FAQ

> How does Orbital work without having SAMU keys?

Until keys are dumped, decryption with SAMU will be "_emulated_" by hashing encrypted input blobs and returning decrypted blobs previously obtained from the actual console.

> My kernel dump crashes shortly after booting. Why?

Kernel ELFs generated from memory dumps will **not** work since writable segments might have been modified into a state where booting is not possible. Please generate proper binaries offline by decrypting ELF segments with SAMU on your actual console, not by dumping memory.

> Where can I get Orbital?

**This project is not ready for end users.** No binaries are provided, so you must build each of the three components (BIOS, GRUB, QEMU) yourself. Furthermore, configuring the emulator to do something will be hard, as you will need to dump and decrypt the entire PS4 filesystem and sflash, including the kernel. You might find hints on how to do this in the few scattered _.sh_ files in this repo. Of course, in the future, I'll make this emulator more user-friendly.


## Requirements

* __System__: Windows (7+), Linux (TBD.), macOS (10.10+).
* __Processor__: x86-64 CPU with AVX and virtualization extensions.
* __Memory__: 12 GB RAM.
* __Graphics__: TBD.

## Acknowledgements

Thanks to all people who have directly or indirectly helped in making this possible. In alphabetical order: *flatz, idc, m0rph3us1987, masterzorag, wildcard, x41, zecoxao, zer0xff, z80*. Also many anonymous folks and others who might have slipped my mind. You know who you are!
