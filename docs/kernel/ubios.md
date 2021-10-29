# UBIOS

Mapped into [0x680000,0x6FFFFF] which is aliasedsize at the end of 32-bit physical address space.
The x86 CPU init/reset state set CS:IP := 0xFFFFFFF0, matching the 80010002 entry point (0x6FFFF0) thanks to the alias.

## AGESA

One of three available images will be loaded at 0x680000:

- GladiusBDK
- ClaytonBDK
- ThebePBDK

## KASLR

The 20-byte buffer at 0x600160 is memcpy'd to a zero-initialized 80-byte SHA1 block, and a single SHA1 transform (80 rounds) is applied.
The first word (4 bytes) of the resulting digest plays a role in different parts of the kernel loading as a source of pseudo-randomness.
Specifically, the first word & 0x7FFF becomes shifted by 14 bits becomes the KASLR offset applied to the kernel base.

One can easily defeat KASLR by finding a preimage that results in the first 2 bytes (thanks little-endian!) being 0x00.
