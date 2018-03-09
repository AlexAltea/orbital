HDD Files
=========

This folder should contain the following files:

- `eap.img`
- `preinst.img`
- `recovery.img`
- `system.img`
- `system_ex.img`

These files can extracted from PUP files, by first decrypting them with [ps4-pup_decrypt](https://github.com/idc/ps4-pup_decrypt) in your console, and then unpacking them with [ps4-pup_unpack](https://github.com/idc/ps4-pup_unpack) in your computer. Specifically:

- `eap.img`, `system.img`, `system_ex.img`: Normal or recovery PUP matching the desired software version.
- `preinst.img`, `recovery.img`: Any recovery PUP (these files never change across software versions).
