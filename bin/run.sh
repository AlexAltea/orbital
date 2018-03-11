#!/usr/bin/env bash

# Run Orbital
../orbital-qemu/ps4-softmmu/qemu-system-ps4 \
    -bios ./ubios.bin \
    -kernel ./boot.img \
    -drive file=hdd.qcow2 \
    -drive file=fat:rw:sflash/,media=disk \
    -monitor stdio -smp 8 -display orbital
