#!/usr/bin/env bash

# cd to script's directory (so that it can be run from anywhere)
cd "${0%/*}"

# Run Orbital
./qemu-system-ps4 \
    -bios ./ubios.bin \
    -kernel ./boot.img \
    -drive if=none,id=hdd,file=hdd.qcow2 \
    -device usb-storage,bus=axhci1.0,drive=hdd \
    -monitor stdio -smp 8 -display orbital \
    ${@}
