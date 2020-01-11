#!/usr/bin/env bash

# cd to script's directory (so that it can be run from anywhere)
cd "${0%/*}"

# Run Orbital
./qemu-system-ps4 \
    -bios ./ubios.bin \
    -kernel ./boot.img \
    -drive if=none,id=hdd,file=hdd.qcow2 \
    -drive if=none,id=usb,file=usb/usb-pup-500rec.qcow2,read-only=on \
    -drive if=ide,index=0,media=cdrom \
    -device usb-storage,drive=hdd,bus=axhci1.0,port=1 \
    -device usb-storage,drive=usb,bus=axhci2.0 \
    -monitor stdio -smp 8 -display orbital \
    ${@}
