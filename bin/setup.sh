#!/usr/bin/env bash

# Setup Orbital
../orbital-qemu/qemu-img.exe create-ps4 \
    --data ./hdd -f qcow2 ./hdd.qcow2 200G
