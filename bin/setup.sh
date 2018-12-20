#!/usr/bin/env bash

# cd to script's directory (so that it can be run from anywhere)
cd "${0%/*}"

# Setup Orbital
../orbital-qemu/qemu-img create-ps4 \
    --data ./hdd -f qcow2 ./hdd.qcow2 200G
