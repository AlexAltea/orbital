#!/bin/bash

# Configuration
path_bin='./bin'
path_grub='./orbital-grub'
path_qemu='./orbital-qemu'
path_orbital=`pwd`

# Dependencies
sudo apt-get -qq install git
sudo apt-get -qq install python
sudo apt-get -qq install libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev
git submodule update --init

# Build GRUB
cd ${path_grub}
./autogen.sh
./configure --target=x86_64
make -j4

# Build QEMU
cd ${path_grub}
./configure --target-list=x86_64-softmmu --enable-sdl --enable-debug
make -j4

# Generate GRUB image
cd ${path_orbital}
${path_grub}/grub-mkimage -d ${path_grub}/grub-core \
  -O i386-pc -o bin/boot.img -p /boot/grub -c resources/boot.cfg \
  biosdisk part_msdos part_gpt gfxterm_menu fat bsd
