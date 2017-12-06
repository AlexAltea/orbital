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
./configure --target-list=ps4-softmmu --enable-sdl --enable-debug
make -j4

# Generate GRUB image
cd ${path_orbital}
tar -C resources -cf ${path_bin}/memdisk.tar boot
${path_grub}/grub-mkimage -d ${path_grub}/grub-core \
  -O i386-pc -o bin/boot.img -m bin/memdisk.tar -c resources/boot/grub/boot.cfg \
  memdisk biosdisk part_msdos part_gpt gfxterm_menu fat tar bsd memrw configfile
