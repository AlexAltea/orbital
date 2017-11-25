#!/bin/bash

# Configuration
path_bin='./bin'
path_grub='./orbital-grub'
path_qemu='./orbital-qemu'
path_orbital=`pwd`

# Dependencies
git submodule update --init
sudo apt-get -qq install kpartx
sudo apt-get -qq install python

# Build GRUB
cd ${path_grub}
./autogen.sh
./configure --target=x86_64
make

# Generate GRUB image
cd ${path_orbital}
${path_grub}/grub-mkimage -d ${path_grub}/grub-core \
  -O i386-pc -o bin/boot.img -p /boot/grub -c boot.cfg \
  biosdisk part_msdos part_gpt gfxterm_menu fat bsd
