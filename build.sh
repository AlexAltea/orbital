#!/bin/bash

# Configuration
path_bin='./bin'
path_grub='./orbital-grub'
path_qemu='./orbital-qemu'
path_orbital=`pwd`

function build_grub() {
  # Dependencies
  sudo apt-get -qq install python
  # Building
  cd ${path_grub}
  ./autogen.sh
  ./configure --target=x86_64
  make -j4
}

function build_qemu() {
  # Dependencies
  sudo apt-get -qq install git
  sudo apt-get -qq install zlib1g-dev
  sudo apt-get -qq install libglib2.0-dev libfdt-dev libpixman-1-dev
  # Building
  cd ${path_qemu}
  ./configure --target-list=ps4-softmmu --enable-sdl --enable-debug
  make -j4
}

#build_grub
#build_qemu

# Generate GRUB image
cd ${path_orbital}
tar -C resources -cf ${path_bin}/memdisk.tar boot
${path_grub}/grub-mkimage -d ${path_grub}/grub-core \
  -O i386-pc -o bin/boot.img -m bin/memdisk.tar -c resources/boot/grub/boot.cfg \
  memdisk biosdisk part_msdos part_gpt gfxterm_menu fat tar bsd memrw configfile
