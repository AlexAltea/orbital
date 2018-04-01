#!/bin/bash

# Configuration
path_bin='./bin'
path_bios='./orbital-bios'
path_grub='./orbital-grub'
path_qemu='./orbital-qemu'
path_orbital=`pwd`

function build_bios() {
  cd ${path_orbital}
  cd ${path_bios}
  make -j4
  mv out/bios.bin ../${path_bin}/ubios.bin
}

function build_grub() {
  # Dependencies
  sudo apt-get -qq install python
  # Building
  cd ${path_orbital}
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
  cd ${path_orbital}
  cd ${path_qemu}
  ./configure --target-list=ps4-softmmu \
    --enable-sdl --enable-vulkan --enable-hax --enable-debug --disable-capstone
  make -j4
}

build_bios
build_grub
build_qemu

# Generate GRUB image
cd ${path_orbital}
tar -c -f ${path_bin}/memdisk.tar -C resources boot
${path_grub}/grub-mkimage -d ${path_grub}/grub-core \
  -O i386-pc -o bin/boot.img -m bin/memdisk.tar -c resources/boot/grub/boot.cfg \
  memdisk biosdisk part_msdos part_gpt gfxterm_menu fat tar bsd memrw configfile
