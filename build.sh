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
  make -j$(nproc)
  mv out/bios.bin ../${path_bin}/ubios.bin
}

function build_grub() {
  # Dependencies
  if [ -x "$(command -v apt)" ]; then
    sudo apt-get -qq install python \
                             dh-autoreconf \
                             bison flex
  fi
  # Building
  cd ${path_orbital}
  cd ${path_grub}
  ./autogen.sh
  ./configure --target=x86_64 --disable-werror
  make -j$(nproc)
}

function build_qemu() {
  # Dependencies
  if [ -x "$(command -v apt)" ]; then
    sudo apt -qq install git \
                         zlib1g-dev \
                         libglib2.0-dev libfdt-dev libpixman-1-dev \
                         libsdl2-dev libvulkan-dev
  fi
  # Building
  cd ${path_orbital}
  cd ${path_qemu}
  ./configure --target-list=ps4-softmmu \
    --enable-sdl --enable-vulkan --enable-debug --disable-capstone \
    --enable-hax
  make -j$(nproc)
}

function generate_image() {
    cd ${path_orbital}
    tar -c -f ${path_bin}/memdisk.tar -C resources boot
    ${path_grub}/grub-mkimage -d ${path_grub}/grub-core \
        -O i386-pc -o bin/boot.img -m bin/memdisk.tar -c resources/boot/grub/boot.cfg \
        memdisk biosdisk part_msdos part_gpt gfxterm_menu fat tar bsd memrw configfile
}

if [ "$1" == "clean" ]; then
  cd ${path_orbital}
  cd ${path_bios}
  make clean
  cd ${path_orbital}
  cd ${path_grub}
  make clean
  cd ${path_orbital}
  cd ${path_qemu}
  make clean
else
  build_bios
  build_grub
  build_qemu
  generate_image
fi
