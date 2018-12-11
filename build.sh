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
  # Building
  cd ${path_orbital}
  cd ${path_grub}
  ./autogen.sh
  ./configure --target=x86_64 --disable-werror
  make -j$(nproc)
}

function build_qemu() {
  # Building
  cd ${path_orbital}
  cd ${path_qemu}
  ./configure --target-list=ps4-softmmu \
    --enable-sdl --enable-vulkan --enable-debug --disable-capstone \
    --enable-hax --disable-stack-protector
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
  build_qemu
  if [ $(uname -o) != "Msys" ] 
  then
    build_bios
    build_grub
    generate_image
  fi
fi
