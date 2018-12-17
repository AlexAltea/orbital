#!/bin/bash

# Configuration
path_bin='./bin'
path_bios='./orbital-bios'
path_grub='./orbital-grub'
path_qemu='./orbital-qemu'
path_orbital=`pwd`

clean="false"
additional_flags=""

function build_bios() {
    cd ${path_orbital}
    cd ${path_bios}
    make -j$(nproc)
    mv out/bios.bin ../${path_bin}/ubios.bin
}

function build_grub() {
    cd ${path_orbital}
    cd ${path_grub}
    
    if [ ! -e ./Makefile ]; then
        ./autogen.sh
        ./configure --target=x86_64 --disable-werror
    fi
    
    make -j$(nproc)
}

function build_qemu() {
    cd ${path_orbital}
    cd ${path_qemu}

    if [ ! -e ./config-host.mak ]; then
        ./configure --target-list=ps4-softmmu \
            --enable-sdl --enable-vulkan --enable-debug --disable-capstone \
            --enable-hax ${additional_flags}
    fi
  
    make -j$(nproc)
}

function postbuild() {
    cd ${path_orbital}
    if [ $(uname -o) != "Msys" ]; then
        tar -c -f ${path_bin}/memdisk.tar -C resources boot
            ${path_grub}/grub-mkimage -d ${path_grub}/grub-core \
            -O i386-pc -o bin/boot.img -m bin/memdisk.tar -c resources/boot/grub/boot.cfg \
            memdisk biosdisk part_msdos part_gpt gfxterm_menu fat tar bsd memrw configfile
    fi
    yes | cp -f ${path_qemu}/ps4-softmmu/qemu-system-* ${path_bin}/
}

while [ $# -ne 0 ]
do
    arg="$1"
    case "$arg" in
        -clean)
        clean="true"
        ;;
        -disableStackProtector)
        additional_flags+="--disable-stack-protector "
        ;;
    esac
    shift
done

if [ ${clean} == "true" ]; then
    echo "Cleaning working directory..."
    cd ${path_orbital}
    cd ${path_qemu}
    make clean
    if [ $(uname -o) != "Msys" ]; then
        cd ${path_orbital}
        cd ${path_bios}
        make clean
        cd ${path_orbital}
        cd ${path_grub}
        make clean
    fi
else
    build_qemu
    if [ $(uname -o) != "Msys" ]; then
        build_bios
        build_grub
    fi
    postbuild
fi
