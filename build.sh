#!/bin/bash

# Style Guide: Adhere to https://github.com/progrium/bashstyle where possible

# cd to script's directory (so that it can be run from anywhere)
cd "${0%/*}" || exit 1

# Configuration
path_bin=$(realpath ./bin)
path_bios=$(realpath ./orbital-bios)
path_grub=$(realpath ./orbital-grub)
path_orbital=$(pwd)

function print_help() {
    usage_text="Usage: $(basename "$0") [option] -- Orbital build script

options:
    -h, --help                            Show this help text
    -c, --clean                           Clean all genererated files"

    echo "$usage_text"
}

function build_bios() {
    cd "${path_bios}" || exit 1
    make "-j$(nproc)"
    mv out/bios.bin "${path_bin}/ubios.bin"
}

function build_grub() {
    cd "${path_grub}" || exit 1

    if [[ ! -e ./Makefile ]]; then
        ./autogen.sh
        ./configure --target=x86_64 --disable-werror
    fi

    make "-j$(nproc)"
}

function postbuild() {
    cd "${path_orbital}" || exit 1

    if [[ $(uname -o) != "Msys" ]]; then
        tar -c -f "${path_bin}"/memdisk.tar -C resources boot
        "${path_grub}"/grub-mkimage -d "${path_grub}"/grub-core \
            -O i386-pc -o bin/boot.img -m bin/memdisk.tar -c resources/boot/grub/boot.cfg \
            memdisk biosdisk part_msdos part_gpt gfxterm_menu fat tar bsd memrw configfile
    fi
}

function build_all() {
    if [[ $(uname -o) != "Msys" ]]; then
        build_bios
        build_grub
    fi
    postbuild
}

function clean_all() {
    echo "Cleaning working directory..."
    if [[ $(uname -o) != "Msys" ]]; then
        cd "${path_bios}" || exit 1
        make distclean
        cd "${path_grub}" || exit 1
        make distclean
    fi
}

function main() {
    # Argument parsing
    while [[ $# -ne 0 ]]
    do
        arg="$1"
        case "$arg" in
            -h|--help)
                print_help
                exit 0
                ;;
            -c|--clean)
                clean_all
                exit 0
                ;;
            *)
                echo >&2 "Invalid option \"$arg\""
                print_help
                exit 1
        esac
        shift
    done

    build_all
}

main "$@"
