# Manual for Linux

## Building

1. Install the following dependencies (if using apt on Ubuntu):
    ```
    # Common dependencies
    sudo apt -qq install \
        git python

    # Dependencies for orbital-grub
    sudo apt -qq install \
        dh-autoreconf bison flex

    # Dependencies for orbital-qemu
    sudo apt -qq install \
        zlib1g-dev libglib2.0-dev libfdt-dev libpixman-1-dev libsdl2-dev \
        libvulkan-dev libzip-dev
    ```

2. Run `./build.sh`.
