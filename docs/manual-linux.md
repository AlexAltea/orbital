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
2. Clone this repository and initialize its submodules:
```
   git clone https://github.com/AlexAltea/orbital
   git submodule update --init
```
3. Run `./build.sh`.

**Note**:   After running the `build.sh` script you may encounter errors similar to this:
```
    cp: cannot stat '/home/user/orbital/orbital-qemu/ps4-softmmu/qemu-system-*': No such file or directory
    cp: cannot stat '/home/user/orbital/orbital-qemu/pc-bios/optionrom/multiboot.bin': No such file or directory
```
For the second error: 
1. Copy `multiboot.bin` from orbital-qemu/pc-bios/ where it probably will be, to `orbital/bin/`

For the first error:
1. Go to the `orbital-qemu` directory and run `./configure`
    If you get this error message:
    ```
        ERROR: libcheck failed
        Make sure to have the libzip libs and headers installed.
    ```
    Then you are probably running `libzip 1.1.2-1.1`. But we need `<= libzip 1.3.1 `. 
    
2. So download the latest version of libzip from here: https://libzip.org/download/ and run the following commands:
    ```
        tar -xzf libzip-x.y.z.tar.gz
        cd libzip-x.y.z
        mkdir build
        cd build
        cmake ..
        make
        sudo make install
     ```
     Note here, `x,y,z` are the version number. For example if you have downloaded `libzip-1.5.1.tar.gz` then `x=1,y=5,z=1`.
     
3. Now go to the `orbital-qemu` directory and open `configure` file with any text editor.

4. Find the line `if compile_prog "" "-lzip" ; then` and replace it with `if compile_prog "-I /usr/local/include -L /usr/local/" "-lzip" ; then`.

5. Now go to the `orbital` directory and run `./build.sh -c` and then `./build.sh`.

## Installing

1. Build *Orbital* as described previously.

2. Build and install *Intel HAXM* (Orbital fork) from: https://github.com/AlexAltea/haxm/tree/orbital.

3. Decrypt your PS4 CPU kernel, VBIOS/UBIOS, SFLASH and PUP for your current firmware. Only if you completed all previous steps independently, you may get help at our server: https://discord.me/orbitalemu.

4. Decrypt your PS4 CPU userland executables using the [Orbital Dumper](https://github.com/AlexAltea/orbital/tree/master/tools/dumper).

5. Place all these decrypted/dumped files in the `bin` folder.


## Running

Go to the `bin` folder and run *Orbital* with the command:

```bash
./run.sh -accel hax
```

If you encounter any issues you might try instead:

```bash
./run.sh -accel tcg
```

Note that the `./run.sh` script forwards any arguments to QEMU, thus refer to the QEMU documentation for further information.
