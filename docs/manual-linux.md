
# Manual for Linux

## Building

1. Install the following dependencies (depending on your distro):

####  Ubuntu
```bash
## Common dependencies
sudo apt -qq install \
    git python

## Dependencies for orbital-grub
sudo apt -qq install \
    dh-autoreconf bison flex

## Dependencies for orbital-qemu
sudo apt -qq install \
    zlib1g-dev libglib2.0-dev libfdt-dev libpixman-1-dev libsdl2-dev \
    libvulkan-dev libzip-dev

## Make sure you install *libzip-dev* v1.3.1 or later!
```

#### Arch linux
```bash
## Update
sudo pacman -Syu

## Common dependencies
sudo pacman -S \
    git python

## Dependencies for orbital-grub
curl -s https://aur.archlinux.org/cgit/aur.git/snapshot/dh-autoreconf.tar.gz | tar xvz \
    && cd dh-autoreconf && makepkg -Acsi && cd .. && rm -rf dh-autoreconf

sudo pacman -S \
    bison flex

## Dependencies for orbital-qemu
sudo pacman -S \
    zlib glib2 dtc pixman sdl2 vulkan-validation-layers \
    vulkan-icd-loader vulkan-headers libzip
```

2. Run `./build.sh`.


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
*Note that the `./run.sh` script forwards any arguments to QEMU, thus refer to the QEMU documentation for further information.*
