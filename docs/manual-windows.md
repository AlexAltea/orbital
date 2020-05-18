# Manual for Windows

## Building

Building Orbital has following absolute prerequisites:

* [Visual Studio 2019](https://visualstudio.microsoft.com/downloads/)+.
* [CMake 3.12](https://cmake.org/)+.

Additionally, install the following libraries:

* [`glslang`](https://github.com/KhronosGroup/glslang).
* [`imgui`](https://github.com/ocornut/imgui/).
* [`libzip`](https://libzip.org/).
* [`sdl2`](https://www.libsdl.org/).
* [`vulkan`](https://vulkan.lunarg.com/sdk/).
* [`zlib`](https://zlib.net/).

Although you might download them all and forward them to CMake via the
appropriate variables (e.g. `SDL2_DIR`, `IMGUI_DIR`, etc.), we recommend
to manage dependencies via [vcpkg](https://github.com/Microsoft/vcpkg).

After installing *vcpkg* and setting the `VCPKG_DEFAULT_TRIPLET` environment
variable to your desired value, i.e. `x86-windows` for 32-bit builds and
`x64-windows` for 64-bit builds, you can install the dependencies via:

```bash
vcpkg install glslang imgui libzip sdl2 vulkan zlib
```

Finally, clone this repository and initialize its submodules:

```bash
git clone https://github.com/AlexAltea/orbital
git submodule update --init
```

And build Orbital with:

```bash
mkdir -p build && cd build
cmake ..
cmake --build .
```


## Installing

1. Build *Orbital* as described previously.

2. Make sure that your system supports Intel VTX or AMD-V, and that these features are enabled.

3. Decrypt your PS4 CPU kernel, VBIOS/UBIOS, SFLASH and PUP for your current firmware. Only if you completed all previous steps independently, you may get help at our server: https://discord.me/orbitalemu.

4. Decrypt your PS4 CPU userland executables using the [Orbital Dumper](https://github.com/AlexAltea/orbital/tree/master/tools/dumper).

5. Place all these decrypted/dumped files in the `bin` folder.


## Running

Go to the `bin` folder and run *Orbital* with the command:

```bash
./orbital.exe
```


## Debugging

If you want to debug the PS4 kernel or userland executables, simply start Orbital passing the flags `-s -S` to `orbital.exe`. Then attach from GDB or IDA Pro.

**Warning:** Older versions of IDA Pro, specifically 7.0 and earlier, have a bug that removes the "Remote GDB debugger" option from debugger list after opening an existing IDA database (*.idb, *.i64). If you face this issue, export the database to an .idc script via the: *File > Produce file > Dump database to IDC file...* menu. Then, reanalyze the original ELF file, and apply the script via the: *File > Script file...* menu. This will work until you close IDA Pro. Update to the latest IDA Pro version to permanently solve this issue.
