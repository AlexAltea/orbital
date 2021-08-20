# Manual for Linux

## Building

Building Orbital has following absolute prerequisites:

* GCC/Clang 9.0+.
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
vcpkg install glslang imgui libzip sdl2[vulkan] vulkan zlib
```

Alternatively, you can install these dependencies with your package manager:
* Ubuntu:
    ```bash
    sudo apt install -qq glslang-dev libsdl2-dev libvulkan-dev libzip-dev zlib1g-dev
    ```
* Arch Linux:
    ```bash
    sudo pacman -S glslang libzip sdl2 vulkan-validation-layers vulkan-icd-loader vulkan-headers zlib
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

3. TBD. (You need to legally own a PS4 console for this step).

4. Place this file in the `bin/crypto` folder.


## Running

Go to the `bin` folder and run *Orbital* with the command:

```bash
./orbital
```

On your first run: you will be asked to create a new virtual PS4 console, and optionally,
to specify a recovery PUP to boot from.


## Debugging

TBD.
