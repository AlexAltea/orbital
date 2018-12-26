# Manual for Windows

## Building

1. Install [MSYS2](https://www.msys2.org/). If you want to use the WHPX accelerator, install the latest [Windows 10 SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk) as well.

2. Open MSYS2 and install the following dependencies:
    ```
    pacman -Syu
    pacman -S git python2
    pacman -S mingw-w64-x86_64-toolchain base-devel
    pacman -S mingw-w64-x86_64-glib2 mingw-w64-x86_64-gtk3
    pacman -S mingw-w64-x86_64-vulkan mingw-w64-x86_64-SDL2
    pacman -S mingw-w64-x86_64-libzip
    ```

3. Run the following commands to setup a proper environment:
    ```bash
    # Prepare Python
    ln -s /usr/bin/python2 /usr/bin/python

    # Copy WHPX headers and libraries (only if you want to use WHPX!)
    WINSDK="/c/Program Files (x86)/Windows Kits/10"
    WINSDKVER=10.0.17134.0
    cp "$WINSDK/Include/$WINSDKVER/um/"WinHv* /mingw64/include
    cp "$WINSDK/Lib/$WINSDKVER/um/x64/"WinHv* /mingw64/lib

    # Fix envsubst-related issue
    mv /mingw64/bin/envsubst.exe /mingw64/bin/envsubst.exe.bak
    ln -s /usr/bin/envsubst.exe /mingw64/bin/envsubst.exe
    ```

4. Add the following lines to `~/.bashrc`:
    ```
    export PATH=/mingw64/bin/:$PATH
    CPPFLAGS=-I/mingw64/include
    LDFLAGS=-L/mingw64/lib
    ```

5. Clone this repository and initialize its submodules:
    ```
    git clone https://github.com/AlexAltea/orbital
    git submodule update --init
    ```

6. Run `./build.sh`.
