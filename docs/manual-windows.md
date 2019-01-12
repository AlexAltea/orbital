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


## Debugging

### Host Debugging

If you want to debug the *Orbital* emulator itself from Windows, we recommand install [Visual Studio](https://visualstudio.microsoft.com/), and generating a *.PDB* file for the executable, by using [cv2pdb](https://github.com/rainers/cv2pdb). Then debug the executable as usual within Visual Studio.

### Guest Debugging

If you want to debug the PS4 kernel or userland executables, simply start Orbital passing the flags `-s -S` to `./run.sh`. Then attach from GDB or IDA Pro. there's slight differences depending on which QEMU accelerator you are using:

* _TCG_: You might use hardware and software breakpoints at any virtual addresses. Everything works as expected.

* _HAXM_: Software breakpoints might fail if the virtual address they target is being written to by the guest software. Thus, you should always start with hardware breakpoints, and then continue with software breakpoints. Note that memory breakpoints/watchpoints do not work at the moment.

**Warning:** Older versions of IDA Pro, specifically 7.0 and earlier, have a bug that removes the "Remote GDB debugger" option from debugger list after opening an existing IDA database (*.idb, *.i64). If you face this issue, export the database to an .idc script via the: *File > Produce file > Dump database to IDC file...* menu. Then, reanalyze the original ELF file, and apply the script via the: *File > Script file...* menu. This will work until you close IDA Pro. Update to the latest IDA Pro version to permanently solve this issue.
