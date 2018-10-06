Orbital Dumper
==============

Dumper to dump/extract files required by Orbital from an actual PlayStation 4 console.

## Usage

1. Connect your computer and PS4 to the same network.

2. Setup [ps4-payload-sdk](https://github.com/xvortex/ps4-payload-sdk/) and build the payload with `make`.

3. Start the server with:

    ```bash
    python server.py
    ```

4. Enter your computer's IP address in the PlayStation 4 web browser and follow the instructions on screen.

## Development

This dumper requires an exploit that listens for payloads in binary format on port `9020`. These payloads need to be mapped as follows in user address space:

- `0x926200000`: Code (can be changed in `Makefile`)
- `0x926300000`: Data (can be changed in `Makefile`)
- `0x926400000`: Arguments (can be changed in `source/main.c`)

Furthermore, the server will listen at port `9021` for incoming blobs, and optionally at `9022` for debug messages.

## Compiling Notes

The dumper currently supports PS4 FW ver 1.76, 4.55, 5.00, 5.05.

By default the build will default to ver 5.00, but in order to compile for a different FW, you must edit the include reference (`#include "ksdk_500.inc"`) found inside `source/ksdk.c` (2 includes to edit) and `source/ksdk.h` (1 include to edit) to match the desired FW.  

If you want to add support for a new FW, use one of the `source/ksdk_XXX.inc` as template and update the required offset to match that of your FW.
