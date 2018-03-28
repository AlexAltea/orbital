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
