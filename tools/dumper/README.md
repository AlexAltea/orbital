Orbital Dumper
==============

Dumper to dump/extract files required by Orbital from an actual PlayStation 4 console.
The dumper currently supports PS4 FW ver 1.76, 4.55, 5.00, 5.05.

## Usage

1. Connect your computer and PS4 to the same network.

2. Setup [ps4-payload-sdk](https://github.com/xvortex/ps4-payload-sdk/). 

3. Before building, change the IP address (`#define BLOBS_ADDR IP(192,168,2,1)`) found inside `source/blob.c` to the IP adress of the pc where the `server.py` will be running.

4. Build the payload for your firmware version with `make`. Pick one of the following supported firmware versions: 1.76, 4.55, 5.00, 5.05. For example:

    ```bash
    make 5.00
    ```

5. Start the server with:

    ```bash
    python server.py
    ```

6. Enter your computer's IP address in the PlayStation 4 web browser and follow the instructions on screen. The exploit provided by `server.py` only works for firmware 5.00. If you are on a different firmware you need to run an exploit manually and send the dumper payload using netcat/socat:

```bash
socat -u FILE:dumper.bin TCP:"PS4 IP":9020
```

## Development

This dumper requires an exploit that listens for payloads in binary format on port `9020`. These payloads need to be mapped as follows in user address space:

- `0x926200000`: Code (can be changed in `Makefile`)
- `0x926300000`: Data (can be changed in `Makefile`)
- `0x926400000`: Arguments (can be changed in `source/main.c`)

Furthermore, the server will listen at port `9021` for incoming blobs, and optionally at `9022` for debug messages.

## Compiling Notes

If you want to add support for a new FW, use one of the `source/ksdk_XXX.inc` as template and update the required offset to match that of your FW.
