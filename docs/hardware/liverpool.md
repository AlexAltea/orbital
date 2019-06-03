Liverpool
=========

## GC

* 2 micro-engines.
* 4 pipes.
* 8 queues.
* 16 VM IDs.

### MMIO Registers

- Registers instanced by me,pipe,queue (specified by address):
  + 0xC900 - 0xC990
  + 0xC20C
  + ???
- Registers instanced by vmid (specified by address):
  + ???

### VM IDs

- 0: System.
- 1: User (Game).
- 2-14: User (VSH).
- 14: System (Screenshot?).
- 15: System (SBL/SAMU).

### IH IDs

- 0x00-0x2F: DCE Interrupt (`dce_interrupt`).
	- 0x08: DCE Page Flip 0
	- 0x0A: DCE Page Flip 1
	- 0x0C: DCE Page Flip 2 (unused)
	- 0x0E: DCE Page Flip 3 (unused)
	- 0x10: DCE Page Flip 4 (unused)
	- 0x12: DCE Page Flip 5 (unused)
	- 0x13: DCE CRTC Line
		- data=8: Line 1.
		- data=9: Line 2.
- 0x34-0x35: DCE Interrupt Scanin (`dce_interrupt_scanin`).
	- 0x34: DCE Scanin:
		- data=8: MFIC.
	- 0x35: DCE Scanin:
	    - data=0: Host conflict.
		- data=1: Data overflow.
- 0x60: SRBM Timeout (`sub_FFFFFFFF826DFFA0` @ 5.00).
- 0x8C: CP Interrupt (`sub_FFFFFFFF826ED420` @ 5.00).
- 0x8D: CP Interrupt (`sub_FFFFFFFF826ED420` @ 5.00).
- 0x92: CP Interrupt (`sub_FFFFFFFF826ED420` @ 5.00).
- 0x93: CP Interrupt (`sub_FFFFFFFF826ED420` @ 5.00).
- 0x98: SAM (`sub_FFFFFFFF8281CD20` @ 5.00).
- 0xA2: ACP (`sub_FFFFFFFF82786190` @ 5.00).
- 0xB4: CP Interrupt (`sub_FFFFFFFF826ED420` @ 5.00).
- 0xB5: ??? (`sub_FFFFFFFF826E6380` @ 5.00).
- 0xB7: CP Interrupt (`sub_FFFFFFFF826ED420` @ 5.00).
- 0xB8: CP Interrupt (`sub_FFFFFFFF826ED420` @ 5.00).
- 0xB9: CP Interrupt (`sub_FFFFFFFF826ED420` @ 5.00).
- 0xE0: ??? (`sub_FFFFFFFF827D4EF0` @ 5.00).
- 0xE9: ??? (`sub_FFFFFFFF826E1EF0` @ 5.00).
- 0xE9: ??? (`sub_FFFFFFFF826E1EF0` @ 5.00).
- 0xEF: ??? (`sub_FFFFFFFF826E6380` @ 5.00).
- 0xF0: ??? (`sub_FFFFFFFF827D4EF0` @ 5.00).
- 0xF3: ??? (`sub_FFFFFFFF827D4EF0` @ 5.00).
- 0xF5: ??? (`sub_FFFFFFFF827D4EF0` @ 5.00).

### Glossary

| Name   | Description                                                         |
|--------|---------------------------------------------------------------------|
| _BIF_  | Bus Interface.                                                      |
| _CB_   | Color Buffer.                                                       |
| _CP_   | Command Processor.                                                  |
| _CPC_  | Command Processor for Compute.                                      |
| _CPF_  | Command Processor Fetcher.                                          |
| _CPG_  | Command Processor for Graphics.                                     |
| _CRTC_ | CRT Controller.                                                     |
| _DB_   | Depth Buffer.                                                       |
| _DCE_  | Display Core Engine.                                                |
| _DCP_  | ???                                                                 |
| _GCA_  | Graphics/Compute Array (same as GFX?).                              |
| _GDS_  | Global Data Share.                                                  |
| _GFX_  | Graphics/Compute Engine (same as GCA?).                             |
| _GMC_  | Graphics Memory Controller.                                         |
| _GRBM_ | Graphics Register Backbone Manager.                                 |
| _IA_   | Input Assembly.                                                     |
| _IH_   | Interrupt Handler.                                                  |
| _LDS_  | Local Data Share.                                                   |
| _MC_   | Memory Controller.                                                  |
| _PA_   | Primitive Assembly.                                                 |
| _RB_   | Ring Buffer.                                                        |
| _RLC_  | Run List Controller.                                                |
| _SAMU_ | Secure Asset Management Unit.                                       |
| _SC_   | Scan Converter.                                                     |
| _SDMA_ | System Direct Memory Access.                                        |
| _SMC_  | System Management Controller.                                       |
| _SPI_  | Shader Processor Input.                                             |
| _SRBM_ | System Register Backbone Manager.                                   |
| _SX_   | Shader Export.                                                      |
| _TA_   | Texture Addressing.                                                 |
| _UVD_  | Universal Video Decoder.                                            |
| _VCE_  | Video Compression Engine.                                           |
| _VGT_  | Vertex Geometry Tesselator.                                         |
| _WD_   | Work Distributor.                                                   |
|        |                                                                     |

### PCI Configuration Space

```
00:01.0 VGA compatible controller: Advanced Micro Devices, Inc. [AMD/ATI] Liverpool [Playstation 4 APU] (prog-if 00 [VGA controller])
	Subsystem: Advanced Micro Devices, Inc. [AMD/ATI] Liverpool [Playstation 4 APU]
	Control: I/O+ Mem+ BusMaster+ SpecCycle- MemWINV- VGASnoop- ParErr- Stepping- SERR- FastB2B- DisINTx+
	Status: Cap+ 66MHz- UDF- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
	Latency: 0, Cache Line Size: 64 bytes
	Interrupt: pin A routed to IRQ 30
	Region 0: Memory at e0000000 (64-bit, prefetchable) [size=64M]
	Region 2: Memory at e4000000 (64-bit, prefetchable) [size=8M]
	Region 4: I/O ports at 6000 [size=256]
	Region 5: Memory at e4800000 (32-bit, non-prefetchable) [size=256K]
	[virtual] Expansion ROM at f8000000 [disabled] [size=128K]
	Capabilities: [50] Power Management version 3
		Flags: PMEClk- DSI- D1+ D2+ AuxCurrent=0mA PME(D0-,D1+,D2+,D3hot+,D3cold-)
		Status: D0 NoSoftRst- PME-Enable- DSel=0 DScale=0 PME-
	Capabilities: [58] Express (v2) Root Complex Integrated Endpoint, MSI 00
		DevCap:	MaxPayload 256 bytes, PhantFunc 0
			ExtTag+ RBE+
		DevCtl:	Report errors: Correctable- Non-Fatal- Fatal- Unsupported-
			RlxdOrd+ ExtTag- PhantFunc- AuxPwr- NoSnoop+
			MaxPayload 128 bytes, MaxReadReq 512 bytes
		DevSta:	CorrErr- UncorrErr- FatalErr- UnsuppReq- AuxPwr- TransPend-
		DevCap2: Completion Timeout: Not Supported, TimeoutDis-, LTR-, OBFF Not Supported
		DevCtl2: Completion Timeout: 50us to 50ms, TimeoutDis-, LTR-, OBFF Disabled
	Capabilities: [a0] MSI: Enable+ Count=1/1 Maskable- 64bit+
		Address: 00000000feeff00c  Data: 4173
	Capabilities: [100 v1] Vendor Specific Information: ID=0001 Rev=1 Len=010 <?>
	Capabilities: [270 v1] #19
	Kernel driver in use: radeon
00: 02 10 20 99 07 04 10 00 00 00 00 03 10 00 80 00
10: 0c 00 00 e0 00 00 00 00 0c 00 00 e4 00 00 00 00
20: 01 60 00 00 00 00 80 e4 00 00 00 00 02 10 20 99
30: 00 00 00 00 50 00 00 00 00 00 00 00 ff 01 00 00
40: 00 00 00 00 00 00 00 00 00 00 00 00 02 10 20 99
50: 01 58 03 76 00 00 00 00 10 a0 92 00 a1 81 00 00
60: 10 28 00 00 00 00 00 00 00 00 00 00 00 00 00 00
70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
a0: 05 00 81 00 0c f0 ef fe 00 00 00 00 73 41 00 00
b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

## HDAC

### PCI Configuration Space

```
00:01.1 Audio device: Advanced Micro Devices, Inc. [AMD/ATI] Liverpool HDMI/DP Audio Controller
	Subsystem: Ncipher Corp Ltd Liverpool HDMI/DP Audio Controller
	Control: I/O+ Mem+ BusMaster+ SpecCycle- MemWINV- VGASnoop- ParErr- Stepping- SERR- FastB2B- DisINTx+
	Status: Cap+ 66MHz- UDF- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
	Latency: 0, Cache Line Size: 64 bytes
	Interrupt: pin B routed to IRQ 29
	Region 0: Memory at e4840000 (64-bit, non-prefetchable) [size=16K]
	Capabilities: [50] Power Management version 3
		Flags: PMEClk- DSI- D1+ D2+ AuxCurrent=0mA PME(D0-,D1-,D2-,D3hot-,D3cold-)
		Status: D0 NoSoftRst- PME-Enable- DSel=0 DScale=0 PME-
	Capabilities: [58] Express (v2) Root Complex Integrated Endpoint, MSI 00
		DevCap:	MaxPayload 256 bytes, PhantFunc 0
			ExtTag+ RBE+
		DevCtl:	Report errors: Correctable- Non-Fatal- Fatal- Unsupported-
			RlxdOrd+ ExtTag- PhantFunc- AuxPwr- NoSnoop+
			MaxPayload 128 bytes, MaxReadReq 512 bytes
		DevSta:	CorrErr- UncorrErr- FatalErr- UnsuppReq- AuxPwr- TransPend-
		DevCap2: Completion Timeout: Not Supported, TimeoutDis-, LTR-, OBFF Not Supported
		DevCtl2: Completion Timeout: 50us to 50ms, TimeoutDis-, LTR-, OBFF Disabled
	Capabilities: [a0] MSI: Enable+ Count=1/1 Maskable- 64bit+
		Address: 00000000feeff00c  Data: 4163
	Capabilities: [100 v1] Vendor Specific Information: ID=0001 Rev=1 Len=010 <?>
	Kernel driver in use: snd_hda_intel
00: 02 10 21 99 07 04 10 00 00 00 03 04 10 00 80 00
10: 04 00 84 e4 00 00 00 00 00 00 00 00 00 00 00 00
20: 00 00 00 00 00 00 00 00 00 00 00 00 00 01 aa 00
30: 00 00 00 00 50 00 00 00 00 00 00 00 ff 02 00 00
40: 00 00 00 00 00 00 00 00 00 00 00 00 00 01 aa 00
50: 01 58 03 06 00 00 00 00 10 a0 92 00 a1 81 00 00
60: 10 28 00 00 00 00 00 00 00 00 00 00 00 00 00 00
70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
a0: 05 00 81 00 0c f0 ef fe 00 00 00 00 63 41 00 00
b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

## References

1. https://www.x.org/wiki/RadeonFeature/
