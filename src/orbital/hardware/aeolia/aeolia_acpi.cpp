/**
 * Aeolia ACPI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "aeolia_acpi.h"

constexpr U32 AEOLIA_V1 = 0x00000100;
constexpr U32 AEOLIA_V2 = 0x00000200;
constexpr U32 AEOLIA_V3 = 0x00000300;
constexpr U32 AEOLIA_V4 = 0x01000100;
constexpr U32 AEOLIA_V5 = 0x01000200;
constexpr U32 AEOLIA_V6 = 0x02000100;
constexpr U32 AEOLIA_V7 = 0x10000100;
constexpr U32 AEOLIA_V8 = 0x10000200;
constexpr U32 AEOLIA_V9 = 0x10000201;

AeoliaACPIDevice::AeoliaACPIDevice(PCIeBus* bus, const AeoliaACPIDeviceConfig& config)
    : PCIeDevice(bus, config) {
    // Define BARs
    mem = new MemorySpace(this, 0x2000000, {
        static_cast<MemorySpaceReadOp>(&AeoliaACPIDevice::mem_read),
        static_cast<MemorySpaceWriteOp>(&AeoliaACPIDevice::mem_write),
    });
    io = new MemorySpace(this, 0x100, {
        static_cast<MemorySpaceReadOp>(&AeoliaACPIDevice::io_read),
        static_cast<MemorySpaceWriteOp>(&AeoliaACPIDevice::io_write),
    });

    // Register BARs
    register_bar(0, PCI_BASE_ADDRESS_SPACE_MEM, mem);
    register_bar(2, PCI_BASE_ADDRESS_SPACE_IO, io);

    reset();
}

AeoliaACPIDevice::~AeoliaACPIDevice() {
    delete mem;
    delete io;
}

void AeoliaACPIDevice::reset() {
    // PCI Configuration Space
    auto& header = config_header();
    header.command = PCI_COMMAND_IO | PCI_COMMAND_MEMORY; // TODO: Is this needed?
    header.header_type |= PCI_HEADER_TYPE_MULTI_FUNCTION;
    header.class_prog = 0x00;

    // Add PCIe capability
    // TODO: Refactor this code
    const auto cap_off = add_capability(PCI_CAP_ID_EXP, 0x14 /* V1 */);
    (U16&)config_data[cap_off +  2 /*PCI_EXP_FLAGS*/ ] = 0x0001;
    (U32&)config_data[cap_off +  4 /*PCI_EXP_DEVCAP*/] = 0;
    (U16&)config_data[cap_off +  8 /*PCI_EXP_DEVCTL*/] = 0;
    (U16&)config_data[cap_off + 10 /*PCI_EXP_DEVSTA*/] = 0;
    (U32&)config_data[cap_off + 12 /*PCI_EXP_LNKCAP*/] = 0;
    (U16&)config_data[cap_off + 16 /*PCI_EXP_LNKCTL*/] = 0;
    (U16&)config_data[cap_off + 18 /*PCI_EXP_LNKSTA*/] = 0;

    constexpr U32 aeolia_version = AEOLIA_V3;
    (U32&)config_data[0x064] = aeolia_version; // HACK: We don't support MSR-based PCIe config space access, so 0x164 becomes 0x64.
    (U32&)config_data[0x164] = aeolia_version;
}

U64 AeoliaACPIDevice::mem_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void AeoliaACPIDevice::mem_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}

U64 AeoliaACPIDevice::io_read(U64 addr, U64 size) {
    //assert_always("Unimplemented");
    return 0;
}

void AeoliaACPIDevice::io_write(U64 addr, U64 value, U64 size) {
    //assert_always("Unimplemented");
}
