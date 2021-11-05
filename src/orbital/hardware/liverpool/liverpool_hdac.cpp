/**
 * Liverpool HD Audio Controller (HDAC) PCI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "liverpool_hdac.h"

enum {
    HDAC_UNK08 = 0x08,
    /* The following three registers are involved in muting audio */
    HDAC_UNK60 = 0x60, // Command?
    HDAC_UNK64 = 0x64, // Size?
    HDAC_UNK68 = 0x68, // Flags?
};

// During the muting audio phase, following values are passed to HDAC_UNK60
// 377703h 377823h 377943h 377A63h
// 577703h 577823h 577943h 577A63h
// 777703h 777823h 777943h 777A63h

LiverpoolHDACDevice::LiverpoolHDACDevice(PCIeBus* bus, const LiverpoolHDACDeviceConfig& config)
    : PCIeDevice(bus, config) {
    // Define BARs
    mmio = new MemorySpace(this, 0x4000, {
        static_cast<MemorySpaceReadOp>(&LiverpoolHDACDevice::mmio_read),
        static_cast<MemorySpaceWriteOp>(&LiverpoolHDACDevice::mmio_write),
    });

    // Register BARs
    register_bar(0, PCI_BASE_ADDRESS_SPACE_MEM, mmio);

    reset();
}

LiverpoolHDACDevice::~LiverpoolHDACDevice() {
}

void LiverpoolHDACDevice::reset() {
    // PCI Configuration Space
    auto& header = config_header();
    header.command = PCI_COMMAND_MEMORY; // TODO: Is this needed?
    header.header_type |= PCI_HEADER_TYPE_MULTI_FUNCTION;
    header.intr_line = 0xFF;
    header.intr_pin = 0x02;
    msi_enable(1, true);
}

U64 LiverpoolHDACDevice::mmio_read(U64 addr, U64 size) {
    U64 value = 0;

    switch (addr) {
    case HDAC_UNK08:
        value = 0;
        break;
    case HDAC_UNK68:
        value = 0;
        break;
    default:
        assert_always("Unimplemented");
        // TODO: Previous implementation was memory-like.
    }
    return value;
}

void LiverpoolHDACDevice::mmio_write(U64 addr, U64 value, U64 size) {
    switch (addr) {
    case HDAC_UNK08:
        break;
    default:
        assert_always("Unimplemented");
        // TODO: Previous implementation was memory-like.
    }
}
