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
    HDAC_UNK60 = 0x60, // Command?
    HDAC_UNK64 = 0x64, // Size?
    HDAC_UNK68 = 0x68, // Flags?
};

LiverpoolHDACDevice::LiverpoolHDACDevice(PCIBus* bus, const LiverpoolHDACDeviceConfig& config)
    : PCIDevice(bus, config) {
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
}

U64 LiverpoolHDACDevice::mmio_read(U64 addr, U64 size) {
    U64 value = 0;
    assert_always("Unimplemented");

    switch (addr) {
    case HDAC_UNK68:
        value = 0;
        break;
    }
    return value;
}

void LiverpoolHDACDevice::mmio_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}
