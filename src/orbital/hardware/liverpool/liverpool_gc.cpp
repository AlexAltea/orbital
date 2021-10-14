/**
 * Liverpool Graphics Controller (GC/Starsha) PCI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "liverpool_gc.h"

LiverpoolGCDevice::LiverpoolGCDevice(PCIBus* bus, const LiverpoolGCDeviceConfig& config)
    : PCIDevice(bus, config) {
    // Define BARs
    bar0 = new MemorySpace(this, 0x4000000, {
        static_cast<MemorySpaceReadOp>(&LiverpoolGCDevice::bar0_read),
        static_cast<MemorySpaceWriteOp>(&LiverpoolGCDevice::bar0_write),
    });
    bar2 = new MemorySpace(this, 0x800000, {
        static_cast<MemorySpaceReadOp>(&LiverpoolGCDevice::bar2_read),
        static_cast<MemorySpaceWriteOp>(&LiverpoolGCDevice::bar2_write),
    });
    pio = new MemorySpace(this, 0x100, {
        static_cast<MemorySpaceReadOp>(&LiverpoolGCDevice::pio_read),
        static_cast<MemorySpaceWriteOp>(&LiverpoolGCDevice::pio_write),
    });
    mmio = new MemorySpace(this, 0x40000, {
        static_cast<MemorySpaceReadOp>(&LiverpoolGCDevice::mmio_read),
        static_cast<MemorySpaceWriteOp>(&LiverpoolGCDevice::mmio_write),
    });

    // Register BARs
    register_bar(0, PCI_BASE_ADDRESS_SPACE_MEM, bar0);
    register_bar(2, PCI_BASE_ADDRESS_SPACE_MEM, bar2);
    register_bar(4, PCI_BASE_ADDRESS_SPACE_IO, pio);
    register_bar(5, PCI_BASE_ADDRESS_SPACE_MEM, mmio);

    reset();
}

LiverpoolGCDevice::~LiverpoolGCDevice() {
    delete bar0;
    delete bar2;
    delete pio;
    delete mmio;
}

void LiverpoolGCDevice::reset() {
    // PCI Configuration Space
    auto& header = config_header();
    header.command = PCI_COMMAND_IO | PCI_COMMAND_MEMORY; // TODO: Is this needed?
    header.header_type |= PCI_HEADER_TYPE_MULTI_FUNCTION;
}

U64 LiverpoolGCDevice::bar0_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void LiverpoolGCDevice::bar0_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}

U64 LiverpoolGCDevice::bar2_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void LiverpoolGCDevice::bar2_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}

U64 LiverpoolGCDevice::pio_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void LiverpoolGCDevice::pio_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}

U64 LiverpoolGCDevice::mmio_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void LiverpoolGCDevice::mmio_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}
