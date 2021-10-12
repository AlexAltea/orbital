/**
 * Aeolia PCIe device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "aeolia_pcie.h"

AeoliaPCIeDevice::AeoliaPCIeDevice(PCIBus* bus, const AeoliaPCIeDeviceConfig& config)
    : PCIDevice(bus, config) {
    // Define BARs
    bar0 = new MemorySpace(this, 0x100000, {
        static_cast<MemorySpaceReadOp>(&AeoliaPCIeDevice::bar0_read),
        static_cast<MemorySpaceWriteOp>(&AeoliaPCIeDevice::bar0_write),
    });
    bar2 = new MemorySpace(this, 0x8000, {
        static_cast<MemorySpaceReadOp>(&AeoliaPCIeDevice::bar2_read),
        static_cast<MemorySpaceWriteOp>(&AeoliaPCIeDevice::bar2_write),
    });
    mmio_peripherals = new MemorySpace(this, 0x200000, {
        static_cast<MemorySpaceReadOp>(&AeoliaPCIeDevice::peripherals_read),
        static_cast<MemorySpaceWriteOp>(&AeoliaPCIeDevice::peripherals_write),
    });

    // Register BARs
    register_bar(0, PCI_BASE_ADDRESS_SPACE_MEM, bar0);
    register_bar(2, PCI_BASE_ADDRESS_SPACE_MEM, bar2);
    register_bar(4, PCI_BASE_ADDRESS_SPACE_MEM, mmio_peripherals);

    reset();
}

AeoliaPCIeDevice::~AeoliaPCIeDevice() {
}

void AeoliaPCIeDevice::reset() {
    // PCI Configuration Space
    auto& header = config_header();
    header.header_type |= PCI_HEADER_TYPE_MULTI_FUNCTION;
    header.class_prog = 0x04;
}

U64 AeoliaPCIeDevice::bar0_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void AeoliaPCIeDevice::bar0_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}

U64 AeoliaPCIeDevice::bar2_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void AeoliaPCIeDevice::bar2_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}

U64 AeoliaPCIeDevice::peripherals_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void AeoliaPCIeDevice::peripherals_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}
