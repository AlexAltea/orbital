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

AeoliaACPIDevice::AeoliaACPIDevice(PCIBus* bus, const AeoliaACPIDeviceConfig& config)
    : PCIDevice(bus, config) {
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
