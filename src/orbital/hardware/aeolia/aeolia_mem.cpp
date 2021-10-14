/**
 * Aeolia memory device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "aeolia_mem.h"

AeoliaMemDevice::AeoliaMemDevice(PCIBus* bus, const AeoliaMemDeviceConfig& config)
    : PCIDevice(bus, config) {
    // Define BARs
    bar0 = new MemorySpace(this, 0x1000, {
        static_cast<MemorySpaceReadOp>(&AeoliaMemDevice::bar0_read),
        static_cast<MemorySpaceWriteOp>(&AeoliaMemDevice::bar0_write),
    });
    bar2 = new MemorySpace(this, 0x40000000, {
        static_cast<MemorySpaceReadOp>(&AeoliaMemDevice::bar2_read),
        static_cast<MemorySpaceWriteOp>(&AeoliaMemDevice::bar2_write),
    });
    bar4 = new MemorySpace(this, 0x100000, {
        static_cast<MemorySpaceReadOp>(&AeoliaMemDevice::bar4_read),
        static_cast<MemorySpaceWriteOp>(&AeoliaMemDevice::bar4_write),
    });
    spm = new MemorySpace(this, 0x40000);

    // Register BARs
    register_bar(0, PCI_BASE_ADDRESS_SPACE_MEM, bar0);
    register_bar(2, PCI_BASE_ADDRESS_SPACE_MEM, bar2);
    register_bar(4, PCI_BASE_ADDRESS_SPACE_MEM, bar4);
    register_bar(5, PCI_BASE_ADDRESS_SPACE_MEM, spm);

    reset();
}

AeoliaMemDevice::~AeoliaMemDevice() {
    delete bar0;
    delete bar2;
    delete bar4;
    delete spm;
}

void AeoliaMemDevice::reset() {
    // PCI Configuration Space
    auto& header = config_header();
    header.command = PCI_COMMAND_MEMORY; // TODO: Is this needed?
    header.header_type |= PCI_HEADER_TYPE_MULTI_FUNCTION;
    header.class_prog = 0x06;
}

U64 AeoliaMemDevice::bar0_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void AeoliaMemDevice::bar0_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}

U64 AeoliaMemDevice::bar2_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void AeoliaMemDevice::bar2_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}

U64 AeoliaMemDevice::bar4_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void AeoliaMemDevice::bar4_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}
