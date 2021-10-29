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

constexpr U32 AMEM_SPM_VERSION_MAJOR = 0x12010;
constexpr U32 AMEM_SPM_VERSION_MINOR = 0x12011;
constexpr U32 AMEM_SPM_VERSION_REV   = 0x12012;

AeoliaMemDevice::AeoliaMemDevice(PCIeBus* bus, const AeoliaMemDeviceConfig& config)
    : PCIeDevice(bus, config) {
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

    // Init SPM
    auto data = reinterpret_cast<U08*>(spm->ptr());

    // Subsystem ID
    // Written in big-endian. Hardcoded to 0x10200 for now.
    // - 0x1XXXX  Aeolia
    // - 0x2XXXX  Belize
    // - 0x3XXXX  Baikal
    // - 0x4XXXX  Belize
    data[AMEM_SPM_VERSION_MAJOR] = 0x1;
    data[AMEM_SPM_VERSION_MINOR] = 0x2;
    data[AMEM_SPM_VERSION_REV] = 0x0;
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
