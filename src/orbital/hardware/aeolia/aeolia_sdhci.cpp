/**
 * Aeolia SDHCI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "aeolia_sdhci.h"

AeoliaSDHCIDevice::AeoliaSDHCIDevice(PCIBus* bus, const AeoliaSDHCIDeviceConfig& config)
    : PCIDevice(bus, config) {
    // Define BARs
    mmio = new MemorySpace(this, 0x1000, {
        static_cast<MemorySpaceReadOp>(&AeoliaSDHCIDevice::mmio_read),
        static_cast<MemorySpaceWriteOp>(&AeoliaSDHCIDevice::mmio_write),
    });

    // Register BARs
    register_bar(0, PCI_BASE_ADDRESS_SPACE_MEM, mmio);

    reset();
}

AeoliaSDHCIDevice::~AeoliaSDHCIDevice() {
}

void AeoliaSDHCIDevice::reset() {
    // PCI Configuration Space
    auto& header = config_header();
    header.command = PCI_COMMAND_MEMORY; // TODO: Is this needed?
    header.header_type |= PCI_HEADER_TYPE_MULTI_FUNCTION;
    header.class_prog = 0x03;
}

U64 AeoliaSDHCIDevice::mmio_read(U64 addr, U64 size) {
    U64 value = 0;
    assert_always("Unimplemented");

    return value;
}

void AeoliaSDHCIDevice::mmio_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}
