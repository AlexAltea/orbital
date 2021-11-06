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

AeoliaSDHCIDevice::AeoliaSDHCIDevice(PCIeBus* bus, const AeoliaSDHCIDeviceConfig& config)
    : PCIeDevice(bus, config) {
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
    msi_enable(1, true);

    // Add PCIe capability
    // TODO: Refactor this code
    const auto cap_off = add_capability(PCI_CAP_ID_EXP, 0x14 /* V1 */, 0x70);
    (U16&)config_data[cap_off +  2 /*PCI_EXP_FLAGS*/ ] = 0x0001;
    (U32&)config_data[cap_off +  4 /*PCI_EXP_DEVCAP*/] = 0;
    (U16&)config_data[cap_off +  8 /*PCI_EXP_DEVCTL*/] = 0;
    (U16&)config_data[cap_off + 10 /*PCI_EXP_DEVSTA*/] = 0;
    (U32&)config_data[cap_off + 12 /*PCI_EXP_LNKCAP*/] = 0;
    (U16&)config_data[cap_off + 16 /*PCI_EXP_LNKCTL*/] = 0;
    (U16&)config_data[cap_off + 18 /*PCI_EXP_LNKSTA*/] = 0;
}

U64 AeoliaSDHCIDevice::mmio_read(U64 addr, U64 size) {
    U64 value = 0;
    assert_always("Unimplemented");

    return value;
}

void AeoliaSDHCIDevice::mmio_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}
