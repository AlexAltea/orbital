/**
 * Aeolia DMAC device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "aeolia_dmac.h"

AeoliaDMACDevice::AeoliaDMACDevice(PCIeBus* bus, const AeoliaDMACDeviceConfig& config)
    : PCIeDevice(bus, config) {
    // Define BARs
    bar0 = new MemorySpace(this, 0x1000, {
        static_cast<MemorySpaceReadOp>(&AeoliaDMACDevice::bar0_read),
        static_cast<MemorySpaceWriteOp>(&AeoliaDMACDevice::bar0_write),
    });
    bar2 = new MemorySpace(this, 0x1000, {
        static_cast<MemorySpaceReadOp>(&AeoliaDMACDevice::bar2_read),
        static_cast<MemorySpaceWriteOp>(&AeoliaDMACDevice::bar2_write),
    });

    // Register BARs
    register_bar(0, PCI_BASE_ADDRESS_SPACE_MEM, bar0);
    register_bar(2, PCI_BASE_ADDRESS_SPACE_MEM, bar2);

#if 0
    msi_init(dev, 0x50, 1, true, false, NULL);
    if (pci_is_express(dev)) {
        pcie_endpoint_cap_init(dev, 0x70);
    }
#endif

    reset();
}

AeoliaDMACDevice::~AeoliaDMACDevice() {
    delete bar0;
    delete bar2;
}

void AeoliaDMACDevice::reset() {
    // PCI Configuration Space
    auto& header = config_header();
    header.command = PCI_COMMAND_MEMORY; // TODO: Is this needed?
    header.header_type |= PCI_HEADER_TYPE_MULTI_FUNCTION;
    header.class_prog = 0x05;

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
}

U64 AeoliaDMACDevice::bar0_read(U64 addr, U64 size) {
    //assert_always("Unimplemented");
    return 0;
}

void AeoliaDMACDevice::bar0_write(U64 addr, U64 value, U64 size) {
    //assert_always("Unimplemented");
}

U64 AeoliaDMACDevice::bar2_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void AeoliaDMACDevice::bar2_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}
