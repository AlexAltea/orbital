/**
 * Aeolia XHCI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "aeolia_xhci.h"

AeoliaXHCIDevice::AeoliaXHCIDevice(PCIBus* bus, const AeoliaXHCIDeviceConfig& config)
    : PCIDevice(bus, config) {
    // Define BARs
    constexpr size_t xhci_size = 0x200000;
    xhci[0] = new MemorySpace(this, xhci_size, {
        static_cast<MemorySpaceReadOp>(&AeoliaXHCIDevice::xhci0_read),
        static_cast<MemorySpaceWriteOp>(&AeoliaXHCIDevice::xhci0_write),
    });
    xhci[1] = new MemorySpace(this, xhci_size, {
        static_cast<MemorySpaceReadOp>(&AeoliaXHCIDevice::xhci1_read),
        static_cast<MemorySpaceWriteOp>(&AeoliaXHCIDevice::xhci1_write),
    });
    xhci[2] = new MemorySpace(this, xhci_size, {
        static_cast<MemorySpaceReadOp>(&AeoliaXHCIDevice::xhci2_read),
        static_cast<MemorySpaceWriteOp>(&AeoliaXHCIDevice::xhci2_write),
    });
    
    // Register BARs
    register_bar(0, PCI_BASE_ADDRESS_SPACE_MEM, xhci[0]);
    register_bar(2, PCI_BASE_ADDRESS_SPACE_MEM, xhci[1]);
    register_bar(4, PCI_BASE_ADDRESS_SPACE_MEM, xhci[2]);

    reset();
}

AeoliaXHCIDevice::~AeoliaXHCIDevice() {
}

void AeoliaXHCIDevice::reset() {
    // PCI Configuration Space
    auto& header = config_header();
    header.command = PCI_COMMAND_MEMORY; // TODO: Is this needed?
    header.header_type |= PCI_HEADER_TYPE_MULTI_FUNCTION;
    header.class_prog = 0x30; // TODO: Is this correct?
}

U64 AeoliaXHCIDevice::xhci0_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void AeoliaXHCIDevice::xhci0_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}

U64 AeoliaXHCIDevice::xhci1_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void AeoliaXHCIDevice::xhci1_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}

U64 AeoliaXHCIDevice::xhci2_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void AeoliaXHCIDevice::xhci2_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}
