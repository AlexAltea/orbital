/**
 * Aeolia AHCI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "aeolia_ahci.h"

constexpr U32 AEOLIA_AHCI_BAR_IDP = 4;
constexpr U32 AEOLIA_AHCI_BAR_MEM = 5;

AeoliaAHCIDevice::AeoliaAHCIDevice(PCIBus* bus, const AeoliaAHCIDeviceConfig& config)
    : PCIDevice(bus, config) {

    // Create AHCI device
    Interrupt* irq = allocate_irq();
    ahci = new AHCIDevice(this, _machine->mem(), irq);

    // Register BARs
    register_bar(AEOLIA_AHCI_BAR_IDP, PCI_BASE_ADDRESS_SPACE_IO, ahci->_idp);
    register_bar(AEOLIA_AHCI_BAR_MEM, PCI_BASE_ADDRESS_SPACE_MEM, ahci->_mem);

    reset();
}

AeoliaAHCIDevice::~AeoliaAHCIDevice() {
    delete ahci;
}

void AeoliaAHCIDevice::reset() {
    // PCI Configuration Space
    auto& header = config_header();
    header.command = PCI_COMMAND_IO | PCI_COMMAND_MEMORY; // TODO: Is this needed?
    header.header_type |= PCI_HEADER_TYPE_MULTI_FUNCTION;
    header.class_prog = 0x02;

    ahci->reset();
}
