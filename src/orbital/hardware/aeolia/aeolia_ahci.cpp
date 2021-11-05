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

AeoliaAHCIDevice::AeoliaAHCIDevice(PCIeBus* bus, const AeoliaAHCIDeviceConfig& config)
    : PCIeDevice(bus, config) {

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

    ahci->reset();
}
