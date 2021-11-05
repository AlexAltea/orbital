/**
 * Liverpool PCI Host/Bus devices.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "liverpool_pci.h"

 // Liverpool Bus
LiverpoolBus::LiverpoolBus(Device* parent, IOAPICDevice* ioapic, const PCIeBusConfig& config)
    : PCIeBus(parent, config), ioapic(ioapic) {}

LiverpoolBus::~LiverpoolBus() {}

void LiverpoolBus::set_irq(void* opaque, int pirq, int level) {
    const int gsi = pirq + 16; // TODO

    auto* irq = ioapic->irq(gsi);
    irq->set(level);
}

int LiverpoolBus::map_irq(PCI_DF df, int intx) {
    int pirq = ((df.d + intx) % 4) + 4; // TODO
    return 0;
}

void LiverpoolBus::route_irq(PCIDevice* opaque, int pin) {
    assert_always("Unimplemented");
}

// Liverpool Host
LiverpoolHost::LiverpoolHost(Device* parent, IOAPICDevice* ioapic, const PCIeHostConfig& config)
    : PCIeHost(parent, config) {
    // Create PCIe bus
    _bus = new LiverpoolBus(this, ioapic);

    // Create PCI IO ports
    const MemorySpaceOps config_data_ops = {
        static_cast<MemorySpaceReadOp>(&LiverpoolHost::config_read),
        static_cast<MemorySpaceWriteOp>(&LiverpoolHost::config_write),
    };
    ContainerSpace* io = _machine->io();
    config_addr_io = new MemorySpace(this, 0x4);
    config_data_io = new MemorySpace(this, 0x4, config_data_ops);
    io->addSubspace(config_addr_io, PCI_HOST_CONFIG_ADDR);
    io->addSubspace(config_data_io, PCI_HOST_CONFIG_DATA);
}

LiverpoolHost::~LiverpoolHost() {}
