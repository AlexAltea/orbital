/**
 * Liverpool PCI Host/Bus devices.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <core.h>

// Liverpool PCI Bus
class LiverpoolBus : public PCIeBus {
public:
    LiverpoolBus(Device* parent, const PCIeBusConfig& config = {});
    ~LiverpoolBus();

    void set_irq(void* opaque, int irq, int level) override;
    int map_irq(PCI_DF df, int irq) override;
    void route_irq(PCIDevice* opaque, int pin) override;
};

// Liverpool PCI Host
class LiverpoolHost final : public PCIeHost {
public:
    LiverpoolHost(Device* parent, const PCIeHostConfig& config = {});
    ~LiverpoolHost();
};
