/**
 * Liverpool Root Port (RP) PCI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <core.h>

enum {
    LIVERPOOL_RP_DEV = 0x2,
    LIVERPOOL_RP_FNC = 0x0,
};

constexpr auto LIVERPOOL_RP_DID = static_cast<PCIDeviceId>(0x1438);

struct LiverpoolRPDeviceConfig : PCIDeviceConfig {
    LiverpoolRPDeviceConfig(PCI_DF df = PCI_DF(LIVERPOOL_RP_DEV, LIVERPOOL_RP_FNC))
        : PCIDeviceConfig(df, PCI_VENDOR_ID_AMD, LIVERPOOL_RP_DID, 0x1, PCI_CLASS_BRIDGE_HOST) {
    }
};

class LiverpoolRPDevice final : public PCIDevice {
public:
    LiverpoolRPDevice(PCIBus* bus, const LiverpoolRPDeviceConfig& config = {});
    ~LiverpoolRPDevice();

    // Device interface
    void reset() override;
};
