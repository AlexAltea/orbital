/**
 * Aeolia DMAC device.
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
    AEOLIA_DMAC_DEV = 0x14,
    AEOLIA_DMAC_FNC = 0x5,
};

constexpr auto AEOLIA_DMAC_VID = static_cast<PCIVendorId>(0x104D);
constexpr auto AEOLIA_DMAC_DID = static_cast<PCIDeviceId>(0x90A2);

struct AeoliaDMACDeviceConfig : PCIDeviceConfig {
    AeoliaDMACDeviceConfig(PCI_DF df = PCI_DF(AEOLIA_DMAC_DEV, AEOLIA_DMAC_FNC))
        : PCIDeviceConfig(df, AEOLIA_DMAC_VID, AEOLIA_DMAC_DID, 0x0, PCI_CLASS_SYSTEM_OTHER) {
    }
};

class AeoliaDMACDevice final : public PCIDevice {
public:
    AeoliaDMACDevice(PCIBus* bus, const AeoliaDMACDeviceConfig& config = {});
    ~AeoliaDMACDevice();
};
