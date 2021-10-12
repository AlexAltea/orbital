/**
 * Aeolia memory device.
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
    AEOLIA_MEM_DEV = 0x14,
    AEOLIA_MEM_FNC = 0x6,
};

constexpr auto AEOLIA_MEM_VID = static_cast<PCIVendorId>(0x104D);
constexpr auto AEOLIA_MEM_DID = static_cast<PCIDeviceId>(0x90A3);

struct AeoliaMemDeviceConfig : PCIDeviceConfig {
    AeoliaMemDeviceConfig(PCI_DF df = PCI_DF(AEOLIA_MEM_DEV, AEOLIA_MEM_FNC))
        : PCIDeviceConfig(df, AEOLIA_MEM_VID, AEOLIA_MEM_DID, 0x0, PCI_CLASS_SYSTEM_OTHER) {
    }
};

class AeoliaMemDevice final : public PCIDevice {
public:
    AeoliaMemDevice(PCIBus* bus, const AeoliaMemDeviceConfig& config = {});
    ~AeoliaMemDevice();
};
