/**
 * Aeolia AHCI device.
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
    AEOLIA_AHCI_DEV = 0x14,
    AEOLIA_AHCI_FNC = 0x2,
};

constexpr auto AEOLIA_AHCI_VID = static_cast<PCIVendorId>(0x104D);
constexpr auto AEOLIA_AHCI_DID = static_cast<PCIDeviceId>(0x909F);

struct AeoliaAHCIDeviceConfig : PCIDeviceConfig {
    AeoliaAHCIDeviceConfig(PCI_DF df = PCI_DF(AEOLIA_AHCI_DEV, AEOLIA_AHCI_FNC))
        : PCIDeviceConfig(df, AEOLIA_AHCI_VID, AEOLIA_AHCI_DID, 0x0, PCI_CLASS_SYSTEM_OTHER) {
    }
};

class AeoliaAHCIDevice final : public PCIDevice {
public:
    AeoliaAHCIDevice(PCIBus* bus, const AeoliaAHCIDeviceConfig& config = {});
    ~AeoliaAHCIDevice();

    // Device interface
    void reset() override;

private:
    AHCIDevice* ahci;
};
