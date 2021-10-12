/**
 * Aeolia SDHCI device.
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
    AEOLIA_SDHCI_DEV = 0x14,
    AEOLIA_SDHCI_FNC = 0x3,
};

constexpr auto AEOLIA_SDHCI_VID = static_cast<PCIVendorId>(0x104D);
constexpr auto AEOLIA_SDHCI_DID = static_cast<PCIDeviceId>(0x90A0);

struct AeoliaSDHCIDeviceConfig : PCIDeviceConfig {
    AeoliaSDHCIDeviceConfig(PCI_DF df = PCI_DF(AEOLIA_SDHCI_DEV, AEOLIA_SDHCI_FNC))
        : PCIDeviceConfig(df, AEOLIA_SDHCI_VID, AEOLIA_SDHCI_DID, 0x0, PCI_CLASS_SYSTEM_OTHER) {
    }
};

class AeoliaSDHCIDevice final : public PCIDevice {
public:
    AeoliaSDHCIDevice(PCIBus* bus, const AeoliaSDHCIDeviceConfig& config = {});
    ~AeoliaSDHCIDevice();

    // Device interface
    void reset() override;

private:
    MemorySpace* mmio;

    U64 mmio_read(U64 addr, U64 size);
    void mmio_write(U64 addr, U64 value, U64 size);
};
