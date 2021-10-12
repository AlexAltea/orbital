/**
 * Aeolia GBE device.
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
    AEOLIA_GBE_DEV = 0x14,
    AEOLIA_GBE_FNC = 0x1,
};

constexpr auto AEOLIA_GBE_VID = static_cast<PCIVendorId>(0x104D);
constexpr auto AEOLIA_GBE_DID = static_cast<PCIDeviceId>(0x909E);

struct AeoliaGBEDeviceConfig : PCIDeviceConfig {
    AeoliaGBEDeviceConfig(PCI_DF df = PCI_DF(AEOLIA_GBE_DEV, AEOLIA_GBE_FNC))
        : PCIDeviceConfig(df, AEOLIA_GBE_VID, AEOLIA_GBE_DID, 0x0, PCI_CLASS_SYSTEM_OTHER) {
    }
};

class AeoliaGBEDevice final : public PCIDevice {
public:
    AeoliaGBEDevice(PCIBus* bus, const AeoliaGBEDeviceConfig& config = {});
    ~AeoliaGBEDevice();

    // Device interface
    void reset() override;

private:
    MemorySpace* mmio;

    U64 mmio_read(U64 addr, U64 size);
    void mmio_write(U64 addr, U64 value, U64 size);
};
