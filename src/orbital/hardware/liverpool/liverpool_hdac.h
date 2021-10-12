/**
 * Liverpool HD Audio Controller (HDAC) PCI device.
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
    LIVERPOOL_HDAC_DEV = 0x1,
    LIVERPOOL_HDAC_FNC = 0x1,
};

constexpr auto LIVERPOOL_HDAC_VID = static_cast<PCIVendorId>(0x1002);
constexpr auto LIVERPOOL_HDAC_DID = static_cast<PCIDeviceId>(0x9921);

struct LiverpoolHDACDeviceConfig : PCIDeviceConfig {
    LiverpoolHDACDeviceConfig(PCI_DF df = PCI_DF(LIVERPOOL_HDAC_DEV, LIVERPOOL_HDAC_FNC))
        : PCIDeviceConfig(df, LIVERPOOL_HDAC_VID, LIVERPOOL_HDAC_DID, 0x0, PCI_CLASS_MULTIMEDIA_AUDIO) {
    }
};

class LiverpoolHDACDevice final : public PCIDevice {
public:
    LiverpoolHDACDevice(PCIBus* bus, const LiverpoolHDACDeviceConfig& config = {});
    ~LiverpoolHDACDevice();

    // Device interface
    void reset() override;

private:
    MemorySpace* mmio;

    U64 mmio_read(U64 addr, U64 size);
    void mmio_write(U64 addr, U64 value, U64 size);
};
