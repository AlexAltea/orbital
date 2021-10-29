/**
 * Liverpool Root Complex (RC) PCI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <orbital/core.h>

enum {
    LIVERPOOL_RC_DEV = 0x0,
    LIVERPOOL_RC_FNC = 0x0,
};

constexpr auto LIVERPOOL_RC_DID = static_cast<PCIDeviceId>(0x1436);

struct LiverpoolRCDeviceConfig : PCIeDeviceConfig {
    LiverpoolRCDeviceConfig(PCI_DF df = PCI_DF(LIVERPOOL_RC_DEV, LIVERPOOL_RC_FNC))
        : PCIeDeviceConfig(df, PCI_VENDOR_ID_AMD, LIVERPOOL_RC_DID, 0x1, PCI_CLASS_BRIDGE_HOST) {
    }
};

class LiverpoolRCDevice final : public PCIeDevice {
public:
    LiverpoolRCDevice(PCIeBus* bus, const LiverpoolRCDeviceConfig& config = {});
    ~LiverpoolRCDevice();

    // Device interface
    void reset() override;

    void config_write(U32 offset, U64 value, size_t size) override;
    U64 config_read(U32 offset, size_t size) override;
};
