/**
 * Aeolia PCIe device.
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
    AEOLIA_PCIE_DEV = 0x14,
    AEOLIA_PCIE_FNC = 0x4,
};

constexpr auto AEOLIA_PCIE_VID = static_cast<PCIVendorId>(0x104D);
constexpr auto AEOLIA_PCIE_DID = static_cast<PCIDeviceId>(0x90A1);

struct AeoliaPCIeDeviceConfig : PCIDeviceConfig {
    AeoliaPCIeDeviceConfig(PCI_DF df = PCI_DF(AEOLIA_PCIE_DEV, AEOLIA_PCIE_FNC))
        : PCIDeviceConfig(df, AEOLIA_PCIE_VID, AEOLIA_PCIE_DID, 0x0, PCI_CLASS_SYSTEM_OTHER) {
    }
};

class AeoliaPCIeDevice final : public PCIDevice {
public:
    AeoliaPCIeDevice(PCIBus* bus, const AeoliaPCIeDeviceConfig& config = {});
    ~AeoliaPCIeDevice();
};
