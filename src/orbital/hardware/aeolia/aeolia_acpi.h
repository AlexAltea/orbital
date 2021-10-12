/**
 * Aeolia ACPI device.
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
    AEOLIA_ACPI_DEV = 0x14,
    AEOLIA_ACPI_FNC = 0x0,
};

constexpr auto AEOLIA_ACPI_VID = static_cast<PCIVendorId>(0x104D);
constexpr auto AEOLIA_ACPI_DID = static_cast<PCIDeviceId>(0x908F);

struct AeoliaACPIDeviceConfig : PCIDeviceConfig {
    AeoliaACPIDeviceConfig(PCI_DF df = PCI_DF(AEOLIA_ACPI_DEV, AEOLIA_ACPI_FNC))
        : PCIDeviceConfig(df, AEOLIA_ACPI_VID, AEOLIA_ACPI_DID, 0x0, PCI_CLASS_SYSTEM_OTHER) {
    }
};

class AeoliaACPIDevice final : public PCIDevice {
public:
    AeoliaACPIDevice(PCIBus* bus, const AeoliaACPIDeviceConfig& config = {});
    ~AeoliaACPIDevice();
};
