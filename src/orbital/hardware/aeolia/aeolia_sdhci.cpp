/**
 * Aeolia SDHCI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "aeolia_sdhci.h"

AeoliaSDHCIDevice::AeoliaSDHCIDevice(PCIBus* bus, const AeoliaSDHCIDeviceConfig& config)
    : PCIDevice(bus, config) {
}

AeoliaSDHCIDevice::~AeoliaSDHCIDevice() {
}
