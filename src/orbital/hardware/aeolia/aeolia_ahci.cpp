/**
 * Aeolia AHCI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "aeolia_ahci.h"

AeoliaAHCIDevice::AeoliaAHCIDevice(PCIBus* bus, const AeoliaAHCIDeviceConfig& config)
    : PCIDevice(bus, config) {
}

AeoliaAHCIDevice::~AeoliaAHCIDevice() {
}
