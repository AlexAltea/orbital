/**
 * Aeolia XHCI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "aeolia_xhci.h"

AeoliaXHCIDevice::AeoliaXHCIDevice(PCIBus* bus, const AeoliaXHCIDeviceConfig& config)
    : PCIDevice(bus, config) {
}

AeoliaXHCIDevice::~AeoliaXHCIDevice() {
}
