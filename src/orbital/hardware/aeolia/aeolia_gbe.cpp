/**
 * Aeolia GBE device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "aeolia_gbe.h"

AeoliaGBEDevice::AeoliaGBEDevice(PCIBus* bus, const AeoliaGBEDeviceConfig& config)
    : PCIDevice(bus, config) {
}

AeoliaGBEDevice::~AeoliaGBEDevice() {
}
