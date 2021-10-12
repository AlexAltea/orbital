/**
 * Aeolia memory device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "aeolia_mem.h"

AeoliaMemDevice::AeoliaMemDevice(PCIBus* bus, const AeoliaMemDeviceConfig& config)
    : PCIDevice(bus, config) {
}

AeoliaMemDevice::~AeoliaMemDevice() {
}
