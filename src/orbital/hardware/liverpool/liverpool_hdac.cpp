/**
 * Liverpool HD Audio Controller (HDAC) PCI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "liverpool_hdac.h"

LiverpoolHDACDevice::LiverpoolHDACDevice(PCIBus* bus, const LiverpoolHDACDeviceConfig& config)
    : PCIDevice(bus, config) {
    reset();
}

LiverpoolHDACDevice::~LiverpoolHDACDevice() {
}

void LiverpoolHDACDevice::reset() {
}
