/**
 * Liverpool Root Complex (RC) PCI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "liverpool_rc.h"

LiverpoolRCDevice::LiverpoolRCDevice(PCIBus* bus, const LiverpoolRCDeviceConfig& config)
    : PCIDevice(bus, config) {
    reset();
}

LiverpoolRCDevice::~LiverpoolRCDevice() {
}

void LiverpoolRCDevice::reset() {
}
