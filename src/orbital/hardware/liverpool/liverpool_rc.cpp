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

LiverpoolRCDevice::LiverpoolRCDevice(PCIeBus* bus, const LiverpoolRCDeviceConfig& config)
    : PCIeDevice(bus, config) {
    reset();
}

LiverpoolRCDevice::~LiverpoolRCDevice() {
}

void LiverpoolRCDevice::reset() {
}
