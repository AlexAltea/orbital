/**
 * Liverpool Root Port (RP) PCI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "liverpool_rp.h"

LiverpoolRPDevice::LiverpoolRPDevice(PCIBus* bus, const LiverpoolRPDeviceConfig& config)
    : PCIDevice(bus, config) {
    reset();
}

LiverpoolRPDevice::~LiverpoolRPDevice() {
}

void LiverpoolRPDevice::reset() {
}
