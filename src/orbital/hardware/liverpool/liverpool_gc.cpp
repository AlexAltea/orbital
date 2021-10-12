/**
 * Liverpool Graphics Controller (GC/Starsha) PCI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "liverpool_gc.h"

LiverpoolGCDevice::LiverpoolGCDevice(PCIBus* bus, const LiverpoolGCDeviceConfig& config)
    : PCIDevice(bus, config) {
    reset();
}

LiverpoolGCDevice::~LiverpoolGCDevice() {
}

void LiverpoolGCDevice::reset() {
}
