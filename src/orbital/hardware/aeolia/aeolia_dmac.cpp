/**
 * Aeolia DMAC device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "aeolia_dmac.h"

AeoliaDMACDevice::AeoliaDMACDevice(PCIBus* bus, const AeoliaDMACDeviceConfig& config)
    : PCIDevice(bus, config) {
}

AeoliaDMACDevice::~AeoliaDMACDevice() {
}
