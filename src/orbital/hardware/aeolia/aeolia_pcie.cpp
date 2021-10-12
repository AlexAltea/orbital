/**
 * Aeolia PCIe device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "aeolia_pcie.h"

AeoliaPCIeDevice::AeoliaPCIeDevice(PCIBus* bus, const AeoliaPCIeDeviceConfig& config)
    : PCIDevice(bus, config) {
}

AeoliaPCIeDevice::~AeoliaPCIeDevice() {
}
