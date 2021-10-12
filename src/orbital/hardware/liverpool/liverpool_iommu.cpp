/**
 * Liverpool IOMMU PCI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "liverpool_iommu.h"

LiverpoolIOMMUDevice::LiverpoolIOMMUDevice(PCIBus* bus, const LiverpoolIOMMUDeviceConfig& config)
    : PCIDevice(bus, config) {
    reset();
}

LiverpoolIOMMUDevice::~LiverpoolIOMMUDevice() {
}

void LiverpoolIOMMUDevice::reset() {
}
