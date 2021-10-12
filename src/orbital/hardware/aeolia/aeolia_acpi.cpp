/**
 * Aeolia ACPI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "aeolia_acpi.h"

AeoliaACPIDevice::AeoliaACPIDevice(PCIBus* bus, const AeoliaACPIDeviceConfig& config)
    : PCIDevice(bus, config) {
}

AeoliaACPIDevice::~AeoliaACPIDevice() {
}
