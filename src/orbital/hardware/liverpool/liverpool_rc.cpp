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
#include <orbital/hardware/liverpool/smu/smu.h>

constexpr U32 D0F0xB8 = 0xB8;
constexpr U32 D0F0xBC = 0xBC;

LiverpoolRCDevice::LiverpoolRCDevice(PCIeBus* bus, const LiverpoolRCDeviceConfig& config)
    : PCIeDevice(bus, config) {
    reset();
}

LiverpoolRCDevice::~LiverpoolRCDevice() {
}

void LiverpoolRCDevice::reset() {
    (U32&)config_data[0xE4] = 0xFF;
    (U32&)config_mask[0xE4] = ~0xFF;
}

void LiverpoolRCDevice::config_write(U32 offset, U64 value, size_t size) {
    U32 smc_ix;
    switch (offset) {
    case D0F0xBC:
        assert(size == 4);
        smc_ix = (U32&)config_data[D0F0xB8];
        smu->smc_write(smc_ix, value);
        break;
    default:
        PCIDevice::config_write(offset, value, size);
    }
}

U64 LiverpoolRCDevice::config_read(U32 offset, size_t size) {
    U64 value = 0;

    U32 smc_ix;
    switch (offset) {
    case D0F0xBC:
        assert(size == 4);
        smc_ix = (U32&)config_data[D0F0xB8];
        value = smu->smc_read(smc_ix);
        break;
    default:
        value = PCIDevice::config_read(offset, size);
    }

    return value;
}
