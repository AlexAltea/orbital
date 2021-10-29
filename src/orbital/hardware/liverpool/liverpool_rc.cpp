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

// Registers
#include "smu/smu_7_1_2_d.h"
#include "smu/smu_7_1_2_sh_mask.h"

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
    PCIDevice::config_write(offset, value, size);
}

U64 LiverpoolRCDevice::config_read(U32 offset, size_t size) {
    U64 value = 0;
    switch (offset) {
    case D0F0xBC:
        switch ((U32&)config_data[D0F0xB8]) {
        case 0xC2100004:
            value = 0x2 | 0x1;
            break;
        case 0xC0500090:
        case 0xC0500098:
        case ixCG_DCLK_STATUS:
        case ixCG_VCLK_STATUS:
        case ixCG_ECLK_STATUS:
        case 0xC05000E0:
        case 0xC05000E8:
            value = 0x1;
            break;
        }
        break;
    default:
        value = PCIDevice::config_read(offset, size);
    }
    return value;
}
