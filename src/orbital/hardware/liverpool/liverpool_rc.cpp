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
    auto& header = config_header();
    header.header_type |= PCI_HEADER_TYPE_MULTI_FUNCTION;

    // Add PCIe capability
    // TODO: Refactor this code
    const auto cap_off = add_capability(PCI_CAP_ID_EXP, 0x14 /* V1 */);
    (U16&)config_data[cap_off +  2 /*PCI_EXP_FLAGS*/ ] = 0x0001;
    (U32&)config_data[cap_off +  4 /*PCI_EXP_DEVCAP*/] = 0;
    (U16&)config_data[cap_off +  8 /*PCI_EXP_DEVCTL*/] = 0;
    (U16&)config_data[cap_off + 10 /*PCI_EXP_DEVSTA*/] = 0;
    (U32&)config_data[cap_off + 12 /*PCI_EXP_LNKCAP*/] = 0;
    (U16&)config_data[cap_off + 16 /*PCI_EXP_LNKCTL*/] = 0;
    (U16&)config_data[cap_off + 18 /*PCI_EXP_LNKSTA*/] = 0;

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
