/**
 * AMD System Management Unit (SMU) device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "smu.h"
#include <orbital/hardware/liverpool/gmc/gmc.h>
#include <orbital/hardware/liverpool/oss/ih.h>

#include "smu_7_1_2_d.h"
#include "smu_7_1_2_sh_mask.h"

SmuDevice::SmuDevice(GmcDevice& gmc, IhDevice& ih)
    : Device(nullptr), gmc(gmc), ih(ih) {
    reset();
}

void SmuDevice::reset() {
}

U32 SmuDevice::mmio_read(U32 index) {
    U32 value = 0;

    switch (index) {
    case mmSMC_IND_INDEX:
        value = smc_ix;
        break;
    case mmSMC_IND_DATA:
        value = smc_read(smc_ix);
        break;
    default:
        assert_always("Unimplemented");
    }

    return value;
}

void SmuDevice::mmio_write(U32 index, U32 value) {
    switch (index) {
    case mmSMC_IND_INDEX:
        smc_ix = value;
        break;
    case mmSMC_IND_DATA:
        smc_write(smc_ix, value);
        break;
    default:
        assert_always("Unimplemented");
    }
}

U32 SmuDevice::smc_read(U32 index) {
    U32 value = 0;

    switch (index) {
    case 0xC2100004:
        value = 0x2 | 0x1;
        break;
    case 0xC0500090:
        value = 0x1;
        break;
    case 0xC0500098:
        value = 0x1;
        break;
    case ixCG_DCLK_STATUS:
        value = 0x1;
        break;
    case ixCG_VCLK_STATUS:
        value = 0x1;
        break;
    case ixCG_ECLK_STATUS:
        value = 0x1;
        break;
    case 0xC05000E0:
        value = 0x1;
        break;
    case 0xC05000E8:
        value = 0x1;
        break;
    default:
        //assert_always("Unimplemented");
        break;
    }

    return value;
}

void SmuDevice::smc_write(U32 index, U32 value) {
    //assert_always("Unimplemented");
}
