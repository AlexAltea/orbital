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

// Undocumented register definitions
// Disclaimer: Most are just guesses based on reverse engineering and common sense.
#define ixCG_ACLK_STATUS 0xC05000E0

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
    case ixCG_ACLK_STATUS:
        value = 0x1;
        break;
    case 0xC05000E8:
        value = 0x1;
        break;

    // Ignored registers
    case ixGENERAL_PWRMGT:
        break;

    // Unknown registers (BIOS)
    case 0x00020014:
        break;
    case 0xC0104000:
    case 0xC0104004:
    case 0xC0104008:
    case 0xC010400C:
    case 0xC0104010:
    case 0xC0104074:
    case 0xC0104078:
    case 0xC010407C:
    case 0xC0104080:
    case 0xC0104084:
        break;
    case 0xC0107064:
    case 0xC0107068:
    case 0xC010706C:
    case 0xC0107070:
    case 0xC0107074:
    case 0xC0107078:
    case 0xC010707C:
    case 0xC0107080:
    case 0xC0107084:
        break;
    case 0xC0200200:
        break;
    case 0xC050008C:
    case 0xC0500094:
    case ixCG_DCLK_CNTL:
    case ixCG_VCLK_CNTL:
    case ixCG_ECLK_CNTL:
    case ixCG_ACLK_CNTL:
    case 0xC05000E4:
        break;
    case 0xC2100000:
    case 0xC210003C:
        break;

    // Unknown registers (Kernel)
    case 0xC0104068:
        break;

    default:
        assert_always("Unimplemented");
        break;
    }

    return value;
}

void SmuDevice::smc_write(U32 index, U32 value) {
    switch (index) {
    // Unknown registers (BIOS)
    case 0xC0200000:
    case 0xC0200200:
        break;
    case 0xC050008C:
    case 0xC0500094:
    case 0xC050009C:
    case 0xC05000A4:
    case 0xC05000AC:
    case 0xC05000DC:
    case 0xC05000E4:
        break;
    case 0xC2100000:
    case 0xC210003C:
        break;

    default:
        assert_always("Unimplemented");
        break;
    }
}
