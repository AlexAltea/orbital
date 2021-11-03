/**
 * AMD System Management Unit (SMU) device.
 *
 * Based on research from: Jevin Sweval (@jevinskie).
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
#define ixCG_SCLK_CNTL        0xC050008C
#define ixCG_SCLK_STATUS      0xC0500090
#define ixCG_LCLK_CNTL        0xC0500094
#define ixCG_LCLK_STATUS      0xC0500098
#define ixCG_ACLK_STATUS      0xC05000E0
#define ixCG_SAMCLK_CNTL      0xC05000E4
#define ixCG_SAMCLK_STATUS    0xC05000E8

#define ixSMU_IOC_REQ         0xC2100000
#define ixSMU_IOC_STATUS      0xC2100004
#define ixSMU_IOC_CTRL        0xC2100008
#define ixSMU_IOC_RDDATA      0xC210000C
#define ixSMU_IOC_PHASE1      0xC2100014
#define ixSMU_IOC_PHASE2      0xC2100018
#define ixSMU_IOC_PHASE3      0xC210001C
#define ixSMU_IOC_ARG         0xC210003C
#define ixSMU_IOC_RES         0xC2100040
#define ixSMU_IOC_READ_0      0xC2100134

/**
 * Clocks Domains:
 * - SCLK:    ???
 * - LCLK:    ???
 * - DCLK:    UVD D-clock
 * - VCLK:    UVD V-clock
 * - ECLK:    VCE clock
 * - ACLK:    ACP clock
 * - SAMCLK:  SAM clock
 */

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
    // Clocks
    case ixCG_SCLK_STATUS:
        value = 0x1;
        break;
    case ixCG_LCLK_STATUS:
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
    case ixCG_SAMCLK_STATUS:
        value = 0x1;
        break;
    case ixCG_SCLK_CNTL:
    case ixCG_LCLK_CNTL:
    case ixCG_DCLK_CNTL:
    case ixCG_VCLK_CNTL:
    case ixCG_ECLK_CNTL:
    case ixCG_ACLK_CNTL:
        break;

    // IOC
    case ixSMU_IOC_REQ:
        value = 0;
        break;
    case ixSMU_IOC_STATUS:
        value = 0x2 | 0x1;
        break;
    case ixSMU_IOC_ARG:
        value = ioc_arg;
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
    case ixSMU_IOC_REQ:
        update_ioc(value);
        break;
    case ixSMU_IOC_ARG:
        ioc_arg = value;
        break;

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

    default:
        assert_always("Unimplemented");
        break;
    }
}

void SmuDevice::update_ioc(U32 req) {
    printf("SmuDevice::update_ioc: req=0x%08X, arg=0x%08X\n", req, ioc_arg);
}
