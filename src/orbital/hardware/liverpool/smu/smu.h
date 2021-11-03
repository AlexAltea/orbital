/**
 * AMD System Management Unit (SMU) device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <orbital/core.h>
#include <orbital/offset_range.h>

 // Forward declarations
class GmcDevice;
class IhDevice;

constexpr auto SMU_MMIO = OffsetRange(0x80, 0x40);

class SmuDevice : public Device {
public:
    SmuDevice(GmcDevice& gmc, IhDevice& ih);

    void reset();

    U32 mmio_read(U32 index);
    void mmio_write(U32 index, U32 value);

    U32 smc_read(U32 index);
    void smc_write(U32 index, U32 value);

private:
    GmcDevice& gmc;
    IhDevice& ih;

    U32 smc_ix;

    // IOC
    U32 ioc_arg;

    void update_ioc(U32 req);
};
