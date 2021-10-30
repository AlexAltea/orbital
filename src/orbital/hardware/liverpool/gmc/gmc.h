/**
 * AMD Graphics Memory Controller (GMC).
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

#include <array>

// Forward declarations
class GmcDevice;

constexpr auto GMC_MMIO_VM = OffsetRange(0x500, 0x78);
constexpr auto GMC_MMIO_MC = OffsetRange(0x800, 0x300);

class GmcVmSpace : public TranslatorSpace {
    friend class GmcDevice;
public:
    GmcVmSpace(Space* gmc_mem);

    TranslatorResult translate(Offset off) override;

private:
    U64 base = 0;
};

struct GmcDeviceConfig : DeviceConfig {
};

class GmcDevice final : public Device {
public:
    GmcDevice(Space* mem, const GmcDeviceConfig& config = {});

    void reset() override;

    U32 mmio_read(U32 index);
    void mmio_write(U32 index, U32 value);

    GmcVmSpace& get(U32 vmid);

private:
    std::vector<GmcVmSpace> vm_contexts;
    U32 vm_invalidate_response;
    U32 mc_bist_mismatch_addr;
};
