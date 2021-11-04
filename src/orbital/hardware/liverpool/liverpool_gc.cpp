/**
 * Liverpool Graphics Controller (GC/Starsha) PCI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "liverpool_gc.h"
#include "amd_regs.h"

// Registers
#include "acp/acp.h"
#include "bif/bif_regs.h"
#include "dce/dce_8_0_d.h"
#include "dce/dce_8_0_sh_mask.h"
#include "gca/gfx_7_2_d.h"
#include "gca/gfx_7_2_sh_mask.h"
#include "oss/oss_2_0_d.h"
#include "oss/oss_2_0_sh_mask.h"

constexpr auto GC_MMIO_PCI  = OffsetRange(0x0000, 0x100);

// Logging
#define DEBUG_GC 0
#define DPRINTF(...) \
do { \
    if (DEBUG_GC) { \
        fprintf(stderr, "lvp-gc (%s:%d): ", __FUNCTION__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
    } \
} while (0)

LiverpoolGCDevice::LiverpoolGCDevice(PCIeBus* bus, const LiverpoolGCDeviceConfig& config)
    : PCIeDevice(bus, config),
    // Engines
    gmc(bus->space_mem()), ih(*this, gmc),
    gfx(gmc, ih, config.gfx),
    smu(gmc, ih),
    sam(gmc, ih, smu)
{
    // Define BARs
    space_bar0 = new MemorySpace(this, 0x4000000, {
        static_cast<MemorySpaceReadOp>(&LiverpoolGCDevice::bar0_read),
        static_cast<MemorySpaceWriteOp>(&LiverpoolGCDevice::bar0_write),
    });
    space_bar2 = new MemorySpace(this, 0x800000, {
        static_cast<MemorySpaceReadOp>(&LiverpoolGCDevice::bar2_read),
        static_cast<MemorySpaceWriteOp>(&LiverpoolGCDevice::bar2_write),
    });
    space_pio = new MemorySpace(this, 0x100, {
        static_cast<MemorySpaceReadOp>(&LiverpoolGCDevice::pio_read),
        static_cast<MemorySpaceWriteOp>(&LiverpoolGCDevice::pio_write),
    });
    space_mmio = new MemorySpace(this, 0x40000, {
        static_cast<MemorySpaceReadOp>(&LiverpoolGCDevice::mmio_read),
        static_cast<MemorySpaceWriteOp>(&LiverpoolGCDevice::mmio_write),
    });

    // Register BARs
    register_bar(0, PCI_BASE_ADDRESS_SPACE_MEM, space_bar0);
    register_bar(2, PCI_BASE_ADDRESS_SPACE_MEM, space_bar2);
    register_bar(4, PCI_BASE_ADDRESS_SPACE_IO, space_pio);
    register_bar(5, PCI_BASE_ADDRESS_SPACE_MEM, space_mmio);

    reset();
}

LiverpoolGCDevice::~LiverpoolGCDevice() {
    delete space_bar0;
    delete space_bar2;
    delete space_pio;
    delete space_mmio;
}

void LiverpoolGCDevice::reset() {
    // PCI Configuration Space
    auto& header = config_header();
    header.command = PCI_COMMAND_IO | PCI_COMMAND_MEMORY; // TODO: Is this needed?
    header.header_type |= PCI_HEADER_TYPE_MULTI_FUNCTION;
    header.intr_line = 0xFF;
    header.intr_pin = 0x01;
    msi_enable(1, true);

    mmio.fill(0);
}

U64 LiverpoolGCDevice::bar0_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void LiverpoolGCDevice::bar0_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}

U64 LiverpoolGCDevice::bar2_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void LiverpoolGCDevice::bar2_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}

U64 LiverpoolGCDevice::pio_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void LiverpoolGCDevice::pio_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}

U64 LiverpoolGCDevice::mmio_read(U64 addr, U64 size) {
    U32 value = 0;
    U64 index = addr >> 2;
    U64 index_ix = 0;

    // Remapped registers
    if (GC_MMIO_PCI.contains(addr)) {
        value = (U32&)config_data[addr];
        return value;
    }
    else if (GFX_MMIO_CP_0.contains(index)
          || GFX_MMIO_CP_1.contains(index)) {
        value = gfx.mmio_read(index);
        return value;
    }
    else if (GMC_MMIO_VM.contains(index)
          || GMC_MMIO_MC.contains(index)) {
        value = gmc.mmio_read(index);
        return value;
    }
    else if (OSS_MMIO_IH.contains(index)) {
        value = ih.mmio_read(index);
        return value;
    }
    else if (SAM_MMIO.contains(index)) {
        value = sam.mmio_read(index);
        return value;
    }
    else if (SMU_MMIO.contains(index)) {
        value = smu.mmio_read(index);
        return value;
    }

    switch (index) {
    // ACP
    case mmACP_STATUS:
        value = 1;
        break;
    case mmACP_SOFT_RESET:
        value = mmio[mmACP_SOFT_RESET];
        break;
    case mmACP_UNK512F_:
        value = 0xFFFFFFFF;
        break;

    // BIF
    case mmBIF_FB_EN:
    case mmBIOS_SCRATCH_7:
    case mmGARLIC_FLUSH_CNTL:
    case mmCC_BIF_SECURE_CNTL:
        break;

    // OSS
    case mmSRBM_CNTL:
    case mmHDP_ADDR_CONFIG:
    case mmSEM_CHICKEN_BITS:
    case mmHDP_HOST_PATH_CNTL:
        break;

    // Unknown registers
    case 0x13E:
    case 0x1D0:
    case 0x615:
    case 0x618:
    case 0x619:
    case 0x61B:
    case 0x3BD3:
    case 0x3BD4:
    case 0x3BD5:
        break;

    default:
        DPRINTF("index=0x%llX, size=0x%llX", index, size);
        assert_always("Unimplemented");
        value = mmio[index];
    }

    return value;
}

void LiverpoolGCDevice::mmio_write(U64 addr, U64 value, U64 size) {
    U64 index = addr >> 2;
    U64 index_ix = 0;

    // Remapped registers
    if (GC_MMIO_PCI.contains(addr)) {
        (U32&)config_data[addr] = value;
        return;
    }
    else if (GFX_MMIO_CP_0.contains(index)
          || GFX_MMIO_CP_1.contains(index)) {
        gfx.mmio_write(index, value);
        return;
    }
    else if (GMC_MMIO_VM.contains(index)
          || GMC_MMIO_MC.contains(index)) {
        gmc.mmio_write(index, value);
        return;
    }
    else if (OSS_MMIO_IH.contains(index)) {
        ih.mmio_write(index, value);
        return;
    }
    else if (SAM_MMIO.contains(index)) {
        sam.mmio_write(index, value);
        return;
    }
    else if (SMU_MMIO.contains(index)) {
        smu.mmio_write(index, value);
        return;
    }

    // Indirect registers
    switch (index) {
    case mmMM_DATA:
        mmio_write(mmio[mmMM_INDEX], value, size);
        return;
    }

    // Direct registers
    mmio[index] = value;
    switch (index) {
    // ACP
    case mmACP_SOFT_RESET:
        mmio[mmACP_SOFT_RESET] = (value << 16);
        break;

    // OSS
    case mmSRBM_CNTL:
        break;
    case mmSRBM_GFX_CNTL:
        DPRINTF("mmSRBM_GFX_CNTL { me: %d, pipe: %d, queue: %d, vmid: %d }",
            REG_GET_FIELD(value, SRBM_GFX_CNTL, MEID),
            REG_GET_FIELD(value, SRBM_GFX_CNTL, PIPEID),
            REG_GET_FIELD(value, SRBM_GFX_CNTL, QUEUEID),
            REG_GET_FIELD(value, SRBM_GFX_CNTL, VMID));
        break;

#ifdef NEEDSPORTING
        break;

    case mmCP_PFP_UCODE_DATA:
        liverpool_gc_ucode_load(s, mmCP_PFP_UCODE_ADDR, value);
        break;
    case mmCP_CE_UCODE_DATA:
        liverpool_gc_ucode_load(s, mmCP_CE_UCODE_ADDR, value);
        break;
    case mmCP_MEC_ME1_UCODE_DATA:
        liverpool_gc_ucode_load(s, mmCP_MEC_ME1_UCODE_ADDR, value);
        break;
    case mmCP_MEC_ME2_UCODE_DATA:
        liverpool_gc_ucode_load(s, mmCP_MEC_ME2_UCODE_ADDR, value);
        break;
    case mmRLC_GPM_UCODE_DATA:
        liverpool_gc_ucode_load(s, mmRLC_GPM_UCODE_ADDR, value);
        break;
    /* oss */
    case mmSDMA0_UCODE_DATA:
        liverpool_gc_ucode_load(s, mmSDMA0_UCODE_ADDR, value);
        break;
    case mmSDMA1_UCODE_DATA:
        liverpool_gc_ucode_load(s, mmSDMA1_UCODE_ADDR, value);
        break;
#endif
    default:
        DPRINTF("index=0x%llX, size=0x%llX, value=0x%llX }", index, size, value);
        assert_always("Unimplemented");
    }
}
