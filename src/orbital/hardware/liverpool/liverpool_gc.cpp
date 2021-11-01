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

// Registers
#include "acp/acp.h"
#include "bif/bif_4_1_d.h"
#include "bif/bif_4_1_sh_mask.h"
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
    else if (SMU_MMIO.contains(index)) {
        value = smu.mmio_read(index);
        return value;
    }
    else if (SAM_MMIO.contains(index)) {
        value = sam.mmio_read(index);
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


    // GCA
    case mmGRBM_GFX_INDEX:
    case mmRLC_MAX_PG_CU:
    case mmRLC_PG_CNTL:
        value = mmio[index];
        break;
    case mmCP_HQD_ACTIVE:
        value = 0;
        break;
    case mmRLC_SERDES_CU_MASTER_BUSY:
        value = 0;
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
    else if (SMU_MMIO.contains(index)) {
        smu.mmio_write(index, value);
        return;
    }
    else if (SAM_MMIO.contains(index)) {
        sam.mmio_write(index, value);
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

    // GCA
    case mmGRBM_GFX_INDEX:
    case mmRLC_PG_ALWAYS_ON_CU_MASK:
    case mmRLC_MAX_PG_CU:
    case mmRLC_PG_CNTL:
        break;

    // GMC
    case mmMC_SHARED_BLACKOUT_CNTL:
    case mmMC_SEQ_RESERVE_0_S:
    case mmMC_SEQ_RESERVE_1_S:
    case mmMC_RPB_ARB_CNTL:
    case mmMC_RPB_CID_QUEUE_WR:
    case mmMC_RPB_WR_COMBINE_CNTL:
    case mmMC_RPB_DBG1:
    case mmMC_HUB_WDP_IH:
    case mmMC_HUB_WDP_CPF:
    case mmMC_HUB_RDREQ_CPC:
    case mmMC_HUB_WDP_RLC:
    case mmMC_HUB_RDREQ_UVD:
    case mmMC_HUB_WRRET_MCDW:
    case mmMC_HUB_RDREQ_DMIF:
    case mmMC_HUB_RDREQ_CNTL:
    case mmMC_HUB_RDREQ_MCDW:
    case mmMC_HUB_RDREQ_MCDX:
    case mmMC_HUB_RDREQ_MCDY:
    case mmMC_HUB_RDREQ_MCDZ:
    case mmMC_CITF_CREDITS_ARB_RD:
    case mmMC_CITF_CREDITS_ARB_WR:
    case mmMC_RD_GRP_EXT:
    case mmMC_WR_GRP_EXT:
    case mmMC_RD_GRP_LCL:
    case mmMC_WR_GRP_LCL:
    case mmMC_ARB_TM_CNTL_RD:
    case mmMC_ARB_TM_CNTL_WR:
    case mmMC_ARB_LAZY0_RD:
    case mmMC_ARB_LAZY0_WR:
    case mmMC_ARB_AGE_RD:
    case mmMC_ARB_AGE_WR:
    case mmMC_RD_GRP_GFX:
    case mmMC_WR_GRP_GFX:
    case mmMC_RD_GRP_SYS:
    case mmMC_WR_GRP_SYS:
    case mmMC_RD_GRP_OTH:
    case mmMC_WR_GRP_OTH:
    case mmMC_HUB_RDREQ_CPF:
    case mmMC_HUB_WDP_ACPO:
    case mmMC_ARB_WTM_CNTL_WR:
    case mmMC_HUB_RDREQ_VMC:
    case mmMC_ARB_WTM_CNTL_RD:
    case mmMC_ARB_RET_CREDITS_WR:
    case mmMC_ARB_LM_WR:
    case mmMC_ARB_LM_RD:
    case mmMC_ARB_RET_CREDITS_RD:
    case mmMC_HUB_WDP_VCEU:
    case mmMC_HUB_WDP_XDMAM:
    case mmMC_HUB_WDP_XDMA:
    case mmMC_HUB_RDREQ_XDMAM:
    case mmMC_ARB_RET_CREDITS2:
    case mmMC_SHARED_CHMAP:
    case mmMC_ARB_SQM_CNTL:
    case mmMC_BIST_MISMATCH_ADDR:
    case mmMC_XPB_CLK_GAT:
    case mmMC_HUB_MISC_SIP_CG:
    case mmMC_HUB_MISC_HUB_CG:
    case mmMC_HUB_MISC_VM_CG:
    case mmMC_CITF_MISC_RD_CG:
    case mmMC_CITF_MISC_WR_CG:
    case mmMC_CITF_MISC_VM_CG:
    case mmVM_L2_CG:
        break;

#endif
    // Simple registers
    case mmSAM_IX_INDEX:
    case mmSAM_GPR_SCRATCH_0:
    case mmSAM_GPR_SCRATCH_1:
    case mmSAM_GPR_SCRATCH_2:
    case mmSAM_GPR_SCRATCH_3:
        break;

    default:
        DPRINTF("index=0x%llX, size=0x%llX, value=0x%llX }", index, size, value);
        assert_always("Unimplemented");
    }
}
