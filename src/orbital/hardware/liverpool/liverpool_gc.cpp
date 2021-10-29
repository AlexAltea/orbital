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
#include "bif/bif_4_1_d.h"
#include "bif/bif_4_1_sh_mask.h"
#include "dce/dce_8_0_d.h"
#include "dce/dce_8_0_sh_mask.h"
#include "gca/gfx_7_2_d.h"
#include "gca/gfx_7_2_sh_mask.h"
#include "gmc/gmc_7_1_d.h"
#include "gmc/gmc_7_1_sh_mask.h"
#include "oss/oss_2_0_d.h"
#include "oss/oss_2_0_sh_mask.h"
#include "smu/smu_7_1_2_d.h"
#include "smu/smu_7_1_2_sh_mask.h"
#include "sam/sam.h"

// Engines
#include "gmc/gmc.h"

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
    : PCIeDevice(bus, config) {
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

    // Create engines
    GmcDeviceConfig gmc_config = {};
    gmc = std::make_unique<GmcDevice>(bus->space_mem(), gmc_config);

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

    mmio.fill(0);
    sam_ix.fill(0);
    sam_sab_ix.fill(0);
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
    if (addr + size <= 0x100) {
        value = (U32&)config_data[addr];
        return value;
    }
    else if (GMC_MMIO_VM.contains(index)) {
        value = gmc->mmio_read(index);
        return value;
    }
    else if (GMC_MMIO_MC.contains(index)) {
        value = gmc->mmio_read(index);
        return value;
    }

    switch (index) {
    // SMU
    case mmSMC_IND_INDEX:
        value = mmio[index];
        break;
    case mmSMC_IND_DATA:
        switch (mmio[mmSMC_IND_INDEX]) {
        case 0xC2100004:
            value = 0x2 | 0x1;
            break;
        case 0xC0500090:
            value = 0x1;
            break;
        case 0xC0500098:
            value = 0x1;
            break;
        default:
            value = 0x0;
        }
        break;

    // GCA
    case mmGRBM_GFX_INDEX:
    case mmRLC_MAX_PG_CU:
    case mmRLC_PG_CNTL:
        value = mmio[index];
        break;

    // GMC
    case mmMC_BIST_MISMATCH_ADDR:
        value = mmio[index];
        break;

    case mmSAM_IX_DATA:
        index_ix = mmio[mmSAM_IX_INDEX];
        DPRINTF("mmSAM_IX_DATA_read { index: %X }", index_ix);
        value = sam_ix[index_ix];
        break;
    case mmSAM_SAB_IX_DATA:
        index_ix = mmio[mmSAM_SAB_IX_INDEX];
        DPRINTF("mmSAM_SAB_IX_DATA_read { index: %X }", index_ix);
        value = sam_sab_ix[index_ix];
        break;

    // Simple registers
    case mmSAM_GPR_SCRATCH_0:
    case mmSAM_GPR_SCRATCH_1:
    case mmSAM_GPR_SCRATCH_2:
    case mmSAM_GPR_SCRATCH_3:
        value = mmio[index];
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
    if (addr + size <= 0x100) {
        (U32&)config_data[addr] = value;
        return;
    }
    else if (GMC_MMIO_VM.contains(index)) {
        gmc->mmio_write(index, value);
    }
    else if (GMC_MMIO_MC.contains(index)) {
        gmc->mmio_write(index, value);
    }

    // Indirect registers
    switch (index) {
    case mmSAM_IX_DATA:
        switch (mmio[mmSAM_IX_INDEX]) {
        case ixSAM_IH_CPU_AM32_INT:
            update_sam(value);
            break;
        case ixSAM_IH_AM32_CPU_INT_ACK:
            sam_ix[ixSAM_IH_CPU_AM32_INT_STATUS] = 0;
            break;
        default:
            index_ix = mmio[mmSAM_IX_INDEX];
            DPRINTF("mmSAM_IX_DATA_write { index: %X, value: %llX }", index_ix, value);
            sam_ix[index_ix] = value;
        }
        return;

    case mmSAM_SAB_IX_DATA:
        switch (mmio[mmSAM_SAB_IX_INDEX]) {
        default:
            index_ix = mmio[mmSAM_SAB_IX_INDEX];
            DPRINTF("mmSAM_SAB_IX_DATA_write { index: %X, value: %llX }", index_ix, value);
            sam_sab_ix[index_ix] = value;
        }
        return;

    case mmMM_DATA:
        mmio_write(mmio[mmMM_INDEX], value, size);
        return;
    }

    // Direct registers
    mmio[index] = value;
    switch (index) {
    // SMU
    case mmSMC_IND_INDEX:
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

void LiverpoolGCDevice::update_sam(U32 value) {
    U64 query_addr;
    U64 reply_addr;

    assert(value == 1);
    query_addr = sam_ix[ixSAM_IH_CPU_AM32_INT_CTX_HIGH];
    query_addr = sam_ix[ixSAM_IH_CPU_AM32_INT_CTX_LOW] | (query_addr << 32);
    query_addr &= 0xFFFFFFFFFFFFULL;
    reply_addr = sam_ix[ixSAM_IH_AM32_CPU_INT_CTX_HIGH];
    reply_addr = sam_ix[ixSAM_IH_AM32_CPU_INT_CTX_LOW] | (reply_addr << 32);
    reply_addr &= 0xFFFFFFFFFFFFULL;

    const U16 flags = query_addr >> 48;
    DPRINTF("flags=0x%llX, query=0x%llX, reply=0x%llX\n", flags, query_addr, reply_addr);


    sam_ix[ixSAM_IH_CPU_AM32_INT_STATUS] = 0;// 1;
    sam_ix[ixSAM_IH_AM32_CPU_INT_STATUS] |= 1;
}
