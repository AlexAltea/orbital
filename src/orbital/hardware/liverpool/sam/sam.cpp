/**
 * AMD Secure Asset Management Unit (SAMU) device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "sam.h"
#include <orbital/hardware/liverpool/gmc/gmc.h>
#include <orbital/hardware/liverpool/oss/ih.h>
#include <orbital/hardware/liverpool/smu/smu.h>

// SBL
constexpr U32 SBL_INT_UNKA202   = 0xA202;
constexpr U32 SBL_INT_UNKA303   = 0xA303;
constexpr U32 SBL_INT_SMU_READ  = 0xA404;
constexpr U32 SBL_INT_SMU_WRITE = 0xA505;

// Logging
#define DEBUG_SAM 1
#define DPRINTF(...) \
do { \
    if (DEBUG_SAM) { \
        fprintf(stderr, "lvp-sam (%s:%d): ", __FUNCTION__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
    } \
} while (0)

SamDevice::SamDevice(GmcDevice& gmc, IhDevice& ih, SmuDevice& smu)
    : Device(nullptr), gmc(gmc), ih(ih), smu(smu) {
    reset();
}

void SamDevice::reset() {
    gpr.fill(0);
    ih_cpu_am32_int_ctx = 0;
    ih_am32_cpu_int_ctx = 0;

    ix_data.fill(0);
    sab_ix_data.fill(0);
}

U32 SamDevice::mmio_read(U32 index) {
    U32 value = 0;

    switch (index) {
    case mmSAM_IX_INDEX:
        value = sam_ix_index;
        break;
    case mmSAM_IX_DATA:
        switch (sam_ix_index) {
        case ixSAM_IH_CPU_AM32_INT_CTX_HIGH:
            value = ih_cpu_am32_int_ctx_high;
            break;
        case ixSAM_IH_CPU_AM32_INT_CTX_LOW:
            value = ih_cpu_am32_int_ctx_low;
            break;
        case ixSAM_IH_AM32_CPU_INT_CTX_HIGH:
            value = ih_am32_cpu_int_ctx_high;
            break;
        case ixSAM_IH_AM32_CPU_INT_CTX_LOW:
            value = ih_am32_cpu_int_ctx_low;
            break;
        default:
            DPRINTF("mmSAM_IX_DATA_read { index: %X }", sam_ix_index);
            value = ix_data[sam_ix_index];
        }
        break;
    case mmSAM_SAB_IX_INDEX:
        value = sam_sab_ix_index;
        break;
    case mmSAM_SAB_IX_DATA:
        DPRINTF("mmSAM_SAB_IX_DATA_read { index: %X }", sam_sab_ix_index);
        value = sab_ix_data[sam_sab_ix_index];
        break;
    case mmSAM_GPR_SCRATCH_0:
        value = gpr[0];
        break;
    case mmSAM_GPR_SCRATCH_1:
        value = gpr[1];
        break;
    case mmSAM_GPR_SCRATCH_2:
        value = gpr[2];
        break;
    case mmSAM_GPR_SCRATCH_3:
        value = gpr[3];
        break;
    default:
        assert_always("Unimplemented");
    }

    return value;
}

void SamDevice::mmio_write(U32 index, U32 value) {
    switch (index) {
    case mmSAM_IX_INDEX:
        sam_ix_index = value;
        break;
    case mmSAM_IX_DATA:
        switch (sam_ix_index) {
        case ixSAM_IH_CPU_AM32_INT:
            handle_request(value);
            break;
        case ixSAM_IH_CPU_AM32_INT_CTX_HIGH:
            ih_cpu_am32_int_ctx_high = value;
            break;
        case ixSAM_IH_CPU_AM32_INT_CTX_LOW:
            ih_cpu_am32_int_ctx_low = value;
            break;
        case ixSAM_IH_AM32_CPU_INT_CTX_HIGH:
            ih_am32_cpu_int_ctx_high = value;
            break;
        case ixSAM_IH_AM32_CPU_INT_CTX_LOW:
            ih_am32_cpu_int_ctx_low = value;
            break;
        case ixSAM_IH_AM32_CPU_INT_ACK:
            //sam_ix[ixSAM_IH_AM32_CPU_INT_STATUS] = 0;
            ix_data[ixSAM_IH_CPU_AM32_INT_STATUS] = 0;
            break;
        default:
            DPRINTF("mmSAM_IX_DATA_write { index: %X, value: %llX }", sam_ix_index, value);
            ix_data[sam_ix_index] = value;
        }
        break;
    case mmSAM_SAB_IX_INDEX:
        sam_sab_ix_index = value;
        break;
    case mmSAM_SAB_IX_DATA:
        switch (sam_sab_ix_index) {
        default:
            DPRINTF("mmSAM_SAB_IX_DATA_write { index: %X, value: %llX }", sam_sab_ix_index, value);
            ix_data[sam_sab_ix_index] = value;
        }
        break;
    case mmSAM_GPR_SCRATCH_0:
        gpr[0] = value;
        break;
    case mmSAM_GPR_SCRATCH_1:
        gpr[1] = value;
        break;
    case mmSAM_GPR_SCRATCH_2:
        gpr[2] = value;
        break;
    case mmSAM_GPR_SCRATCH_3:
        gpr[3] = value;
        break;
    default:
        assert_always("Unimplemented");
    }
}


void SamDevice::handle_request(U32 value) {
    const auto query_addr = ih_cpu_am32_int_ctx & UINT64_C(0xFFFFFFFFFFFF);
    const auto reply_addr = ih_am32_cpu_int_ctx & UINT64_C(0xFFFFFFFFFFFF);

    assert(value == 1);
    const U16 flags = ih_cpu_am32_int_flags;
    DPRINTF("flags=0x%llX, query=0x%llX, reply=0x%llX\n", flags, query_addr, reply_addr);
    if (flags == 0) {
        const auto id = gpr[0];
        switch (id) {
        case SBL_INT_UNKA202:
            assert_always("Unimplemented");
            break;
        case SBL_INT_UNKA303:
            assert_always("Unimplemented");
            break;
        case SBL_INT_SMU_READ:
            gpr[2] = smu.smc_read(gpr[1]);
            gpr[3] = 0;
            break;
        case SBL_INT_SMU_WRITE:
            smu.smc_write(gpr[1], gpr[2]);
            gpr[3] = 0;
            break;
        }
        ix_data[ixSAM_IH_CPU_AM32_INT_STATUS] = 0;// 1;
        ix_data[ixSAM_IH_AM32_CPU_INT_STATUS] |= 1;
        return;
    }
    else {
#if 0
        uint32_t command = ldl_le_phys(s->gart.as[15 /*gart->as[SAMU_VMID] */], query_addr);
        if (command == 0) {
            liverpool_gc_samu_init(&s->samu, query_addr);
        }
        else {
            liverpool_gc_samu_packet(&s->samu, query_addr, reply_addr);
        }

        if (command == SAMU_CMD_SERVICE_RAND || command == 0) {
            return;
        }
#endif

        ix_data[ixSAM_IH_CPU_AM32_INT_STATUS] = 0;//1
        ix_data[ixSAM_IH_AM32_CPU_INT_STATUS] |= 1;
        ih.push_iv(0, IV_SRCID_SAM, 0 /* TODO */);
    }
}
