/**
 * AMD Secure Asset Management Unit (SAMU) device.
 *
 * Based on research from: Alexey Kulaev (@flatz).
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "sam.h"
#include "sam_regs.h"
#include <orbital/hardware/liverpool/gmc/gmc.h>
#include <orbital/hardware/liverpool/oss/ih.h>
#include <orbital/hardware/liverpool/smu/smu.h>

// SBL
constexpr U32 SBL_SK_MBOX_READ  = 0xA202;
constexpr U32 SBL_SK_MBOX_WRITE = 0xA303;
constexpr U32 SBL_SK_SMC_READ   = 0xA404;
constexpr U32 SBL_SK_SMC_WRITE  = 0xA505;

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
    ih_cpu_am32_int_status = 0;
    ih_am32_cpu_int_ctx = 0;

    ix_data.fill(0);
    sab_ix_data.fill(0);
}

U32 SamDevice::mmio_read(U32 index) {
    U32 value = 0;

    switch (index) {
    case mmSAM_IX_INDEX:
        value = ix_index;
        break;
    case mmSAM_IX_DATA:
        switch (ix_index) {
        case ixSAM_IH_CPU_AM32_INT_CTX_HIGH:
            value = ih_cpu_am32_int_ctx_high;
            break;
        case ixSAM_IH_CPU_AM32_INT_CTX_LOW:
            value = ih_cpu_am32_int_ctx_low;
            break;
        case ixSAM_IH_CPU_AM32_INT_STATUS:
            value = ih_cpu_am32_int_status;
            break;
        case ixSAM_IH_AM32_CPU_INT_CTX_HIGH:
            value = ih_am32_cpu_int_ctx_high;
            break;
        case ixSAM_IH_AM32_CPU_INT_CTX_LOW:
            value = ih_am32_cpu_int_ctx_low;
            break;
        default:
            DPRINTF("mmSAM_IX_DATA_read { index: %X }", ix_index);
            value = ix_data[ix_index];
        }
        break;
    case mmSAM_SAB_IX_INDEX:
        value = sab_ix_index;
        break;
    case mmSAM_SAB_IX_DATA:
        DPRINTF("mmSAM_SAB_IX_DATA_read { index: %X }", sab_ix_index);
        value = sab_ix_data[sab_ix_index];
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
        ix_index = value;
        break;
    case mmSAM_IX_DATA:
        switch (ix_index) {
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
            //ix_data[ixSAM_IH_AM32_CPU_INT_STATUS] = 0;
            ih_cpu_am32_int_status = 0;
            break;
        default:
            DPRINTF("mmSAM_IX_DATA_write { index: %X, value: %llX }", ix_index, value);
            ix_data[ix_index] = value;
        }
        break;
    case mmSAM_SAB_IX_INDEX:
        sab_ix_index = value;
        break;
    case mmSAM_SAB_IX_DATA:
        switch (sab_ix_index) {
        default:
            DPRINTF("mmSAM_SAB_IX_DATA_write { index: %X, value: %llX }", sab_ix_index, value);
            ix_data[sab_ix_index] = value;
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
        case SBL_SK_MBOX_READ:
            // TODO: gpr[2] = mbox_read(addr=gpr[1]);
            assert_always("Unimplemented");
            gpr[3] = 0;
            break;
        case SBL_SK_MBOX_WRITE:
            // TODO: mbox_write(addr=gpr[1], value=gpr[2]);
            assert_always("Unimplemented");
            gpr[3] = 0;
            break;
        case SBL_SK_SMC_READ:
            gpr[2] = smu.smc_read(gpr[1]);
            gpr[3] = 0;
            break;
        case SBL_SK_SMC_WRITE:
            smu.smc_write(gpr[1], gpr[2]);
            gpr[3] = 0;
            break;
        }
        ih_cpu_am32_int_status = 0;
        ih_am32_cpu_int_status |= 1;
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
        ih_cpu_am32_int_status = 0;//1
        ih_am32_cpu_int_status |= 1;
        ih.push_iv(0, IV_SRCID_SAM, 0 /* TODO */);
    }
}
