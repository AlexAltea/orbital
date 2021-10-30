/**
 * AMD Graphics Memory Controller (GMC).
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "gmc.h"

#include "gmc_7_1_d.h"
#include "gmc_7_1_sh_mask.h"

constexpr auto GMC_VM_COUNT = 16;

constexpr U64 VM_PTE_VALID   = (1ULL << 0);
constexpr U64 VM_PTE_SYSTEM  = (1ULL << 1);
constexpr U64 VM_PTE_SNOOPED = (1ULL << 2);
constexpr U64 VM_PTE_TMZ     = (1ULL << 3);
constexpr U64 VM_PTE_PROT_X  = (1ULL << 4);
constexpr U64 VM_PTE_PROT_R  = (1ULL << 5);
constexpr U64 VM_PTE_PROT_W  = (1ULL << 6);

constexpr U64 VM_MAX_ADDR = 0xFF'FFFFFFFF;

GmcVmSpace::GmcVmSpace(Space* gmc_mem)
    : TranslatorSpace(nullptr, VM_MAX_ADDR + 1, gmc_mem) {
}

TranslatorResult GmcVmSpace::translate(Offset offset) {
    TranslatorResult res = {};
    if (!this->base) {
        return res;
    }

    uint64_t pde_base, pde_index, pde;
    uint64_t pte_base, pte_index, pte;
    pde_base = this->base;
    pde_index = (offset >> 23) & 0xFFFFF; // TODO: What's the mask?
    pte_index = (offset >> 12) & 0x7FF;
    pde = child->read<U64>(pde_base + pde_index * 8);
    pte_base = pde & ~UINT64_C(0xFF);
    pte = child->read<U64>(pte_base + pte_index * 8);

    // Make translation result
    res.base_pa = offset & ~UINT64_C(0xFFF);
    res.base_va = offset & +UINT64_C(0xFFF) | (pte & ~UINT64_C(0xFFF));
    res.size = 0x1000; // TODO: How to decode this? (set for now to 4 KB pages)
    if (pte & VM_PTE_PROT_X) {
        res.protection |= TranslatorResult::PROT_X;
    }
    if (pte & VM_PTE_PROT_R) {
        res.protection |= TranslatorResult::PROT_R;
    }
    if (pte & VM_PTE_PROT_W) {
        res.protection |= TranslatorResult::PROT_W;
    }

    return res;
}

GmcDevice::GmcDevice(Space* mem, const GmcDeviceConfig& config)
    : Device(nullptr, config), vm_contexts(GMC_VM_COUNT, { mem }) {
    reset();
}

void GmcDevice::reset() {
    vm_invalidate_response = 0;
}

U32 GmcDevice::mmio_read(U32 index) {
    if (index >= mmVM_CONTEXT0_PAGE_TABLE_BASE_ADDR &&
        index <= mmVM_CONTEXT7_PAGE_TABLE_BASE_ADDR) {
        const U32 vmid = index - mmVM_CONTEXT0_PAGE_TABLE_BASE_ADDR;
        return vm_contexts[vmid].base >> 12;
    }
    if (index >= mmVM_CONTEXT8_PAGE_TABLE_BASE_ADDR &&
        index <= mmVM_CONTEXT15_PAGE_TABLE_BASE_ADDR) {
        const U32 vmid = 8 + index - mmVM_CONTEXT8_PAGE_TABLE_BASE_ADDR;
        return vm_contexts[vmid].base >> 12;
    }

    U32 value = 0;
    switch (index) {
    // VM
    case mmVM_INVALIDATE_RESPONSE:
        value = vm_invalidate_response;
        break;

    // MC
    case mmMC_BIST_MISMATCH_ADDR:
        value = mc_bist_mismatch_addr;
        break;

    default:
        //assert_always("Unimplemented");
        break;
    }

    return value;
}

void GmcDevice::mmio_write(U32 index, U32 value) {
    if (index >= mmVM_CONTEXT0_PAGE_TABLE_BASE_ADDR &&
        index <= mmVM_CONTEXT7_PAGE_TABLE_BASE_ADDR) {
        const U32 vmid = index - mmVM_CONTEXT0_PAGE_TABLE_BASE_ADDR;
        vm_contexts[vmid].base = value << 12;
        return;
    }
    if (index >= mmVM_CONTEXT8_PAGE_TABLE_BASE_ADDR &&
        index <= mmVM_CONTEXT15_PAGE_TABLE_BASE_ADDR) {
        const U32 vmid = 8 + index - mmVM_CONTEXT8_PAGE_TABLE_BASE_ADDR;
        vm_contexts[vmid].base = value << 12;
        return;
    }

    switch (index) {
    // VM
    case mmVM_L2_CG:
        break;
    case mmVM_INVALIDATE_REQUEST:
        vm_invalidate_response = value;
        break;

    // MC
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
    case mmMC_XPB_CLK_GAT:
    case mmMC_HUB_MISC_SIP_CG:
    case mmMC_HUB_MISC_HUB_CG:
    case mmMC_HUB_MISC_VM_CG:
    case mmMC_CITF_MISC_RD_CG:
    case mmMC_CITF_MISC_WR_CG:
    case mmMC_CITF_MISC_VM_CG:
        break;
    case mmMC_BIST_MISMATCH_ADDR:
        mc_bist_mismatch_addr = value;
        break;

    default:
        break;
    }
}

GmcVmSpace& GmcDevice::get(U32 vmid) {
    return vm_contexts[vmid];
}
