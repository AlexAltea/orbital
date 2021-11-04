/**
 * AMD Graphics and Compute Array (GCA aka GFX).
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "gfx.h"
#include <orbital/hardware/liverpool/gmc/gmc.h>
#include <orbital/hardware/liverpool/oss/ih.h>

#include "gfx_7_2_d.h"
#include "gfx_7_2_sh_mask.h"

#include <chrono>

using namespace std::chrono_literals;

GfxDevice::GfxDevice(GmcDevice& gmc, IhDevice& ih, const GfxDeviceConfig& config)
    : Device(nullptr), gmc(gmc), ih(ih), vk(config.vk), cp_thread(&GfxDevice::cp_task, this) {
    reset();
}

void GfxDevice::reset() {
    memset(cp_rb, 0, sizeof(cp_rb));
    cp_rb_vmid = 0;
}

U32 GfxDevice::mmio_read(U32 index) {
    U32 value = 0;

    switch (index) {
    case mmCP_RB0_BASE:
        value = cp_rb[0].base >> 8;
        break;
    case mmCP_RB1_BASE:
        value = cp_rb[1].base >> 8;
        break;
    case mmCP_RB0_CNTL:
        value = cp_rb[0].cntl;
        break;
    case mmCP_RB1_CNTL:
        value = cp_rb[1].cntl;
        break;
    case mmCP_RB0_RPTR:
        value = cp_rb[0].rptr;
        break;
    case mmCP_RB1_RPTR:
        value = cp_rb[1].rptr;
        break;
    case mmCP_RB0_WPTR:
        value = cp_rb[0].wptr;
        break;
    case mmCP_RB1_WPTR:
        value = cp_rb[1].wptr;
        break;
    case mmCP_RB_VMID:
        value = cp_rb_vmid;
        break;
    case mmCP_INT_CNTL_RING0:
        value = cp_rb[0].int_cntl;
        break;
    case mmCP_INT_CNTL_RING1:
        value = cp_rb[1].int_cntl;
        break;

    case mmGRBM_STATUS:
        grbm_status.gui_active = grbm_status.gui_active ^ 1; // HACK
        value = grbm_status.value;
        break;
    case mmGRBM_STATUS2:
        value = 0; // TODO
        break;
    case mmGRBM_GFX_INDEX:
        value = 0; // TODO
        break;
    case mmVGT_EVENT_INITIATOR:
        value = vgt_event_initiator;
        break;
    case mmRLC_GPM_STAT:
        value = 2; // TODO
        break;
    case mmRLC_GPU_CLOCK_32_RES_SEL:
        value = 0; // TODO
        break;
    case mmRLC_GPU_CLOCK_32:
        value = Clock::now().time_since_epoch().count();
        value /= 1LL; // TODO
        value &= 0x7FFFFFFF;
        break;
    case mmRLC_PG_CNTL:
        value = 0; // TODO
        break;
    case mmRLC_MAX_PG_CU:
        value = 0; // TODO
        break;
    case mmRLC_SERDES_CU_MASTER_BUSY:
        value = 0; // TODO
        break;
    case mmCP_HQD_ACTIVE:
        value = 0; // TODO
        break;

    // Ignored access
    case mmCP_MEM_SLP_CNTL:
    case mmCP_IQ_WAIT_TIME1:
        break;

    default:
        //assert_always("Unimplemented");
        break;
    }

    return value;
}

void GfxDevice::mmio_write(U32 index, U32 value) {
    switch (index) {
    case mmCP_RB0_BASE:
        cp_rb[0].base = U64(value) << 8;
        break;
    case mmCP_RB1_BASE:
        cp_rb[1].base = U64(value) << 8;
        break;
    case mmCP_RB0_CNTL:
        cp_rb[0].cntl = value;
        break;
    case mmCP_RB1_CNTL:
        cp_rb[1].cntl = value;
        break;
    case mmCP_RB0_RPTR:
        cp_rb[0].rptr = value;
        break;
    case mmCP_RB1_RPTR:
        cp_rb[1].rptr = value;
        break;
    case mmCP_RB0_WPTR:
        cp_rb[0].wptr = value;
        break;
    case mmCP_RB1_WPTR:
        cp_rb[1].wptr = value;
        break;
    case mmCP_RB_VMID:
        cp_rb_vmid = value;
        break;
    case mmCP_INT_CNTL_RING0:
        cp_rb[0].int_cntl = value;
        break;
    case mmCP_INT_CNTL_RING1:
        cp_rb[1].int_cntl = value;
        break;

    // Microcode
    case mmCP_PFP_UCODE_ADDR:
        cp_pfp_ucode.addr = value;
        break;
    case mmCP_CE_UCODE_ADDR:
        cp_ce_ucode.addr = value;
        break;
    case mmCP_MEC_ME1_UCODE_ADDR:
        cp_mec_me1_ucode.addr = value;
        break;
    case mmCP_MEC_ME2_UCODE_ADDR:
        cp_mec_me2_ucode.addr = value;
        break;
    case mmRLC_GPM_UCODE_ADDR:
        rlc_gpm_ucode.addr = value;
        break;
    case mmCP_PFP_UCODE_DATA:
        cp_pfp_ucode.push(value);
        break;
    case mmCP_CE_UCODE_DATA:
        cp_ce_ucode.push(value);
        break;
    case mmCP_MEC_ME1_UCODE_DATA:
        cp_mec_me1_ucode.push(value);
        break;
    case mmCP_MEC_ME2_UCODE_DATA:
        cp_mec_me2_ucode.push(value);
        break;
    case mmRLC_GPM_UCODE_DATA:
        rlc_gpm_ucode.push(value);
        break;

    // Ignored registers
    case mmCP_RB_WPTR_POLL_CNTL:
    case mmCP_MEM_SLP_CNTL:
    case mmCP_IQ_WAIT_TIME1:
        break;
    case mmGRBM_GFX_INDEX:
    case mmRLC_PG_ALWAYS_ON_CU_MASK:
    case mmRLC_MAX_PG_CU:
    case mmRLC_PG_CNTL:
        break;

    default:
        //assert_always("Unimplemented");
        break;
    }
}

void GfxDevice::cp_task() {
    VkResult res;
    VkDevice dev = vk->getDevice();
    
    // Create command pool
    VkCommandPoolCreateInfo commandPoolInfo = {};
    commandPoolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    commandPoolInfo.queueFamilyIndex = vk->getQueueFamilyIndex();
    commandPoolInfo.flags =
        VK_COMMAND_POOL_CREATE_TRANSIENT_BIT |
        VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    res = vkCreateCommandPool(dev, &commandPoolInfo, NULL, &vk_cmdpool);
    vk_assert(res);

    // Create command buffer
    VkCommandBufferAllocateInfo commandBufferInfo = {};
    commandBufferInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    commandBufferInfo.commandPool = vk_cmdpool;
    commandBufferInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    commandBufferInfo.commandBufferCount = 1;
    res = vkAllocateCommandBuffers(dev, &commandBufferInfo, &vk_cmdbuf);
    vk_assert(res);

    // Create command fence
    VkFenceCreateInfo fenceInfo = {};
    fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    res = vkCreateFence(dev, &fenceInfo, NULL, &vk_cmdfence);
    vk_assert(res);

    auto& rb0 = cp_rb[0];
    auto& rb1 = cp_rb[1];
    while (true) {
        // Wait for packets
        if (rb0.idle() && rb1.idle()) {
            std::this_thread::sleep_for(1ms);
            continue;
        }
        if (!rb0.idle()) {
            cp_step(rb0);
        }
        if (!rb0.idle()) {
            cp_step(rb1);
        }
    }
}

void GfxDevice::cp_step(GfxRing& rb) {
    CpBuffer cp = {};
    cp.vmid = cp_rb_vmid;
    cp.base = rb.base;
    cp.rptr = rb.rptr;
    cp.size = rb.size();

    cp_handle_pm4(cp);
    rb.rptr += cp.rptr;
    rb.rptr &= cp.size - 1;
}

void GfxDevice::cp_read(CpBuffer& cp, U32* dwords, U32 count) {
    auto vm = gmc.get(cp.vmid);
    auto va = cp.base | cp.rptr;
    const auto size = count * sizeof(U32);
    vm.read(va, size, dwords);
    cp.rptr += size;
}

std::vector<U32> GfxDevice::cp_read(CpBuffer& cp, U32 count) {
    std::vector<U32> dwords(count);
    cp_read(cp, dwords.data(), dwords.size());
    return dwords;
}

void GfxDevice::cp_handle_pm4(CpBuffer& cp) {
    auto pm4 = cp_read<PM4Packet>(cp);
    switch (pm4.type) {
    case PM4_PACKET_TYPE0:
        cp_handle_pm4_type0(cp, pm4.type0);
        break;
    case PM4_PACKET_TYPE1:
        cp_handle_pm4_type1(cp, pm4.type1);
        break;
    case PM4_PACKET_TYPE2:
        cp_handle_pm4_type2(cp, pm4.type2);
        break;
    case PM4_PACKET_TYPE3:
        cp_handle_pm4_type3(cp, pm4.type3);
        break;
    }
}

void GfxDevice::cp_handle_pm4_type0(CpBuffer& cp, PM4Packet::Type0 p) {
    const auto size = p.count + 1;
    const auto data = cp_read(cp, size);

    U32 index = p.reg;
    for (auto reg : data) {
        mmio_write(index++, reg);
    }
}

void GfxDevice::cp_handle_pm4_type1(CpBuffer& cp, PM4Packet::Type1 p) {
    assert_always("Unsupported packet type");
}

void GfxDevice::cp_handle_pm4_type2(CpBuffer& cp, PM4Packet::Type2 p) {
    assert_always("Unsupported packet type");
}

void GfxDevice::cp_handle_pm4_type3(CpBuffer& cp, PM4Packet::Type3 p) {
    const auto rptr_old = cp.rptr;

    switch (p.itop) {
    case PM4_IT_INDIRECT_BUFFER_CONST:
        cp_handle_pm4_it_indirect_buffer_const(cp);
        break;
    case PM4_IT_INDIRECT_BUFFER:
        cp_handle_pm4_it_indirect_buffer(cp);
        break;
    case PM4_IT_SET_CONFIG_REG:
    case PM4_IT_SET_CONTEXT_REG:
    case PM4_IT_SET_SH_REG:
    case PM4_IT_SET_UCONFIG_REG:
        cp_handle_pm4_it_set_reg(cp, p);
        break;

    // Ignored commands
    case PM4_IT_PREAMBLE_CNTL:
    case PM4_IT_CONTEXT_CONTROL:
    case PM4_IT_CLEAR_STATE:
    case PM4_IT_SET_BASE:
        break;
#if 0
    case PM4_IT_DRAW_INDEX_AUTO:
        cp_handle_pm4_it_draw_index_auto(s, vmid, packet);
        break;
    case PM4_IT_EVENT_WRITE_EOP:
        cp_handle_pm4_it_event_write_eop(s, vmid, packet);
        break;
    case PM4_IT_NUM_INSTANCES:
        cp_handle_pm4_it_num_instances(s, vmid, packet);
        break;
    case PM4_IT_WAIT_REG_MEM:
        cp_handle_pm4_it_wait_reg_mem(s, vmid, packet);
        break;
#endif
    default:
        printf("PM4: %s\n", pm4_itop_name(p.itop));
        assert_always("Unimplemented");
    }

    // TODO: Once all commands are implemented, turn this into an assert
    const auto rptr_new = rptr_old + sizeof(U32) * (p.count + 1);
    if (cp.rptr != rptr_new) {
        cp.rptr = rptr_new;
    }
}

void GfxDevice::cp_handle_pm4_it_indirect_buffer(CpBuffer& cp) {
    const auto args = cp_read<PM4_IndirectBuffer>(cp);

    CpBuffer cp_ib = {};
    cp_ib.base = args.base;
    cp_ib.size = args.size * sizeof(U32);
    cp_ib.vmid = args.vmid;
    while (cp_ib.rptr < cp_ib.size) {
        cp_handle_pm4(cp_ib);
    }
}

void GfxDevice::cp_handle_pm4_it_indirect_buffer_const(CpBuffer& cp) {
    cp_handle_pm4_it_indirect_buffer(cp);
}

void GfxDevice::cp_handle_pm4_it_set_reg(CpBuffer& cp, PM4Packet::Type3 p) {
    auto block_base = 0;
    auto block_size = 0;
    switch (p.itop) {
    case PM4_IT_SET_CONFIG_REG:
        block_base = 0x2000;
        block_size = 0xC00;
        break;
    case PM4_IT_SET_CONTEXT_REG:
        block_base = 0xA000;
        block_size = 0x400;
        break;
    case PM4_IT_SET_SH_REG:
        block_base = 0x2C00;
        block_size = 0x400;
        break;
    case PM4_IT_SET_UCONFIG_REG:
        block_base = 0xC000;
        block_size = 0x2000;
        break;
    default:
        assert_always("Unknown region");
    }

    const auto args = cp_read<PM4_SetReg>(cp);
    const auto reg_size = p.count - 1;
    const auto reg_data = cp_read(cp, reg_size);

    U32 reg_offset = args.offset;
    assert(reg_offset + reg_size <= block_size);
    for (auto reg : reg_data) {
        mmio_write(block_base + reg_offset, reg);
        reg_offset += 1;
    }
}
    }
}
