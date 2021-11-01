/**
 * AMD Graphics and Compute Array (GCA aka GFX).
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <orbital/core.h>
#include <orbital/host/graphics/vulkan.h>
#include <orbital/offset_range.h>
#include "pm4.h"

#include <vulkan/vulkan.h>

#include <thread>

// Forward declarations
class GmcDevice;
class IhDevice;

constexpr auto GFX_MMIO_CP_0 = OffsetRange(0X219D, 0x26);
constexpr auto GFX_MMIO_CP_1 = OffsetRange(0x3020, 0x98);

struct GfxDeviceConfig : DeviceConfig {
    VulkanManager* vk;
};

struct GfxRing {
    U64 base;
    U32 rptr;
    U32 wptr;
    union {
        U32 cntl;
        Bitfield<U32, 0, 6> cntl_rb_bufsz_log2;
        Bitfield<U32, 8, 6> cntl_rb_blksz_log2;
    };
    union {
        U32 int_cntl;
        Bit<U32, 14> enable_int_cp_ecc_error;
        Bit<U32, 17> enable_int_wrm_poll_timeout;
        Bit<U32, 19> enable_int_cntx_busy;
        Bit<U32, 20> enable_int_cntx_empty;
        Bit<U32, 22> enable_int_priv_instr;
        Bit<U32, 23> enable_int_priv_reg;
        Bit<U32, 24> enable_int_opcode_error;
        Bit<U32, 26> enable_int_time_stamp;
        Bit<U32, 27> enable_int_reserved_bit_error;
        Bit<U32, 29> enable_int_generic2;
        Bit<U32, 30> enable_int_generic1;
        Bit<U32, 31> enable_int_generic0;
    };

    bool idle() const noexcept {
        return rptr == wptr;
    }
    U32 size() const noexcept {
        return UINT64_C(8) << cntl_rb_bufsz_log2;
    }
};

class GfxDevice : public Device {
public:
    GfxDevice(GmcDevice& gmc, IhDevice& ih, const GfxDeviceConfig& config = {});

    void reset();

    U32 mmio_read(U32 index);
    void mmio_write(U32 index, U32 value);

private:
    GmcDevice& gmc;
    IhDevice& ih;
    std::thread cp_thread;

    VulkanManager* vk;
    VkCommandPool vk_cmdpool;
    VkCommandBuffer vk_cmdbuf;
    VkFence vk_cmdfence;

    // Command Processor
    GfxRing cp_rb[2];
    U32 cp_rb_vmid;
    U32 cp_vmid;

    void cp_task();
    void cp_step(GfxRing& rb);
    void cp_read(GfxRing& rb, void* data, U32 size);

    void cp_handle_pm4(GfxRing& rb, PM4Packet p);
    void cp_handle_pm4_type0(GfxRing& rb, PM4Packet::Type0 p);
    void cp_handle_pm4_type1(GfxRing& rb, PM4Packet::Type1 p);
    void cp_handle_pm4_type2(GfxRing& rb, PM4Packet::Type2 p);
    void cp_handle_pm4_type3(GfxRing& rb, PM4Packet::Type3 p);

    template <typename T>
    T cp_read(GfxRing& rb) {
        static_assert(sizeof(T) % 4 == 0);
        T value;
        cp_read(rb, &value, sizeof(T));
        return value;
    }
};
