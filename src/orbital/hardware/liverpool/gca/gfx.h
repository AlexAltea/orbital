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
#include <orbital/hardware/liverpool/amd_ucode.h>
#include <orbital/host/graphics/vulkan.h>
#include <orbital/offset_range.h>
#include "pm4.h"

#include <vulkan/vulkan.h>

#include <thread>

// Forward declarations
class GmcDevice;
class IhDevice;

constexpr auto GFX_MMIO_CP_0    = OffsetRange(0x219D, 0x26);
constexpr auto GFX_MMIO_CP_1    = OffsetRange(0x3020, 0x98);
constexpr auto GFX_MMIO_RLC     = OffsetRange(0x30C0, 0x78);
constexpr auto GFX_MMIO_SPI     = OffsetRange(0x31C0, 0x40);
constexpr auto GFX_MMIO_CP_HPD  = OffsetRange(0x3240, 0x40);
constexpr auto GFX_MMIO_GDS     = OffsetRange(0x3300, 0x50);
constexpr auto GFX_MMIO_CONFIG  = OffsetRange(0x2000, 0xC00);
constexpr auto GFX_MMIO_SH      = OffsetRange(0x2C00, 0x400);
constexpr auto GFX_MMIO_CONTEXT = OffsetRange(0xA000, 0x400);
constexpr auto GFX_MMIO_UCONFIG = OffsetRange(0xC000, 0x2000);

constexpr bool gfx_mmio_contains(U32 index) {
    return GFX_MMIO_CP_0.contains(index)
        || GFX_MMIO_CP_1.contains(index)
        || GFX_MMIO_RLC.contains(index)
        || GFX_MMIO_SPI.contains(index)
        || GFX_MMIO_CP_HPD.contains(index)
        || GFX_MMIO_GDS.contains(index)
        || GFX_MMIO_CONFIG.contains(index)
        || GFX_MMIO_SH.contains(index)
        || GFX_MMIO_CONTEXT.contains(index)
        || GFX_MMIO_UCONFIG.contains(index);
}

struct GfxDeviceConfig : DeviceConfig {
    VulkanManager* vk;
};

struct CpBuffer {
    U64 base;
    U64 size;
    U32 rptr;
    U32 vmid;
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

    // Config
    union {
        U32 data_config[0xC00];
        struct {
            U32 grbm_cntl;
            U32 grbm_status2;
            U32 reserved[2];
            union {
                U32 value;
                Bit<U32,  5> srbm_rq_pending;
                Bit<U32,  7> me0pipe0_cf_rq_pending;
                Bit<U32,  8> me0pipe0_pf_rq_pending;
                Bit<U32,  9> gds_dma_rq_pending;
                Bit<U32, 12> db_clean;
                Bit<U32, 13> cb_clean;
                Bit<U32, 14> ta_busy;
                Bit<U32, 15> gds_busy;
                Bit<U32, 16> wd_busy_no_dma;
                Bit<U32, 17> vgt_busy;
                Bit<U32, 18> ia_busy_no_dma;
                Bit<U32, 19> ia_busy;
                Bit<U32, 20> sx_busy;
                Bit<U32, 21> wd_busy;
                Bit<U32, 22> spi_busy;
                Bit<U32, 23> bci_busy;
                Bit<U32, 24> sc_busy;
                Bit<U32, 25> pa_busy;
                Bit<U32, 26> db_busy;
                Bit<U32, 28> cp_coherency_busy;
                Bit<U32, 29> cp_busy;
                Bit<U32, 30> cb_busy;
                Bit<U32, 31> gui_active;
            } grbm_status;
        };
    };
    union {
        U32 data_context[0x400];
        struct {
            U32 vgt_event_initiator;
        };
    };

#if 0
    vk_attachment_t* att_cache[16];
    size_t att_cache_size;
    gfx_pipeline_t* pipeline;
#endif
    // Microcode
    AmdUcode<0x2000> cp_pfp_ucode;
    AmdUcode<0x2000> cp_ce_ucode;
    AmdUcode<0x2000> cp_mec_me1_ucode;
    AmdUcode<0x2000> cp_mec_me2_ucode;
    AmdUcode<0x2000> rlc_gpm_ucode;
    AmdUcode<0x2000> cp_me_ram;

    // Command Processor
    GfxRing cp_rb[2];
    U32 cp_rb_vmid;
    U32 cp_vmid;

    void cp_task();
    void cp_step(GfxRing& rb);
    void cp_read(CpBuffer& cp, U32* dwords, U32 count);
    std::vector<U32> cp_read(CpBuffer& cp, U32 count);

    void cp_handle_pm4(CpBuffer& cp);
    void cp_handle_pm4_type0(CpBuffer& cp, PM4Packet::Type0 p);
    void cp_handle_pm4_type1(CpBuffer& cp, PM4Packet::Type1 p);
    void cp_handle_pm4_type2(CpBuffer& cp, PM4Packet::Type2 p);
    void cp_handle_pm4_type3(CpBuffer& cp, PM4Packet::Type3 p);

    void cp_handle_pm4_it_indirect_buffer(CpBuffer& cp);
    void cp_handle_pm4_it_indirect_buffer_const(CpBuffer& cp);
    void cp_handle_pm4_it_set_reg(CpBuffer& cp, PM4Packet::Type3 p);

    template <typename T>
    T cp_read(CpBuffer& cp) {
        static_assert(sizeof(T) % 4 == 0);
        T value;
        constexpr auto dw_count = sizeof(T) / sizeof(U32);
        cp_read(cp, reinterpret_cast<U32*>(&value), dw_count);
        return value;
    }
};
