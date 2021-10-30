/**
 * AMD Interrupt Handler (IH) device.
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

#include <mutex>

// Forward declarations
class GmcDevice;

constexpr auto OSS_MMIO_IH = OffsetRange(0xF50, 0x40);

// IV SRC identifiers
enum {
    IV_SRCID_DCE_CRTC0            = 0x01, // 1
    IV_SRCID_DCE_CRTC1            = 0x02, // 2
    IV_SRCID_DCE_CRTC2            = 0x03, // 3
    IV_SRCID_DCE_CRTC3            = 0x04, // 4
    IV_SRCID_DCE_CRTC4            = 0x05, // 5
    IV_SRCID_DCE_CRTC5            = 0x06, // 6
    IV_SRCID_DCE_DCP0_VUPDATE     = 0x07, // 7
    IV_SRCID_DCE_DCP0_PFLIP       = 0x08, // 8
    IV_SRCID_DCE_DCP1_VUPDATE     = 0x09, // 9
    IV_SRCID_DCE_DCP1_PFLIP       = 0x0A, // 10
    IV_SRCID_DCE_DCP2_VUPDATE     = 0x0B, // 11
    IV_SRCID_DCE_DCP2_PFLIP       = 0x0C, // 12
    IV_SRCID_DCE_DCP3_VUPDATE     = 0x0D, // 13
    IV_SRCID_DCE_DCP3_PFLIP       = 0x0E, // 14
    IV_SRCID_DCE_DCP4_VUPDATE     = 0x0F, // 15
    IV_SRCID_DCE_DCP4_PFLIP       = 0x10, // 16
    IV_SRCID_DCE_DCP5_VUPDATE     = 0x11, // 17
    IV_SRCID_DCE_DCP5_PFLIP       = 0x12, // 18
    IV_SRCID_DCE_DCP0_EXT         = 0x13, // 19
    IV_SRCID_DCE_DCP1_EXT         = 0x14, // 20
    IV_SRCID_DCE_DCP2_EXT         = 0x15, // 21
    IV_SRCID_DCE_DCP3_EXT         = 0x16, // 22
    IV_SRCID_DCE_DCP4_EXT         = 0x17, // 23
    IV_SRCID_DCE_DCP5_EXT         = 0x18, // 24
    IV_SRCID_DCE_SCANIN           = 0x34, // 52
    IV_SRCID_DCE_SCANIN_ERROR     = 0x35, // 53
    IV_SRCID_UVD_TRAP             = 0x7C, // 124
    IV_SRCID_GMC_VM_FAULT0        = 0x92, // 146
    IV_SRCID_GMC_VM_FAULT1        = 0x93, // 147
    IV_SRCID_SAM                  = 0x98, // 152
    IV_SRCID_ACP                  = 0xA2, // 162
    IV_SRCID_GFX_EOP              = 0xB5, // 181
    IV_SRCID_GFX_PRIV_REG         = 0xB8, // 184
    IV_SRCID_GFX_PRIV_INST        = 0xB9, // 185
    IV_SRCID_SDMA_TRAP            = 0xE0, // 224

    IV_SRCID_UNK0_B4              = 0xB4,
    IV_SRCID_UNK0_B7              = 0xB7,
    IV_SRCID_UNK0_BC              = 0xBC,
    IV_SRCID_UNK0_BD              = 0xBD,
    IV_SRCID_UNK2_F0              = 0xF0,
    IV_SRCID_UNK2_F3              = 0xF3,
    IV_SRCID_UNK2_F5              = 0xF5,
    IV_SRCID_UNK3_GUI_IDLE        = 0xE9,
    IV_SRCID_UNK4_EF              = 0xEF,
};

// IV EXT identifiers
enum {
    IV_EXTID_VERTICAL_INTERRUPT0  = 0x07, // 7
    IV_EXTID_VERTICAL_INTERRUPT1  = 0x08, // 8
    IV_EXTID_VERTICAL_INTERRUPT2  = 0x09, // 9
    IV_EXTID_EXT_TIMING_SYNC_LOSS = 0x0A, // 10
    IV_EXTID_EXT_TIMING_SYNC      = 0x0B, // 11
    IV_EXTID_EXT_TIMING_SIGNAL    = 0x0C, // 12
};

class IhDevice : public Device {
public:
    IhDevice(PCIeDevice& gc, GmcDevice& gmc);

    void reset();

    /**
     * Push an interrupt.
     */
    void push_iv(U32 vmid, U32 id, U32 data);

    U32 mmio_read(U32 index);
    void mmio_write(U32 index, U32 value);

private:
    PCIeDevice& gc;
    GmcDevice& gmc;
    std::mutex mutex;

    U32 vmid_lut[16];
    union {
        U32 rb_cntl;
        struct {
            U32 rb_enable                 : 1;
            U32 rb_size_log2              : 5;
            U32 rb_full_drain_enable      : 1;
            U32                           : 1;
            U32 wptr_writeback_enable     : 1;
            U32 wptr_writeback_timer_log2 : 7;
            U32 wptr_overflow_enable      : 1;
            U32                           : 14;
            U32 wptr_overflow_clear       : 1;
        };
    };
    U32 rb_base;
    U32 rb_rptr;
    U32 rb_wptr;
    union {
        U64 rb_wptr_addr;
        struct {
            U32 rb_wptr_addr_lo;
            U32 rb_wptr_addr_hi;
        };
    };
    union {
        U32 cntl;
        struct {
            U32 enable_intr     : 1;
            U32 mc_swap         : 3;
            U32 rptr_rearm      : 1;
            U32                 : 10;
            U32 mc_wrreq_credit : 5;
            U32 mc_wr_clean_bit : 5;
            U32 mc_vmid         : 5;
        };
    };
    U32 level_status;  
    union {
        U32 status;
        struct {
            U32 status_idle                 : 1; // 0x1
            U32 status_input_idle           : 1; // 0x2
            U32 status_rb_idle              : 1; // 0x4
            U32 status_rb_full              : 1; // 0x8
            U32 status_rb_full_drain        : 1; // 0x10
            U32 status_rb_overflow          : 1; // 0x20
            U32 status_mc_wr_idle           : 1; // 0x40
            U32 status_mc_wr_stall          : 1; // 0x80
            U32 status_mc_wr_clean_pending  : 1; // 0x100
            U32 status_mc_wr_clean_stall    : 1; // 0x200
            U32 status_bif_interrupt_line   : 1; // 0x400
        };
    };
    U32 perfmon_cntl;       
    U32 perfcounter0_result;
    U32 perfcounter1_result;
    U32 advfault_cntl;

    /**
     * Get IH ringbuffer size.
     * @return  Size of ringbuffer in bytes
     */
    U64 rb_size() const noexcept {
        return 1 << rb_size_log2;
    }

    /**
     * Push 32-bit integer into the current ringbuffer at VMID 0.
     * @param[in]  value  Value to be pushed
     */
    void rb_push(U32 value);
};
