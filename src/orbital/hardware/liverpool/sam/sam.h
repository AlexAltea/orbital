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

#pragma once

#include <orbital/core.h>
#include <orbital/offset_range.h>

// Forward declarations
class GmcDevice;
class IhDevice;
class SmuDevice;

constexpr auto SAM_MMIO  = OffsetRange(0x8800, 0x100);
constexpr auto SAM0_MMIO = OffsetRange(0x8800, 0x100);
constexpr auto SAM1_MMIO = OffsetRange(0x8900, 0x100);

// SAMU
#define mmSAM_IX_INDEX                    0x8800
#define mmSAM_IX_DATA                     0x8801
#define mmSAM_SAB_IX_INDEX                0x8802
#define mmSAM_SAB_IX_DATA                 0x8803
#define mmSAM_IND_INDEX                   0x8800
#define mmSAM_IND_DATA                    0x8801
#define mmSAM_AM32_BOOT_BASE              0x8809
#define mmSAM_AM32_BOOT_OFFSET            0x880A
#define mmSAM_AM32_BOOT_LENGTH            0x880B
#define mmSAM_AM32_BOOT_CTRL              0x880C
#define mmSAM_AM32_BOOT_STATUS            0x880D
#define mmSAM_AM32_BOOT_HASH0             0x880E
#define mmSAM_AM32_BOOT_HASH1             0x880F
#define mmSAM_AM32_BOOT_HASH2             0x8810
#define mmSAM_AM32_BOOT_HASH3             0x8811
#define mmSAM_AM32_BOOT_HASH4             0x8812
#define mmSAM_AM32_BOOT_HASH5             0x8813
#define mmSAM_AM32_BOOT_HASH6             0x8814
#define mmSAM_AM32_BOOT_HASH7             0x8815
#define mmSAM_EMU_SRCID                   0x8816
#define mmSAM_GPR_SCRATCH_4               0x8818
#define mmSAM_GPR_SCRATCH_5               0x8819
#define mmSAM_GPR_SCRATCH_6               0x881A
#define mmSAM_GPR_SCRATCH_7               0x881B
#define mmSAM_GPR_SCRATCH_0               0x881C
#define mmSAM_GPR_SCRATCH_1               0x881D
#define mmSAM_GPR_SCRATCH_2               0x881E
#define mmSAM_GPR_SCRATCH_3               0x881F
#define mmSAM_POWER_GATE                  0x8834
#define mmSAM_BOOT_PWR_UP                 0x8835
#define mmSAM_SMU_ALLOW_MEM_ACCESS        0x8836
#define mmSAM_PGFSM_CONFIG_REG            0x8837
#define mmSAM_PGFSM_WRITE_REG             0x8838
#define mmSAM_PGFSM_READ_REG              0x8839
#define mmSAM_PKI_FAIL_STATUS             0x883A

// SAMU IX                               
#define ixSAM_RST_HOST_SOFT_RESET         0x0001
#define ixSAM_CGC_HOST_CTRL               0x0003
#define ixSAM_IH_CPU_AM32_INT             0x0032
#define ixSAM_IH_CPU_AM32_INT_CTX_HIGH    0x0033
#define ixSAM_IH_CPU_AM32_INT_CTX_LOW     0x0034
#define ixSAM_IH_AM32_CPU_INT_CTX_HIGH    0x0035
#define ixSAM_IH_AM32_CPU_INT_CTX_LOW     0x0036
#define ixSAM_IH_AM32_CPU_INT_ACK         0x0037
#define ixSAM_UNK3E                       0x003E
#define ixSAM_IH_CPU_AM32_INT_STATUS      0x004A
#define ixSAM_IH_AM32_CPU_INT_STATUS      0x004B
#define ixSAM_RST_HOST_SOFT_RST_RDY       0x0051

// SAMU SAB IX                           
#define ixSAM_SAB_INIT_TLB_CONFIG         0x0004
#define ixSAM_SAB_UNK29                   0x0029

/* SAMU Commands */
struct samu_command_io_open_t {
    char name[8];
};

struct samu_command_io_close_t {
    LE<U32> fd;
};

struct samu_command_io_read_t {
    LE<U32> fd;
    LE<U32> size;
    LE<U08> data[0];
};

struct samu_command_io_write_t {
    LE<U32> fd;
    LE<U32> size;
    LE<U08> data[0];
};

struct samu_command_io_seek_t {
    LE<U32> fd;
    LE<U32> offset;
};

struct samu_command_service_spawn_t {
    char name[16];
    LE<U32> args[4];
};

struct samu_command_service_ccp_t {
    LE<U32> opcode;
    LE<U32> status;

    union {
        struct {
            LE<U64> data_size;
            LE<U64> in_addr;
            LE<U64> out_addr;
            LE<U08> key[0x20];
            LE<U08> iv[0x10];
        } aes;

        struct {
            LE<U32> num_sectors;
            LE<U64> in_addr;
            LE<U64> out_addr;
            LE<U64> start_sector;
            LE<U08> key[0x20];
        } xts;

        struct {
            LE<U64> data_size;
            LE<U64> in_addr;
            LE<U64> out_addr;
            LE<U08> hash[0x20];
        } sha;

        struct {
            LE<U64> data_size;
            LE<U64> data_addr;
            LE<U64> data_size_bits;
            LE<U08> hash[0x20];
            LE<U08> key[0x40];
            LE<U64> key_size;
        } hmac;

        struct {
            LE<U08> data[0x20];
        } rng;

        struct {
            LE<U32> unk_08;
            LE<U32> in_size;
            LE<U32> out_size;
            LE<U32> unk_14;
            LE<U64> in_addr;
            LE<U64> out_addr;
        } zlib;
    };
};

struct samu_command_service_rand_t {
    LE<U08> data[0x10];
};

class SamDevice : public Device {
public:
    SamDevice(GmcDevice& gmc, IhDevice& ih, SmuDevice& smu);

    void reset();

    U32 mmio_read(U32 index);
    void mmio_write(U32 index, U32 value);

private:
    GmcDevice& gmc;
    IhDevice& ih;
    SmuDevice& smu;

    std::array<U32, 4> gpr;
    std::array<U32, 0x80> ix_data;
    std::array<U32, 0x40> sab_ix_data;
    U32 ix_index;
    U32 sab_ix_index;

    U32 ih_cpu_am32_int_status;
    U32 ih_am32_cpu_int_status;
    union {
        LE<U64> ih_cpu_am32_int_ctx;
        Bitfield<U64, 48, 16> ih_cpu_am32_int_flags;
        struct {
            LE<U32> ih_cpu_am32_int_ctx_low;
            LE<U32> ih_cpu_am32_int_ctx_high;
        };
    };
    union {
        LE<U64> ih_am32_cpu_int_ctx;
        struct {
            LE<U32> ih_am32_cpu_int_ctx_low;
            LE<U32> ih_am32_cpu_int_ctx_high;
        };
    };

    void handle_request(U32 value);
};
