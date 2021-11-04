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
