/**
 * AMD Secure Asset Management Unit (SAMU) device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

// SAMU
#define mmSAM_IX_INDEX                    0x00008800
#define mmSAM_IX_DATA                     0x00008801
#define mmSAM_SAB_IX_INDEX                0x00008802
#define mmSAM_SAB_IX_DATA                 0x00008803
#define mmSAM_UNK881C                     0x0000881C

// SAMU IX                               
#define ixSAM_RST_HOST_SOFT_RESET         0x00000001
#define ixSAM_CGC_HOST_CTRL               0x00000003
#define ixSAM_IH_CPU_AM32_INT             0x00000032
#define ixSAM_IH_CPU_AM32_INT_CTX_HIGH    0x00000033
#define ixSAM_IH_CPU_AM32_INT_CTX_LOW     0x00000034
#define ixSAM_IH_AM32_CPU_INT_CTX_HIGH    0x00000035
#define ixSAM_IH_AM32_CPU_INT_CTX_LOW     0x00000036
#define ixSAM_IH_AM32_CPU_INT_ACK         0x00000037
#define ixSAM_IH_CPU_AM32_INT_STATUS      0x0000004A
#define ixSAM_IH_AM32_CPU_INT_STATUS      0x0000004B
#define ixSAM_RST_HOST_SOFT_RST_RDY       0x00000051

// SAMU SAB IX                           
#define ixSAM_SAB_INIT_TLB_CONFIG         0x00000004
#define ixSAM_SAB_UNK29                   0x00000029

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

class SAMUDevice : public Device {

};
