/**
 * AMD PM4 packets.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <orbital/core.h>

enum {
    PM4_PACKET_TYPE0                 = 0x00,
    PM4_PACKET_TYPE1                 = 0x01,
    PM4_PACKET_TYPE2                 = 0x02,
    PM4_PACKET_TYPE3                 = 0x03,
};

enum {
    PM4_IT_NOP                       = 0x10,
    PM4_IT_SET_BASE                  = 0x11,
    PM4_IT_CLEAR_STATE               = 0x12,
    PM4_IT_INDEX_BUFFER_SIZE         = 0x13,
    PM4_IT_DISPATCH_DIRECT           = 0x15,
    PM4_IT_DISPATCH_INDIRECT         = 0x16,
    PM4_IT_ATOMIC_GDS                = 0x1D,
    PM4_IT_OCCLUSION_QUERY           = 0x1F,
    PM4_IT_SET_PREDICATION           = 0x20,
    PM4_IT_REG_RMW                   = 0x21,
    PM4_IT_COND_EXEC                 = 0x22,
    PM4_IT_PRED_EXEC                 = 0x23,
    PM4_IT_DRAW_INDIRECT             = 0x24,
    PM4_IT_DRAW_INDEX_INDIRECT       = 0x25,
    PM4_IT_INDEX_BASE                = 0x26,
    PM4_IT_DRAW_INDEX_2              = 0x27,
    PM4_IT_CONTEXT_CONTROL           = 0x28,
    PM4_IT_INDEX_TYPE                = 0x2A,
    PM4_IT_DRAW_INDIRECT_MULTI       = 0x2C,
    PM4_IT_DRAW_INDEX_AUTO           = 0x2D,
    PM4_IT_NUM_INSTANCES             = 0x2F,
    PM4_IT_DRAW_INDEX_MULTI_AUTO     = 0x30,
    PM4_IT_INDIRECT_BUFFER_CONST     = 0x33,
    PM4_IT_STRMOUT_BUFFER_UPDATE     = 0x34,
    PM4_IT_DRAW_INDEX_OFFSET_2       = 0x35,
    PM4_IT_DRAW_PREAMBLE             = 0x36,
    PM4_IT_WRITE_DATA                = 0x37,
    PM4_IT_DRAW_INDEX_INDIRECT_MULTI = 0x38,
    PM4_IT_MEM_SEMAPHORE             = 0x39,
    PM4_IT_COPY_DW                   = 0x3B,
    PM4_IT_WAIT_REG_MEM              = 0x3C,
    PM4_IT_INDIRECT_BUFFER           = 0x3F,
    PM4_IT_COPY_DATA                 = 0x40,
    PM4_IT_PFP_SYNC_ME               = 0x42,
    PM4_IT_SURFACE_SYNC              = 0x43,
    PM4_IT_COND_WRITE                = 0x45,
    PM4_IT_EVENT_WRITE               = 0x46,
    PM4_IT_EVENT_WRITE_EOP           = 0x47,
    PM4_IT_EVENT_WRITE_EOS           = 0x48,
    PM4_IT_RELEASE_MEM               = 0x49,
    PM4_IT_PREAMBLE_CNTL             = 0x4A,
    PM4_IT_DMA_DATA                  = 0x50,
    PM4_IT_ACQUIRE_MEM               = 0x58,
    PM4_IT_REWIND                    = 0x59,
    PM4_IT_LOAD_UCONFIG_REG          = 0x5E,
    PM4_IT_LOAD_SH_REG               = 0x5F,
    PM4_IT_LOAD_CONFIG_REG           = 0x60,
    PM4_IT_LOAD_CONTEXT_REG          = 0x61,
    PM4_IT_SET_CONFIG_REG            = 0x68,
    PM4_IT_SET_CONTEXT_REG           = 0x69,
    PM4_IT_SET_CONTEXT_REG_INDIRECT  = 0x73,
    PM4_IT_SET_SH_REG                = 0x76,
    PM4_IT_SET_SH_REG_OFFSET         = 0x77,
    PM4_IT_SET_QUEUE_REG             = 0x78,
    PM4_IT_SET_UCONFIG_REG           = 0x79,
    PM4_IT_SCRATCH_RAM_WRITE         = 0x7D,
    PM4_IT_SCRATCH_RAM_READ          = 0x7E,
    PM4_IT_LOAD_CONST_RAM            = 0x80,
    PM4_IT_WRITE_CONST_RAM           = 0x81,
    PM4_IT_DUMP_CONST_RAM            = 0x83,
    PM4_IT_INCREMENT_CE_COUNTER      = 0x84,
    PM4_IT_INCREMENT_DE_COUNTER      = 0x85,
    PM4_IT_WAIT_ON_CE_COUNTER        = 0x86,
    PM4_IT_WAIT_ON_DE_COUNTER_DIFF   = 0x88,
    PM4_IT_SWITCH_BUFFER             = 0x8B,
    PM4_IT_SET_RESOURCES             = 0xA0,
    PM4_IT_MAP_PROCESS               = 0xA1,
    PM4_IT_MAP_QUEUES                = 0xA2,
    PM4_IT_UNMAP_QUEUES              = 0xA3,
    PM4_IT_QUERY_STATUS              = 0xA4,
    PM4_IT_RUN_LIST                  = 0xA5,
};

union PM4Packet {
    U32 value;
    Bitrange<U32, 30, 31> type;
    struct Type0 {
        Bitrange<U32,  0, 15> reg;
        Bitrange<U32, 16, 29> count;
    } type0;
    struct Type1 {
    } type1;
    struct Type2 {
    } type2;
    struct Type3 {
        Bitrange<U32,  0,  0> pred;
        Bitrange<U32,  1,  1> shtype;
        Bitrange<U32,  8, 15> itop;
        Bitrange<U32, 16, 29> count;
    } type3;
};

// Debugging
const char* pm4_itop_name(U32 itop);
