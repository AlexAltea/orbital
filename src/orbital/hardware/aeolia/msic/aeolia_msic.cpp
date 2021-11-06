/**
 * Aeolia MSI Controller (MSIC) device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "aeolia_msic.h"

#define REG_MSI(x)                                                    (x)
#define REG_MSI_CONTROL                                    REG_MSI(0x000)
#define REG_MSI_UNK004                                     REG_MSI(0x004)
#define REG_MSI_UNK008                                     REG_MSI(0x008) // Always 0xFFFFFFFF?

// Always 0xB7FFFFX0?
#define REG_MSI_UNK00C(func)              (REG_MSI(0x00C) + 4*(func & 7))
#define REG_MSI_FNC0_UNK00C                             REG_MSI_UNK00C(0)
#define REG_MSI_FNC1_UNK00C                             REG_MSI_UNK00C(1)
#define REG_MSI_FNC2_UNK00C                             REG_MSI_UNK00C(2)
#define REG_MSI_FNC3_UNK00C                             REG_MSI_UNK00C(3)
#define REG_MSI_FNC4_UNK00C                             REG_MSI_UNK00C(4)
#define REG_MSI_FNC5_UNK00C                             REG_MSI_UNK00C(5)
#define REG_MSI_FNC6_UNK00C                             REG_MSI_UNK00C(6)
#define REG_MSI_FNC7_UNK00C                             REG_MSI_UNK00C(7)

#define REG_MSI_IRQ_STA(func)             (REG_MSI(0x02C) + 4*(func & 7))
#define REG_MSI_FNC0_IRQ_STA                           REG_MSI_IRQ_STA(0)
#define REG_MSI_FNC1_IRQ_STA                           REG_MSI_IRQ_STA(1)
#define REG_MSI_FNC2_IRQ_STA                           REG_MSI_IRQ_STA(2)
#define REG_MSI_FNC3_IRQ_STA                           REG_MSI_IRQ_STA(3)
#define REG_MSI_FNC4_IRQ_STA                           REG_MSI_IRQ_STA(4)
#define REG_MSI_FNC5_IRQ_STA                           REG_MSI_IRQ_STA(5)
#define REG_MSI_FNC6_IRQ_STA                           REG_MSI_IRQ_STA(6)
#define REG_MSI_FNC7_IRQ_STA                           REG_MSI_IRQ_STA(7)

#define REG_MSI_MASK(func)                (REG_MSI(0x04C) + 4*(func & 7))
#define REG_MSI_FNC0_MASK                                 REG_MSI_MASK(0)
#define REG_MSI_FNC1_MASK                                 REG_MSI_MASK(1)
#define REG_MSI_FNC2_MASK                                 REG_MSI_MASK(2)
#define REG_MSI_FNC3_MASK                                 REG_MSI_MASK(3)
#define REG_MSI_FNC4_MASK                                 REG_MSI_MASK(4)
#define REG_MSI_FNC5_MASK                                 REG_MSI_MASK(5)
#define REG_MSI_FNC6_MASK                                 REG_MSI_MASK(6)
#define REG_MSI_FNC7_MASK                                 REG_MSI_MASK(7)

#define REG_MSI_DATA(func)                (REG_MSI(0x08C) + 4*(func & 7))
#define REG_MSI_FNC0_DATA                                 REG_MSI_DATA(0)
#define REG_MSI_FNC1_DATA                                 REG_MSI_DATA(1)
#define REG_MSI_FNC2_DATA                                 REG_MSI_DATA(2)
#define REG_MSI_FNC3_DATA                                 REG_MSI_DATA(3)
#define REG_MSI_FNC4_DATA                                 REG_MSI_DATA(4)
#define REG_MSI_FNC5_DATA                                 REG_MSI_DATA(5)
#define REG_MSI_FNC6_DATA                                 REG_MSI_DATA(6)
#define REG_MSI_FNC7_DATA                                 REG_MSI_DATA(7)

#define REG_MSI_ADDR(func)                (REG_MSI(0x0AC) + 4*(func & 7))
#define REG_MSI_FNC0_ADDR                                 REG_MSI_ADDR(0)
#define REG_MSI_FNC1_ADDR                                 REG_MSI_ADDR(1)
#define REG_MSI_FNC2_ADDR                                 REG_MSI_ADDR(2)
#define REG_MSI_FNC3_ADDR                                 REG_MSI_ADDR(3)
#define REG_MSI_FNC4_ADDR                                 REG_MSI_ADDR(4)
#define REG_MSI_FNC5_ADDR                                 REG_MSI_ADDR(5)
#define REG_MSI_FNC6_ADDR                                 REG_MSI_ADDR(6)
#define REG_MSI_FNC7_ADDR                                 REG_MSI_ADDR(7)

// Always 0x0?
#define REG_MSI_UNK0CC(func)              (REG_MSI(0x0CC) + 4*(func & 7))
#define REG_MSI_FNC0_UNK0CC                             REG_MSI_UNK0CC(0)
#define REG_MSI_FNC1_UNK0CC                             REG_MSI_UNK0CC(1)
#define REG_MSI_FNC2_UNK0CC                             REG_MSI_UNK0CC(2)
#define REG_MSI_FNC3_UNK0CC                             REG_MSI_UNK0CC(3)
#define REG_MSI_FNC4_UNK0CC                             REG_MSI_UNK0CC(4)
#define REG_MSI_FNC5_UNK0CC                             REG_MSI_UNK0CC(5)
#define REG_MSI_FNC6_UNK0CC                             REG_MSI_UNK0CC(6)
#define REG_MSI_FNC7_UNK0CC                             REG_MSI_UNK0CC(7)

#define REG_MSI_DATA_LO(func, sub)           REG_MSI_LODATA_FN##func(sub)
#define REG_MSI_FNC0_DATA_LO(sub)       (REG_MSI(0x100) + 4*(sub & 0x03))
#define REG_MSI_FNC1_DATA_LO(sub)       (REG_MSI(0x110) + 4*(sub & 0x03))
#define REG_MSI_FNC2_DATA_LO(sub)       (REG_MSI(0x120) + 4*(sub & 0x03))
#define REG_MSI_FNC3_DATA_LO(sub)       (REG_MSI(0x130) + 4*(sub & 0x03))
#define REG_MSI_FNC4_DATA_LO(sub)       (REG_MSI(0x140) + 4*(sub & 0x17))
#define REG_MSI_FNC5_DATA_LO(sub)       (REG_MSI(0x1A0) + 4*(sub & 0x01))
#define REG_MSI_FNC6_DATA_LO(sub)       (REG_MSI(0x1B0) + 4*(sub & 0x01))
#define REG_MSI_FNC7_DATA_LO(sub)       (REG_MSI(0x1C0) + 4*(sub & 0x03))

#define CASE_FUNC_R(index, name, variable) \
    case REG_MSI_FNC##index##_##name: \
        value = variable[index]; \
        break;
#define CASE_FUNC_W(index, name, variable) \
    case REG_MSI_FNC##index##_##name: \
        variable[index] = value; \
        break;
#define CASE_FUNCS(type, name, variable) \
    CASE_FUNC_##type(0, name, variable) \
    CASE_FUNC_##type(1, name, variable) \
    CASE_FUNC_##type(2, name, variable) \
    CASE_FUNC_##type(3, name, variable) \
    CASE_FUNC_##type(4, name, variable) \
    CASE_FUNC_##type(5, name, variable) \
    CASE_FUNC_##type(6, name, variable) \
    CASE_FUNC_##type(7, name, variable)

AeoliaMsic::AeoliaMsic(Space * mem)
    : Device(nullptr), mem(mem) {
    reset();
}

void AeoliaMsic::reset() {
    memset(func_addr, 0, sizeof(func_addr));
    memset(func_mask, 0, sizeof(func_addr));
    memset(func_data, 0, sizeof(func_addr));
    memset(data_lo, 0, sizeof(func_addr));
}

U32 AeoliaMsic::mmio_read(U32 offset) {
    U32 data_lo_index;
    U32 value;

    value = 0;
    switch (offset) {
    // Handle global control/status
    case REG_MSI_CONTROL:
    case REG_MSI_UNK004:
    case REG_MSI_UNK008:
        break;

    // Handle regular function-specific registers
    CASE_FUNCS(R, ADDR, func_addr);
    CASE_FUNCS(R, MASK, func_mask);
    CASE_FUNCS(R, DATA, func_data);

    // Handle irregular function-specific registers
    default:
        data_lo_index = (offset - REG_MSI_FNC0_DATA_LO(0)) >> 2;
        if (data_lo_index < 48) {
            value = data_lo[data_lo_index];
        }
    }
    return value;
}

void AeoliaMsic::mmio_write(U32 offset, U32 value) {
    U32 data_lo_index;

    switch (offset) {
    // Handle global control/status
    case REG_MSI_CONTROL:
    case REG_MSI_UNK004:
    case REG_MSI_UNK008:
        break;

    // Handle regular function-specific registers
    CASE_FUNCS(W, ADDR, func_addr);
    CASE_FUNCS(W, MASK, func_mask);
    CASE_FUNCS(W, DATA, func_data);

    // Handle irregular function-specific registers
    default:
        data_lo_index = (offset - REG_MSI_FNC0_DATA_LO(0)) >> 2;
        if (data_lo_index < 52) {
            data_lo[data_lo_index] = value;
        }
    }
}

void AeoliaMsic::msi_trigger(U32 func, U32 sub) {
    if (sub > 30) {
        fprintf(stderr, "%s: Subfunction #%u out of range!",
            __FUNCTION__, sub);
        assert(0);
        return;
    }

    auto enabled = func_mask[func] & (1 << sub);
    if (!enabled) {
        return;
    }

    auto data = func_data[func];
    switch (func) {
    case 0:
        assert(sub < 4);
        data |= func0_data_lo[sub];
        break;
    case 1:
        assert(sub < 4);
        data |= func1_data_lo[sub];
        break;
    case 2:
        assert(sub < 4);
        data |= func2_data_lo[sub];
        break;
    case 3:
        assert(sub < 4);
        data |= func3_data_lo[sub];
        break;
    case 4:
        assert(sub < 24);
        data |= func4_data_lo[sub];
        break;
    case 5:
        assert(sub < 2);
        data |= func5_data_lo[sub];
        break;
    case 6:
        assert(sub < 2);
        data |= func6_data_lo[sub];
        break;
    case 7:
        assert(sub < 4);
        data |= func7_data_lo[sub];
        break;
    default:
        fprintf(stderr, "%s: Function #%u out of range!", __FUNCTION__, func);
        return;
    }
    mem->write<U32>(func_addr[func], data);
}
