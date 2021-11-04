/**
 * Liverpool F32 ucode utilities.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <orbital/core.h>

template <size_t N>
struct AmdUcode {
    U32 data[N];
    U32 addr;

    void push(U32 value) {
        data[addr >> 2] = value;
        addr += 4;
        addr &= N - 1;
    }
};
