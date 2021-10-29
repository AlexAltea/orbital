/**
 * Aeolia Non-Volatile Storage (NVS).
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <orbital/core.h>

#include <array>

#define NVS_RANGE(base, size, ...) \
    struct { std::array<U08, base> _; union { std::array<U08, size> data; struct { __VA_ARGS__ }; }; }

struct AeoliaNVS {
    union {
        U08 data[0x400];
        union {
            // [0x9B330, 0x9B34F]
            NVS_RANGE(0x000, 0x20) OsBootParameter;
            // [0x9B350, 0x9B38F]
            NVS_RANGE(0x000, 0x40) LsiBootParameter;
            // [0x9B390, 0x9B48F]
            NVS_RANGE(0x300, 0x100) BiosConfig;
            // [0x9B6E4, 0x9B743]
            NVS_RANGE(0x200, 0x60) EapPartitionKey;
            // 0x9B6DD
            NVS_RANGE(0x065, 0x1) CsBackupMode;
            // 0x9B6DE
            NVS_RANGE(0x0C0, 0x2) TempSlewRate;
        };
    };

    AeoliaNVS() {
        memset(data, 0, sizeof(data));

        OsBootParameter.data[0x18] = 2; // sceKernelHwHasWlanBt second bit as 1 for none
        BiosConfig.data[0] = 0xF0; // verbose ubios boot
    }

    constexpr size_t size() const noexcept {
        return sizeof(AeoliaNVS);
    }
};
