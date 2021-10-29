/**
 * Offset range helper.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

struct OffsetRange {
    uint64_t base;
    uint64_t size;

    constexpr OffsetRange(uint64_t base, uint64_t size)
        : base(base), size(size) {
    }
    constexpr bool contains(uint64_t off) const noexcept {
        return (base <= off) && (off < base + size);
    }
    constexpr bool contains_strict(uint64_t off, uint64_t len) const noexcept {
        return contains(off) && (off + len <= base + size);
    }
};
