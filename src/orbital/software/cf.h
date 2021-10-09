/**
 * Common Format (CF) format.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <core.h>

struct CfSegment {
    enum AttrFlags {
        FLAGS_INFO        = (1 << 0),
        FLAGS_ENCRYPTION  = (1 << 1),
        FLAGS_SIGNING     = (1 << 2),
        FLAGS_COMPRESSION = (1 << 3),
        FLAGS_BLOCKS      = (1 << 11),
        FLAGS_DIGESTS     = (1 << 16),
        FLAGS_EXTENTS     = (1 << 17),
    };

    LE<U64> attr;
    LE<U64> offset;
    LE<U64> mem_size;
    LE<U64> file_size;

    U64 id() const noexcept {
        return attr >> 20;
    }
    U64 block_size() const noexcept {
        if (has_blocks()) {
            return UINT64_C(1) << (((attr >> 12) & 0xF) + 12);
        }
        else {
            return 0x10000;
        }
    }
    U64 block_count() const noexcept {
        const U64 bs = block_size();
        return (file_size + bs - 1) / bs;
    }

    // Helpers
    bool is_info() const noexcept {
        return attr & FLAGS_INFO;
    }
    bool is_encrypted() const noexcept {
        return attr & FLAGS_ENCRYPTION;
    }
    bool is_signed() const noexcept {
        return attr & FLAGS_SIGNING;
    }
    bool is_compressed() const noexcept {
        return attr & FLAGS_COMPRESSION;
    }
    bool has_blocks() const noexcept {
        return attr & FLAGS_BLOCKS;
    }
    bool has_digests() const noexcept {
        return attr & FLAGS_DIGESTS;
    }
    bool has_extents() const noexcept {
        return attr & FLAGS_EXTENTS;
    }
};

struct CfMeta {
    U08 data_key[16];
    U08 data_iv[16];
    U08 digest[32];
    U08 digest_key[16];
};

class CfParser {
protected:
    Stream& s;

public:
    CfParser(Stream& s) : s(s) {}

    static void decrypt(Buffer& data, const CfMeta& meta);
};
