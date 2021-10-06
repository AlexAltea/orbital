/**
 * PUP format.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "pup.h"
#include <orbital/crypto_ps4.h>

constexpr U32 PUP_MAGIC = 0x1D3D154F;

enum PupEndian {
    LITTLE = 1,
};

enum PupFlags {
    JIG = 1,
};

PupParser::PupParser(Stream& s) : s(s) {
    const auto& crypto = ps4Crypto();

    // Read and verify PUP header
    s.seek(0, StreamSeek::Set);
    header = s.read_t<PupHeader>();
    assert(header.magic == PUP_MAGIC);
    assert(header.version == 0);
    assert(header.mode == 1);
    assert(header.endian == PupEndian::LITTLE);
    assert(header.attr == 0x12);

    // Discard unsupported flags
    assert((header.flags & PupFlags::JIG) == 0, "Unsupported JIG flag");

    // Decrypt header
    auto header = crypto.decrypt<PupHeaderEx>(s, "pup.hdr");
}

PupParser::~PupParser() {
}
