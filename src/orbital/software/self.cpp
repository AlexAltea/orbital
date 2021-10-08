/**
 * SELF format.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "self.h"

#include <stdexcept>

constexpr U32 SELF_MAGIC = '\x4F\x15\x3D\x1D';

enum SelfEndian {
    LITTLE = 1,
};

SelfParser::SelfParser(Stream& s) : s(s) {
    // Read and verify SELF header
    s.seek(0, StreamSeek::Set);
    header = s.read_t<SelfHeader>();
    assert(header.magic == SELF_MAGIC);
    assert(header.version == 0);
    assert(header.mode == 1);
    assert(header.endian == SelfEndian::LITTLE);
    assert(header.attr == 0x12);
}

SelfParser::~SelfParser() {
}
