/**
 * SELF format.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <core.h>
#include <orbital/software/cf.h>

// Forward declarations
class SelfParser;

struct SelfHeader {
    LE<U32> magic;
    LE<U08> version;
    LE<U08> mode;
    LE<U08> endian;
    LE<U08> attr;
    LE<U32> key_type;
    LE<U16> header_size;
    LE<U16> meta_size;
    LE<U64> file_size;
    LE<U16> num_entries;
    LE<U16> flags;
    LE<U32> reserved;
};

using SelfSegment = CfSegment;

class SelfParser {
    Stream& s;
    SelfHeader header;

public:
    SelfParser(Stream& s);
    ~SelfParser();
};
