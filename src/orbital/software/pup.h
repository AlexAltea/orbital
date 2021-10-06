/**
 * PUP format.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <core.h>

struct PupHeader {
    LE<U32> magic;
    LE<U08> version;
    LE<U08> mode;
    LE<U08> endian;
    LE<U08> attr;
    LE<U16> key_type;
    LE<U16> flags;
    LE<U16> hdr_size;
    LE<U16> meta_size;
};

struct PupHeaderEx {
    LE<U64> size;
    LE<U16> entry_count;
    LE<U16> hash_count;
    LE<U32> flags;
};

class PupParser {
    Stream& s;
    PupHeader header;

public:
    PupParser(Stream& s);
    ~PupParser();
};
