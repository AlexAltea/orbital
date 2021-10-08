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
#include <orbital/software/elf.h>

#include <memory>
#include <vector>

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
    LE<U16> segment_count;
    LE<U16> flags;
    LE<U32> reserved;
};

using SelfSegment = CfSegment;

class SelfParser {
    Stream& s;
    SelfHeader header;
    std::vector<SelfSegment> segments;
    std::unique_ptr<ElfParser> elf;

public:
    SelfParser(Stream& s);
    ~SelfParser();

    // ELF parser interface
    Elf_Ehdr<> get_ehdr();

    Elf_Phdr<> get_phdr(size_t i);
};
