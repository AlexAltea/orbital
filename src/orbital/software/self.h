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
using SelfMeta = CfMeta;

struct SelfInfo {
    LE<U64> paid;        // Program Authority ID
    LE<U64> ptype;       // Program Type
    LE<U64> version_app; // Application Version
    LE<U64> version_fw;  // Firmware Version
    U08 digest[0x20];
};

class SelfParser : public CfParser {
    SelfHeader header;
    SelfInfo info;
    std::vector<SelfSegment> segments;
    std::vector<SelfMeta> metas;
    std::unique_ptr<ElfParser> elf;

public:
    SelfParser(Stream& s);
    ~SelfParser();

    // ELF parser interface
    Elf_Ehdr<> get_ehdr();

    Elf_Phdr<> get_phdr(size_t i);

    Buffer get_pdata(size_t i);

private:
    /**
     * Get index of first segment whose identifier matches the given PHDR index, if any.
     * @param[in]  id  Segment identifier (44-bits).
     */
    U64 find_segment(U64 phdr_idx) const;

    /**
     * Get blocked SELF segment by identifier.
     * @param[in]  id  Segment identifier (44-bits).
     */
    Buffer get_segment_blocked(U64 index);

    /**
     * Get non-blocked SELF segment by identifier.
     * @param[in]  id  Segment identifier (44-bits).
     */
    Buffer get_segment_nonblocked(U64 index);
};
