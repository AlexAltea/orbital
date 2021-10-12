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
#include <orbital/crypto_ps4.h>

#include <zlib.h>

#include <stdexcept>

constexpr U32 SELF_MAGIC = '\x4F\x15\x3D\x1D';

enum SelfEndian {
    LITTLE = 1,
};

enum ProgramAuthID : U64 {
    PAID_KERNEL = UINT64_C(0x3C00000000000001),
};

enum ProgramType : U64 {
    PTYPE_FAKE          = 0x1,
    PTYPE_NPDRM_EXEC    = 0x4,
    PTYPE_NPDRM_DYNLIB  = 0x5,
    PTYPE_SYSTEM_EXEC   = 0x8,
    PTYPE_SYSTEM_DYNLIB = 0x9,
    PTYPE_HOST_KERNEL   = 0xC,
    PTYPE_SECURE_MODULE = 0xE,
    PTYPE_SECURE_KERNEL = 0xF,
};

static Key getKey(const SelfInfo& info) {
    const auto& crypto = ps4Crypto();

    switch (info.paid) {
    case PAID_KERNEL:
        if (info.version_app >= 0x00000500'00000000 &&
            info.version_app <= 0x0000054F'FFFFFFFF) {
            return crypto.get("self.80010002.500");
        } else {
            throw std::runtime_error("Unsupported");
        }
        break;
    default:
        throw std::runtime_error("Unsupported");
    }
}

SelfParser::SelfParser(Stream& s) : CfParser(s) {
    const auto& crypto = ps4Crypto();

    // Read and verify SELF header
    s.seek(0, StreamSeek::Set);
    header = s.read_t<SelfHeader>();
    assert(header.magic == SELF_MAGIC);
    assert(header.version == 0);
    assert(header.mode == 1);
    assert(header.endian == SelfEndian::LITTLE);
    assert(header.attr == 0x12);

    // Read SELF segments
    segments.resize(header.segment_count);
    s.read(sizeof(SelfSegment) * segments.size(), segments.data());

    // Create ELF parser
    const auto elf_offset = s.tell();
    elf = std::make_unique<ElfParser>(s);
    const auto ehdr = elf->get_ehdr();

    // Read SELF information
    const auto info_offset = elf_offset + ehdr.e_phoff + ehdr.e_phentsize * ehdr.e_phnum;
    s.seek(align(info_offset, 16), StreamSeek::Set);
    info = s.read_t<SelfInfo>();
    assert(s.tell() == header.header_size, "NPDRM Control Blocks are unsupported");

    // Decrypt and cache meta
    Buffer buffer(header.meta_size);
    s.read(buffer.size(), buffer.data());
    crypto.decrypt(buffer.data(), buffer.size(), getKey(info));
    auto* meta_entries = reinterpret_cast<const SelfMeta*>(&buffer[0]);
    metas.clear();
    for (size_t i = 0; i < header.segment_count; i++) {
        metas.push_back(meta_entries[i]);
    }
}

SelfParser::~SelfParser() {
}

Elf_Ehdr<> SelfParser::get_ehdr() {
    return elf->get_ehdr();
}

Elf_Phdr<> SelfParser::get_phdr(size_t i) {
    return elf->get_phdr(i);
}

Buffer SelfParser::get_pdata(size_t i) {
    // Decrypt SELF segment corresponding to ELF program
    const auto segment_idx = find_segment(i);
    if (segments[segment_idx].has_blocks()) {
        return get_segment_blocked(i);
    } else {
        return get_segment_nonblocked(i);
    }
}

U64 SelfParser::find_segment(U64 phdr_idx) const {
    for (size_t i = 0; i < header.segment_count; i++) {
        if (segments[i].id() == phdr_idx) {
            return i;
        }
    }
    throw std::out_of_range("SELF segment not found");
}

Buffer SelfParser::get_segment_blocked(U64 index) {
    throw std::runtime_error("Unimplemented");
}

Buffer SelfParser::get_segment_nonblocked(U64 index) {
    const auto segment_idx = find_segment(index);
    const auto& segment = segments[segment_idx];
    const auto& meta = metas[segment_idx];

    s.seek(segment.offset, StreamSeek::Set);
    Buffer buffer = s.read_b(segment.mem_size);
    if (segment.is_encrypted()) {
        decrypt(buffer, meta);
    }
    if (segment.is_compressed()) {
        const auto size = segment.mem_size;
        unsigned long cur_zsize = (size & ~0xF) - (size & 0xF);
        unsigned long cur_usize = segment.file_size;

        Buffer result(segment.file_size);
        int zerr = uncompress(result.data(), &cur_usize, buffer.data(), cur_zsize);
        assert(zerr == 0);
        buffer = std::move(result);
    }
    return buffer;
}
