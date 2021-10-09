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

#include <zlib.h>

#include <stdexcept>

constexpr U32 PUP_MAGIC = 0x1D3D154F;

enum PupEndian {
    LITTLE = 1,
};

enum PupFlags {
    JIG = 1,
};

// PUP parser
PupParser::PupParser(Stream& s, bool verify) : CfParser(s) {
    Buffer buffer;
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

    // Decrypt and cache header
    buffer.resize(header.hdr_size - sizeof(PupHeader));
    s.read(buffer.size(), buffer.data());
    crypto.decrypt(buffer.data(), buffer.size(), crypto.get("pup.hdr"));
    headerEx = reinterpret_cast<const PupHeaderEx&>(buffer[0]);
    auto* segment_entries = reinterpret_cast<const PupSegmentEntry*>(&buffer[sizeof(PupHeaderEx)]);
    segEntries.clear();
    for (size_t i = 0; i < headerEx.segment_count; i++) {
        segEntries.push_back(segment_entries[i]);
    }

    // Decrypt and cache meta
    buffer.resize(header.meta_size);
    s.read(buffer.size(), buffer.data());
    crypto.decrypt(buffer.data(), buffer.size(), crypto.get("pup.root_key"));
    auto* meta_entries = reinterpret_cast<const PupSegmentMeta*>(&buffer[0]);
    segMetas.clear();
    for (size_t i = 0; i < headerEx.segment_count; i++) {
        segMetas.push_back(meta_entries[i]);
    }

    if (verify) {
        throw std::runtime_error("Unimplemented");
    }
}

PupParser::~PupParser() {
}

Buffer PupParser::get(U64 id) {
    const auto index = find(id);
    if (segEntries[index].has_blocks()) {
        return get_blocked(index);
    } else {
        return get_nonblocked(index);
    }
}

Buffer PupParser::get_blocked(U64 index) {
    const auto& crypto = ps4Crypto();

    // Get target segment
    const PupSegmentEntry& entry = segEntries[index];
    const PupSegmentMeta& meta = segMetas[index];
    const auto block_size = entry.block_size();
    const auto block_count = entry.block_count();

    // Get information segment
    const auto info_index = find_info(index);
    const PupSegmentEntry& info_entry = segEntries[info_index];
    const PupSegmentMeta& info_meta = segMetas[info_index];

    // Read and process information segment data
    Buffer info_buffer(info_entry.file_size);
    s.seek(info_entry.offset, StreamSeek::Set);
    s.read(info_buffer.size(), info_buffer.data());
    if (info_entry.is_encrypted()) {
        decrypt(info_buffer, info_meta);
    }
    if (info_entry.is_compressed()) {
        throw std::runtime_error("Unimplemented");
    }
    if (info_entry.is_signed()) {
        // TODO: throw std::runtime_error("Unimplemented");
    }

    BufferStream info_stream(std::move(info_buffer));
    std::vector<PupDigest> digests;
    std::vector<PupExtent> extents;
    if (info_entry.has_digests()) {
        for (size_t i = 0; i < block_count; i++) {
            digests.push_back(info_stream.read_t<PupDigest>());
        }
    }
    if (info_entry.has_extents()) {
        for (size_t i = 0; i < block_count; i++) {
            extents.push_back(info_stream.read_t<PupExtent>());
        }
    }

    // Process target segment
    auto left_size = entry.file_size;
    Buffer block, segment;
    for (const auto& extent : extents) {
        block.resize(extent.size);
        s.seek(entry.offset + extent.offset, StreamSeek::Set);
        s.read(extent.size, block.data());

        const auto cur_zsize = (extent.size & ~0xF) - (extent.size & 0xF);
        const auto cur_size = std::min(block_size, left_size);
        left_size -= cur_size;
        if (entry.is_signed()) {
            // TODO: throw std::runtime_error("Unimplemented");
        }
        if (entry.is_encrypted()) {
            decrypt(block, meta);
        }
        segment.resize(segment.size() + cur_size);
        U08* dest = &segment[segment.size() - cur_size];
        if (entry.is_compressed() && cur_size != cur_zsize) {
            unsigned long cur_usize = cur_size;
            int zerr = uncompress(dest, &cur_usize, block.data(), cur_zsize);
            assert(zerr == 0);
        } else {
            memcpy(dest, block.data(), block.size());
        }
    }
    return segment;
}

Buffer PupParser::get_nonblocked(U64 index) {
    throw std::runtime_error("Unimplemented");
}

U64 PupParser::find(const std::function<bool(const PupSegmentEntry&, const PupSegmentMeta&)>& pred) const {
    for (size_t i = 0; i < headerEx.segment_count; i++) {
        if (pred(segEntries[i], segMetas[i])) {
            return i;
        }
    }
    throw std::out_of_range("PUP segment not found");
}

U64 PupParser::find(U64 id) const {
    return find([=](const PupSegmentEntry& entry, const PupSegmentMeta& meta) -> bool {
        return entry.id() == id && !entry.is_info();
    });
}

U64 PupParser::find_info(U64 id) const {
    return find([=](const PupSegmentEntry& entry, const PupSegmentMeta& meta) -> bool {
        return entry.id() == id && entry.is_info();
    });
}
