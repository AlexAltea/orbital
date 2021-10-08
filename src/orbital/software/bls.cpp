/**
 * BLS format.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "bls.h"

#include <stdexcept>

constexpr U32 BLS_MAGIC = '2BLS';
constexpr U64 BLS_BLOCK = 0x200;

U64 BlsStream::read(U64 size, void* buffer) {
    std::unique_lock<std::mutex> lock(bls->mtx);
    Stream& s = bls->s;
    s.seek(base + offset, StreamSeek::Set);
    size = std::min<U32>(size, this->size - offset);

    U64 nbytes = s.read(size, buffer);
    offset += nbytes;
    return nbytes;
}

U64 BlsStream::write(U64 size, const void* buffer) {
    throw std::runtime_error("Unsupported method");
}

void BlsStream::seek(U64 offset, StreamSeek mode) {
    switch (mode) {
    case StreamSeek::Set:
        this->offset = offset;
        break;
    case StreamSeek::Cur:
        this->offset += offset;
        break;
    case StreamSeek::End:
        this->offset = size - offset;
        break;
    default:
        throw std::runtime_error("Unsupported mode");
    }
}

U64 BlsStream::tell() const {
    return offset;
}

BlsParser::BlsParser(Stream& s) : s(s) {
    // Read and verify BLS header
    s.seek(0, StreamSeek::Set);
    header = s.read_t<BlsHeader>();
    assert(header.magic == BLS_MAGIC);
    assert(header.version <= 2);
}

BlsParser::~BlsParser() {
}

std::vector<std::string> BlsParser::files() {
    std::unique_lock<std::mutex> lock(mtx);
    std::vector<std::string> names(header.num_files);
    s.seek(sizeof(BlsHeader), StreamSeek::Set);
    for (auto& name : names) {
        auto entry = s.read_t<BlsEntry>();
        name = entry.file_name;
    }
    return names;
}

BlsStream BlsParser::get(std::string_view name) {
    std::unique_lock<std::mutex> lock(mtx);
    s.seek(sizeof(BlsHeader), StreamSeek::Set);
    for (U32 i = 0; i < header.num_files; i++) {
        auto entry = s.read_t<BlsEntry>();
        if (name == entry.file_name)
            return BlsStream(this, entry.block_offset * BLS_BLOCK, entry.file_size);
    }
    throw std::runtime_error("Could not find file within BLS");
}

BlsStream BlsParser::get(U32 index) {
    std::unique_lock<std::mutex> lock(mtx);
    s.seek(sizeof(BlsHeader) + sizeof(BlsEntry) * index, StreamSeek::Set);
    auto entry = s.read_t<BlsEntry>();
    return BlsStream(this, entry.block_offset * BLS_BLOCK, entry.file_size);
}
