/**
 * BLS format.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <core.h>

#include <string>
#include <string_view>
#include <vector>

// Forward declarations
class BlsParser;

struct BlsEntry {
    LE<U32> block_offset;
    LE<U32> file_size;
    LE<U32> padding[2];
    char file_name[32];
};

struct BlsHeader {
    LE<U32> magic;
    LE<U32> version;
    LE<U32> flags;
    LE<U32> num_files;
    LE<U32> num_blocks;
    LE<U32> padding[3];
};

class BlsStream : public Stream {
    BlsParser* bls;
    const U64 base;
    const U32 size;
    U32 offset;

public:
    BlsStream(BlsParser* bls, U32 base, U32 size)
        : bls(bls), base(base), size(size), offset(0) {}

    virtual U64 read(U64 size, void* buffer) override;
    virtual U64 write(U64 size, const void* buffer) override;
    virtual void seek(U64 offset, StreamSeek mode) override;
    virtual U64 tell() const override;
};

class BlsParser {
    friend BlsStream;
    Stream& s;
    BlsHeader header;
    std::mutex mtx;

public:
    BlsParser(Stream& s);
    ~BlsParser();

    /**
     * Return list of file names corresponding to the BLS entries.
     * @return  Vector of strings of the file names
     */
    std::vector<std::string> files();

    /**
     * Get BLS stream by file name
     */
    BlsStream get(std::string_view name);

    /**
     * Get BLS stream by index
     */
    BlsStream get(U32 index);
};
