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
#include <orbital/software/cf.h>

#include <vector>

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
    LE<U64> file_size;
    LE<U16> segment_count;
    LE<U16> hash_count;
    LE<U32> flags;
};

using PupSegmentEntry = CfSegment;
using PupSegmentMeta = CfMeta;

struct PupExtent {
    LE<U32> offset;
    LE<U32> size;
};

struct PupDigest {
    std::byte data[32];
};

class PupParser : public CfParser {
    PupHeader header;
    PupHeaderEx headerEx;
    std::vector<PupSegmentEntry> segEntries;
    std::vector<PupSegmentMeta> segMetas;

public:
    /**
     * Create PUP parser. 
     * @param[in]  verify  Verify digital signatures.
     */
    PupParser(Stream& s, bool verify=false);
    ~PupParser();

    /**
     * Get PUP segment by identifier.
     * @param[in]  id  Segment identifier (44-bits).
     */
    Buffer get(U64 id);

private:
    /**
     * Get index of first PUP segment satisfying the given predicate, if any.
     * @param[in]  pred  Predicate function.
     */
    U64 find(const std::function<bool(const PupSegmentEntry&, const PupSegmentMeta&)>& pred) const;

    /**
     * Get index of first PUP segment with the given identifier, if any.
     * @param[in]  id  Segment identifier (44-bits).
     */
    U64 find(U64 id) const;

    /**
     * Get index of the first information segment of a given PUP segment, if any.
     * @param[in]  index  Target segment index.
     */
    U64 find_info(U64 id) const;

    /**
     * Get blocked PUP segment by identifier.
     * @param[in]  id  Segment identifier (44-bits).
     */
    Buffer get_blocked(U64 index);

    /**
     * Get non-blocked PUP segment by identifier.
     * @param[in]  id  Segment identifier (44-bits).
     */
    Buffer get_nonblocked(U64 index);
};
