#!/usr/bin/env python3

import argparse
import ctypes
import os
import pathlib
import struct
import sys

# Configuration
DEBUG = False

# Globals
ENC_PATH = None
DEC_PATH = None

# Structures
class struct_t(object):
    def from_file(self, file):
        size = struct.calcsize(self.fmt)
        data = file.read(size)
        self.from_data(data)

class bls_header_t(struct_t):
    def __init__(self):
        self.fmt = 'IIIIIIII'

    def from_data(self, data):
        fields = struct.unpack(self.fmt, data)
        self.magic = fields[0]
        self.version = fields[1]
        self.flags = fields[2]
        self.entry_count = fields[3]
        self.block_count = fields[4]

    def __repr__(self):
        output= 'bls_header_t({\n'
        output += '  magic:        0x%08X\n' % self.magic
        output += '  version:      0x%08X\n' % self.version
        output += '  flags:        0x%08X\n' % self.flags
        output += '  entry_count:  0x%08X\n' % self.entry_count
        output += '  block_count:  0x%08X\n' % self.block_count
        output += '})' 
        return output

class bls_entry_t(struct_t):
    def __init__(self):
        self.fmt = 'IIII32s'

    def from_data(self, data):
        fields = struct.unpack(self.fmt, data)
        self.block_offset = fields[0]
        self.file_size = fields[1]
        self.file_name = ctypes.create_string_buffer(fields[4]).value
        self.file_name = self.file_name.decode('utf-8')

    def __repr__(self):
        output= 'bls_entry_t({\n'
        output += '  block_offset: 0x%08X\n' % self.block_offset
        output += '  file_size:    0x%08X\n' % self.file_size
        output += '  file_name:    %s\n'     % self.file_name
        output += '})'
        return output

class pup_header_t(struct_t):
    def __init__(self):
        self.fmt = 'IIIHH'

    def from_data(self, data):
        fields = struct.unpack(self.fmt, data)
        self.magic = fields[0]
        self.unk_04 = fields[1]
        self.unk_08 = fields[2]
        self.unk_0C_size = fields[3]
        self.unk_0E_size = fields[4]

    def __repr__(self):
        output= 'pup_header_t({\n'
        output += '  magic:        0x%08X\n' % self.magic
        output += '  unk_04:       0x%08X\n' % self.unk_04
        output += '  unk_08:       0x%08X\n' % self.unk_08
        output += '  unk_0C_size:  0x%04X\n' % self.unk_0C_size
        output += '  unk_0E_size:  0x%04X\n' % self.unk_0E_size
        output += '})' 
        return output

class pup_header_ex_t(struct_t):
    def __init__(self):
        self.fmt = 'QHHI'

    def from_data(self, data):
        fields = struct.unpack(self.fmt, data)
        self.file_size = fields[0]
        self.segment_count = fields[1]
        self.unk_1A = fields[2]
        self.unk_1C = fields[3]

    def __repr__(self):
        output= 'pup_header_ex_t({\n'
        output += '  file_size:    %d bytes\n' % self.file_size
        output += '  seg_count:    0x%04X\n' % self.segment_count
        output += '  unk_1A:       0x%04X\n' % self.unk_1A
        output += '  unk_1C:       0x%08X\n' % self.unk_1C
        output += '})' 
        return output

class pup_segment_t(struct_t):
    def __init__(self):
        self.fmt = 'QQQQ'

    def from_data(self, data):
        fields = struct.unpack(self.fmt, data)
        self.flags = fields[0]
        self.offset = fields[1]
        self.compressed_size = fields[2]
        self.uncompressed_size = fields[3]

    def __repr__(self):
        output= 'pup_segment_t({\n'
        output += '  flags:        0x%08X (%s)\n' % (self.flags,
            ('E' if self.has_encryption else '') +
            ('C' if self.has_compression else '') +
            ('B' if self.has_blocks else '') +
            ('D' if self.has_digests else '') +
            ('X' if self.has_extents else ''))
        output += '  offset:       0x%08X\n' % self.offset
        output += '  compr_size:   0x%08X\n' % self.compressed_size
        output += '  uncompr_size: 0x%08X\n' % self.uncompressed_size
        output += '})' 
        return output

    @property
    def has_encryption(self):
        return bool(self.flags & (1 << 1))
    
    @property
    def has_compression(self):
        return bool(self.flags & (1 << 3))
    
    @property
    def has_blocks(self):
        return bool(self.flags & (1 << 11))

    @property
    def has_digests(self):
        return bool(self.flags & (1 << 16))

    @property
    def has_extents(self):
        return bool(self.flags & (1 << 17))
    
    @property
    def block_size(self):
        return 1 << (((self.flags & 0xF000) >> 12) + 12)

    @property
    def block_count(self):
        return (self.block_size + self.uncompressed_size - 1) // self.block_size

class pup_block_t(struct_t):
    def __init__(self):
        self.fmt = 'II'

    def from_data(self, data):
        fields = struct.unpack(self.fmt, data)
        self.offset = fields[0]
        self.size = fields[1]

    def __repr__(self):
        output= 'pup_block_t({\n'
        output += '  offset:       0x%08X\n' % self.offset
        output += '  size:         0x%08X\n' % self.size
        output += '})' 
        return output


# Helpers
def dprint(*args):
    if DEBUG:
        print(*args)

def decrypt(blob_name, blob_data):
    with open(os.path.join(ENC_PATH, blob_name), 'wb') as f:
        f.write(blob_data)
    blob_size = len(blob_data)
    with open(os.path.join(DEC_PATH, blob_name), 'rb') as f:
        blob_data = f.read()
    assert(len(blob_data) == blob_size)
    return blob_data


# Slicer
def slice_bls_entry(pup, bls_entry):
    # Parse PUP header
    offset = bls_entry.block_offset * 0x200
    pup.seek(offset)
    pup_header = pup_header_t()
    pup_header.from_file(pup)
    dprint(pup_header)

    # Get PUP header blob
    blob_name = 'd%d_hdr.bin' % (bls_entry.index)
    blob_size = pup_header.unk_0C_size - struct.calcsize(pup_header.fmt)
    blob_data = pup.read(blob_size)
    blob_data = decrypt(blob_name, blob_data)

    # Parse PUP extended header
    pup_header_ex = pup_header_ex_t()
    pup_header_ex.from_data(blob_data[:0x10])
    dprint(pup_header_ex)

    # Parse PUP segments
    pup_segments = []
    for i in range(pup_header_ex.segment_count):
        pup_segment_size = 0x20
        pup_segment_offs = 0x10 + pup_segment_size * i
        pup_segment_data = blob_data[pup_segment_offs: \
                                     pup_segment_offs + pup_segment_size]
        pup_segment = pup_segment_t()
        pup_segment.from_data(pup_segment_data)
        pup_segments.append(pup_segment)
        dprint(pup_segment)

    # Get PUP segment blobs
    table_segments = {}
    for i in range(len(pup_segments)):
        pup_segment = pup_segments[i]
        
        # Skip special PUP segments
        special_flags = pup_segment.flags & 0xF0000000
        if special_flags == 0xF0000000 or \
           special_flags == 0xE0000000:
            continue

        if pup_segment.has_blocks:
            # Get PUP segment blob (blocked)
            count = pup_segment.block_count
            table = table_segments[i]
            table = table[0x20 * count:]
            for j in range(count):
                if pup_segment.has_compression:
                    pup_block = pup_block_t()
                    pup_block.from_data(table[(j+0)*0x8:(j+1)*0x8])
                    blob_offs = pup_block.offset + pup_segment.offset
                    blob_size = pup_block.size & ~0xF
                    dprint(pup_block)
                else:
                    blob_offs = pup_segment.block_size * j
                    blob_size = pup_segment.block_size
                    blob_size = min(blob_size,
                                    pup_segment.uncompressed_size - blob_offs)
                pup.seek(blob_offs)
                blob_name = 'd%d_blkseg%04d_b%04d.bin' % (bls_entry.index, i, j)
                blob_data = pup.read(blob_size)
                blob_data = decrypt(blob_name, blob_data)
        elif pup_segment.has_digests:
            # Get PUP segment blob (non-blocked table)
            pup.seek(pup_segment.offset)
            segment_id = (pup_segment.flags >> 20) & 0xFF
            blob_name = 'd%d_blkseg%04d_i%04d.bin' % \
                        (bls_entry.index, segment_id, i)
            blob_size = pup_segment.compressed_size
            blob_data = pup.read(blob_size)
            blob_data = decrypt(blob_name, blob_data)
            table_segments[segment_id] = blob_data
        else:
            # Get PUP segment blob (non-blocked)
            pup.seek(pup_segment.offset)
            blob_name = 'd%d_nonblkseg%04d.bin' % (bls_entry.index, i)
            blob_size = pup_segment.compressed_size & ~0xF
            blob_data = pup.read(blob_size)
            blob_data = decrypt(blob_name, blob_data)


def slice_pup(pup_path):
    # Sanity checks
    if not os.listdir(DEC_PATH):
        print("Directory of decrypted blobs is empty")
        return
    pathlib.Path(ENC_PATH).mkdir(parents=True, exist_ok=True)
    if os.listdir(ENC_PATH):
        print("Directory of encrypted blobs is not empty")
        return

    # Parse BLS header
    pup = open(pup_path, 'rb')
    bls_header = bls_header_t()
    bls_header.from_file(pup)
    dprint(bls_header)

    # Parse BLS entries
    dprint('')
    bls_entries = []
    for i in range(bls_header.entry_count):
        bls_entry = bls_entry_t()
        bls_entry.from_file(pup)
        bls_entry.index = i
        bls_entries.append(bls_entry)
        dprint('bls_entries[%d] =' % i, bls_entry)

    # Slice BLS entries
    for i in range(bls_header.entry_count):
        dprint('')
        slice_bls_entry(pup, bls_entries[i])
    pup.close()


def main():
    # Define arguments
    parser = argparse.ArgumentParser(
        description='Slice a PUP file into named encrypted blobs.')
    parser.add_argument('pup',
        metavar='path/to/pup', help='path to input pup',
    )
    parser.add_argument('dec',
        metavar='path/to/dec', help='path to decrypted blobs',
    )
    parser.add_argument('enc', nargs='?',
        metavar='path/to/enc', help='path to encrypted blobs',
    )
    
    # Parse arguments
    args = parser.parse_args()
    if args.enc is None:
        args.enc = args.pup + '.enc'
        
    # Set globals and perform slicing
    global ENC_PATH
    global DEC_PATH
    DEC_PATH = args.dec
    ENC_PATH = args.enc
    slice_pup(args.pup)


if __name__ == '__main__':
    main()
