#!/usr/bin/python

import argparse
import copy
import re
import struct

from uuid import *
from zlib import *

# Configuration
LBA_SIZE = 512

# Constants
GPT_TYPE_GUID_SCE_PREINST      = UUID("17800F17-B9E1-425D-B937-0119A0813172")
GPT_TYPE_GUID_SCE_PREINST2     = UUID("CCB52E94-EBEF-48C4-A195-9E2DA5B0292C")
GPT_TYPE_GUID_SCE_DA0X2        = UUID("145268BF-63AD-47C1-9378-9AACD9BEED7C")
GPT_TYPE_GUID_SCE_EAP_VSH      = UUID("6E0C5310-8445-4066-B571-9B65FDB75935")
GPT_TYPE_GUID_SCE_SYSTEM       = UUID("757A614B-6179-5361-6B61-6B6968617261")
GPT_TYPE_GUID_SCE_SYSTEM_EX    = UUID("DC85025F-A694-4109-BE44-FA0C063E8B81")
GPT_TYPE_GUID_SCE_SWAP         = UUID("76A9A5B4-44B0-472A-BDE3-3107472ADEE2")
GPT_TYPE_GUID_SCE_APP_TMP      = UUID("80DD49E3-A985-4887-81DE-1DACA47AED90")
GPT_TYPE_GUID_SCE_SYSTEM_DATA  = UUID("A71FF62D-1421-4DD9-935D-25DABD81BEC5")
GPT_TYPE_GUID_SCE_UPDATE       = UUID("FDB5EDE1-73C3-4C43-8C5B-2D3DCFCDDFF8")
GPT_TYPE_GUID_SCE_USER         = UUID("C638477A-E002-4B57-A454-A27FB63A33A8")
GPT_TYPE_GUID_SCE_EAP_USER     = UUID("21E4DFB4-0040-4934-A037-EA9DC058EEA6")
GPT_TYPE_GUID_SCE_DA0X15       = UUID("3EF7290A-DE81-4887-A11F-46FBA765C71C")

GPT_PART_FLAG_SCE_UNK55 = 0x80000000000000

# Utilities
def parse_size(size_str):
    if not re.match('\d+[BKMGT]', size_str):
        raise Exception('Invalid size specified')
    size = int(size_str[:-1])
    if size_str[-1] == 'B': size *= 1024**0
    if size_str[-1] == 'K': size *= 1024**1
    if size_str[-1] == 'M': size *= 1024**2
    if size_str[-1] == 'G': size *= 1024**3
    if size_str[-1] == 'T': size *= 1024**4
    return size

def is_power2(num):
    return num != 0 and ((num & (num - 1)) == 0)

def sce_guid(time_low):
    return UUID("%08X-0000-1000-A2D0-709E2913C1F5" % time_low)

# GPT
class GPTPartition(object):
    def __init__(self, parent, size, type_guid, part_guid, flags=0, name=""):
        # Arguments
        if type(size) == str:
            size = parse_size(size)
        assert size > 0 and size % LBA_SIZE == 0
        assert type(type_guid) == UUID
        assert type(part_guid) == UUID
        # Fields
        self.type_guid = type_guid
        self.part_guid = part_guid
        self.first_lba = 0
        self.last_lba = 0
        self.flags = flags
        self.name = name
        # Helpers
        self.parent = parent
        self.size = size

    def serialize(self):
        fmt = '<16s16sQQQ72s'
        assert struct.calcsize(fmt) == 0x80
        assert len(self.name) <= 72
        return struct.pack(fmt,
            self.type_guid.bytes_le,
            self.part_guid.bytes_le,
            self.first_lba,
            self.last_lba,
            self.flags,
            self.name.encode('utf-8'))

class GPTHeader(object):
    def __init__(self, disk_size, disk_guid, signature=b"", revision=0):
        # Arguments
        assert disk_size > 0 and disk_size % LBA_SIZE == 0
        last_lba = (disk_size // LBA_SIZE) - 1
        last_lba -= 1  # Skip dummy/scratch end sector
        last_lba -= 32 # Skip backup GPT partitions
        last_lba -= 1  # Skip backup GPT header
        # Fields
        self.signature = signature
        self.revision = revision
        self.size = 0x5C
        self.crc = 0
        self.reserved = 0
        self.current_lba = 1
        self.backup_lba = last_lba + 1 
        self.first_lba = 34
        self.last_lba = last_lba
        self.disk_guid = disk_guid
        self.parts_lba = 2
        self.parts_count = 0
        self.parts_size = 0x80
        self.parts_crc = 0
        # Helpers
        self.disk_size = disk_size
        self.partitions = []

    def serialize(self):
        fmt = '<8sIIIIQQQQ16sQIII'
        assert struct.calcsize(fmt) == 0x5C
        assert struct.calcsize(fmt) == self.size
        return struct.pack(fmt,
            self.signature,
            self.revision,
            self.size,
            self.crc,
            self.reserved,
            self.current_lba,
            self.backup_lba,
            self.first_lba,
            self.last_lba,
            self.disk_guid.bytes_le,
            self.parts_lba,
            self.parts_count,
            self.parts_size,
            self.parts_crc)

    def update(self):
        self.parts_lba = self.current_lba + 1
        # Allocate partitions
        current_lba = 2048
        self.parts_count = len(self.partitions) * 4
        for part in sorted(self.partitions, key=lambda x: x.part_guid):
            part.first_lba = current_lba
            current_lba += part.size // LBA_SIZE
            part.last_lba = current_lba - 1
        # Update partitions CRC
        buffer = b''
        for part in self.partitions:
            entry = part.serialize()
            buffer += entry + (b'\x00' * (LBA_SIZE-len(entry)))
        parts_table_size = (self.first_lba - self.parts_lba) * LBA_SIZE
        buffer += b'\x00' * (parts_table_size - len(buffer))
        self.parts_crc = crc32(buffer) & 0xFFFFFFFF
        # Update header CRC
        self.crc = 0
        self.crc = crc32(self.serialize()) & 0xFFFFFFFF

    def save(self, f):
        self.update()
        f.seek(LBA_SIZE * self.current_lba)
        f.write(self.serialize())
        for i in range(len(self.partitions)):
            partition = self.partitions[i]
            partition_lba = self.parts_lba + i
            f.seek(LBA_SIZE * partition_lba)
            f.write(partition.serialize())
        

# Generate image
def generate_hdd_gpt_partitions(gpt, size):
    gpt.partitions.append(GPTPartition(gpt, '512M',
        GPT_TYPE_GUID_SCE_PREINST,
        sce_guid(0xA)))
    gpt.partitions.append(GPTPartition(gpt, '1G',
        GPT_TYPE_GUID_SCE_PREINST2,
        sce_guid(0xB)))
    gpt.partitions.append(GPTPartition(gpt, '16M',
        GPT_TYPE_GUID_SCE_DA0X2,
        sce_guid(0xC)))
    gpt.partitions.append(GPTPartition(gpt, '128M',
        GPT_TYPE_GUID_SCE_EAP_VSH,
        sce_guid(0xD)))

    gpt.partitions.append(GPTPartition(gpt, '1G',
        GPT_TYPE_GUID_SCE_SYSTEM,
        sce_guid(0x5), flags=GPT_PART_FLAG_SCE_UNK55))
    gpt.partitions.append(GPTPartition(gpt, '1G',
        GPT_TYPE_GUID_SCE_SYSTEM,
        sce_guid(0x6)))
    gpt.partitions.append(GPTPartition(gpt, '1G',
        GPT_TYPE_GUID_SCE_SYSTEM_EX,
        sce_guid(0x7), flags=GPT_PART_FLAG_SCE_UNK55))
    gpt.partitions.append(GPTPartition(gpt, '1G',
        GPT_TYPE_GUID_SCE_SYSTEM_EX,
        sce_guid(0x8)))

    gpt.partitions.append(GPTPartition(gpt, '8G',
        GPT_TYPE_GUID_SCE_SWAP,
        sce_guid(0x4)))
    gpt.partitions.append(GPTPartition(gpt, '1G',
        GPT_TYPE_GUID_SCE_APP_TMP,
        sce_guid(0x1)))
    gpt.partitions.append(GPTPartition(gpt, '8G',
        GPT_TYPE_GUID_SCE_SYSTEM_DATA,
        sce_guid(0x9)))
    gpt.partitions.append(GPTPartition(gpt, '6G',
        GPT_TYPE_GUID_SCE_UPDATE,
        sce_guid(0xF)))

    gpt.partitions.append(GPTPartition(gpt, size - parse_size('36G'),
        GPT_TYPE_GUID_SCE_USER,
        sce_guid(0x3)))
    gpt.partitions.append(GPTPartition(gpt, '1G',
        GPT_TYPE_GUID_SCE_EAP_USER,
        sce_guid(0xE)))
    gpt.partitions.append(GPTPartition(gpt, '6G',
        GPT_TYPE_GUID_SCE_DA0X15,
        sce_guid(0x2)))
    return gpt

def generate_hdd_mbr(f, size):
    # Write MBR partition entry
    last_lba = (size // LBA_SIZE) - 2
    f.seek(0x1BE)
    f.write(b'\x00')
    f.write(b'\x00\x02\x00')
    f.write(b'\xEE')
    f.write(b'\xFF\xFF\xFF')
    f.write(struct.pack('<I', 1))
    f.write(struct.pack('<I', last_lba))
    # Magic
    f.seek(0x1FE)
    f.write(b'\x55')
    f.write(b'\xAA')

def generate_hdd_gpt(f, size):
    gpt = GPTHeader(size, sce_guid(0),
        signature=b"EFI PART", revision=0x10000)
    gpt = generate_hdd_gpt_partitions(gpt, size)

    gpt1 = copy.copy(gpt)
    gpt2 = copy.copy(gpt)
    gpt2.current_lba = gpt1.backup_lba
    gpt2.backup_lba = gpt1.current_lba
    
    # Save changes
    gpt1.save(f)
    gpt2.save(f)
    f.seek(gpt.disk_size - 1)
    f.write(b'\x00')

def generate_hdd(f, size):
    generate_hdd_mbr(f, size)
    generate_hdd_gpt(f, size)

def main():
    # Define arguments
    parser = argparse.ArgumentParser(
        description='Generate an HDD image partitioned as PS4 kernels expect.')
    parser.add_argument('-s', '--size', default='50G',
        help="size of the disk image (e.g. '500G', '1T')",
    )
    parser.add_argument('output',
        metavar='path/to/disk.img', help='path to output disk image file',
    )
    # Parse arguments
    args = parser.parse_args()
    size = parse_size(args.size)
    if size < parse_size('20G'):
        raise Exception('Specified size below allowed minimum')
    with open(args.output, 'wb') as f:
        generate_hdd(f, size)

if __name__ == '__main__':
    main()
