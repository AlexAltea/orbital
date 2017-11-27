#!/usr/bin/python

import argparse
import io
import lief
import os
import struct

# Indices
INDEX_NULL = 0
INDEX_SYMTAB = 1
INDEX_STRTAB = 2
INDEX_SHSTRTAB = 3

# Utilities
class Section(object):
    def __init__(self):
        self.name_idx = 0
        self.type = lief.ELF.SECTION_TYPES.NULL
        self.flags = lief.ELF.SECTION_FLAGS.NONE
        self.virtual_address = 0
        self.offset = 0
        self.size = 0
        self.link = 0
        self.information = 0
        self.alignment = 0
        self.entry_size = 0
        # Helpers
        self.name = ""
        self.content = b""

    def serialize(self):
        section_fmt = 'IIQQQQIIQQ'
        assert struct.calcsize(section_fmt) == 0x40
        return struct.pack(section_fmt,
            self.name_idx,
            int(self.type),
            int(self.flags),
            self.virtual_address,
            self.offset,
            self.size,
            self.link,
            self.information,
            self.alignment,
            self.entry_size)

class Symbol(object):
    def __init__(self, data):
        symbol_fmt = 'IBBHQQ'
        assert struct.calcsize(symbol_fmt) == 0x18
        fields = struct.unpack(symbol_fmt, data)
        self.name = fields[0]
        self.info = fields[1]
        self.other = fields[2]
        self.shndx = fields[3]
        self.value = fields[4]
        self.size = fields[5]

def patch_i08(stream, offset, value):
    data = struct.pack('B', value)
    stream.seek(offset)
    stream.write(data)
    
def patch_i16(stream, offset, value):
    data = struct.pack('H', value)
    stream.seek(offset)
    stream.write(data)
    
def patch_i32(stream, offset, value):
    data = struct.pack('I', value)
    stream.seek(offset)
    stream.write(data)
    
def patch_i64(stream, offset, value):
    data = struct.pack('Q', value)
    stream.seek(offset)
    stream.write(data)


# Sections
def create_section_null():
    return Section()


def create_section_symtab(elf):
    section = Section()
    section.name = ".symtab"
    section.type = lief.ELF.SECTION_TYPES.SYMTAB
    section.flags = lief.ELF.SECTION_FLAGS.NONE
    section.link = INDEX_STRTAB
    section.information = 0
    section.alignment = 8
    section.offset = 0
    section.entry_size = 0
    section.size = 0
    
    for de in elf.dynamic_entries:
        if de.tag == lief.ELF.DYNAMIC_TAGS.SYMTAB:
            section.virtual_address = de.value
            section.offset = elf.virtual_address_to_offset(de.value)
        if de.tag == lief.ELF.DYNAMIC_TAGS.SYMENT:
            section.entry_size = de.value     
    if not section.offset and not section.entry_size:
        raise Exception("No dynamic entries for symbols")
    assert section.entry_size == 0x18

    section.size = section.entry_size
    while True:
        symdata = bytes(elf.get_content_from_virtual_address(
            section.virtual_address + section.size,
            section.entry_size))
        sym = Symbol(symdata)
        if sym.size > 0xFFFFFFFF: break
        section.size += section.entry_size
    return section


def create_section_strtab(elf):
    section = Section()
    section.name = ".strtab"
    section.type = lief.ELF.SECTION_TYPES.STRTAB
    section.flags = lief.ELF.SECTION_FLAGS.NONE
    section.link = 0
    section.information = 0
    section.alignment = 1
    section.offset = 0
    section.entry_size = 0
    section.size = 0

    for de in elf.dynamic_entries:
        if de.tag == lief.ELF.DYNAMIC_TAGS.STRTAB:
            section.virtual_address = de.value
            section.offset = elf.virtual_address_to_offset(de.value)
        if de.tag == lief.ELF.DYNAMIC_TAGS.STRSZ:
            section.size = de.value

    if not section.offset and not section.size:
        raise Exception("No dynamic entries for strings")
    return section


def create_section_shstrtab(sections):
    section = Section()
    section.name = ".shstrtab"
    section.type = lief.ELF.SECTION_TYPES.STRTAB
    section.flags = lief.ELF.SECTION_FLAGS.NONE
    section.link = 0
    section.information = 0
    section.alignment = 1
    section.offset = 0
    section.entry_size = 0
    section.size = 0

    section.content = b''
    for other_section in sections:
        other_section.name_idx = len(section.content)
        section.content += other_section.name.encode('ascii') + b'\x00'
    section.name_idx = len(section.content)
    section.content += section.name.encode('ascii') + b'\x00'
    return section
    

def patch_sections(path_in, path_out):
    elf = lief.parse(path_in)
    assert len(elf.sections) == 0, "Expected an executable without sections"
    sections = []
    sections.append(create_section_null())
    sections.append(create_section_symtab(elf))
    sections.append(create_section_strtab(elf))
    sections.append(create_section_shstrtab(sections))

    e_shentsize = 0x40
    e_shoff = os.path.getsize(path_in)
    e_shnum = len(sections)
    e_shstrndx = INDEX_SHSTRTAB

    with open(path_out, 'wb') as f:
        with open(path_in, 'rb') as binary:
            f.write(binary.read())
        patch_i64(f, 0x28, e_shoff)
        patch_i08(f, 0x3A, e_shentsize)
        patch_i08(f, 0x3C, e_shnum)
        patch_i08(f, 0x3E, e_shstrndx)
        f.seek(0, io.SEEK_END)
        offset = e_shoff + (e_shnum * e_shentsize)
        for section in sections:
            if section.content:
                section.offset = offset
                section.size = len(section.content)
                offset += len(section.content)
            f.write(section.serialize())
        for section in sections:
            f.write(section.content)


def main():
    parser = argparse.ArgumentParser(
        description='Generate ELF sections from dynamic entries.')
    parser.add_argument('input',
        metavar='input.elf', help='Path to input file',
    )
    parser.add_argument('output',
        metavar='output.elf', help='Path to output file',
    )
    args = parser.parse_args()
    patch_sections(args.input, args.output)

if __name__ == '__main__':
    main()
