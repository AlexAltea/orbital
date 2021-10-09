/**
 * ELF format.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "elf.h"

ElfParser::ElfParser(Stream& s) : s(s) {
    ehdr_offset = s.tell();
    U08 e_ident[EI_NIDENT] = {};
    s.read(EI_NIDENT, &e_ident);
    assert(e_ident[EI_MAG0] == '\x7F');
    assert(e_ident[EI_MAG1] == 'E');
    assert(e_ident[EI_MAG2] == 'L');
    assert(e_ident[EI_MAG3] == 'F');

    // Determine ELF-type at runtime
    switch (e_ident[EI_CLASS]) {
    case ELFCLASS32:
        switch (e_ident[EI_DATA]) {
        case ELFDATA2LSB:
            type = ElfType::LE_32;
            break;
        case ELFDATA2MSB:
            type = ElfType::BE_32;
            break;
        default:
            throw std::runtime_error("Unimplemented");
        }
        break;
    case ELFCLASS64:
        switch (e_ident[EI_DATA]) {
        case ELFDATA2LSB:
            type = ElfType::LE_64;
            break;
        case ELFDATA2MSB:
            type = ElfType::BE_64;
            break;
        default:
            throw std::runtime_error("Unimplemented");
        }
        break;
    default:
        throw std::runtime_error("Unimplemented");
    }

    // Cache EHDR
    s.seek(ehdr_offset, StreamSeek::Set);
    ehdr = parse<Elf_Ehdr>();
}

ElfParser::~ElfParser() {
}

Elf_Ehdr<> ElfParser::get_ehdr() {
    return ehdr;
}

Elf_Phdr<> ElfParser::get_phdr(size_t i) {
    assert(i < ehdr.e_phnum);
    s.seek(ehdr_offset + ehdr.e_phoff + ehdr.e_phentsize * i, StreamSeek::Set);
    return parse<Elf_Phdr>();
}

Buffer ElfParser::get_pdata(size_t i) {
    const auto phdr = get_phdr(i);
    s.seek(ehdr_offset + phdr.p_offset, StreamSeek::Set);
    return s.read_b(phdr.p_filesz);
}
