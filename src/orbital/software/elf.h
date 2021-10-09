/**
 * ELF Loader.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <core.h>

// ELF conversion
enum class ElfType {
    LE_32,
    BE_32,
    LE_64,
    BE_64,
};

class ElfParser {
    Stream& s;
    ElfType type;

    size_t ehdr_offset;
    Elf_Ehdr<> ehdr;

public:
    ElfParser(Stream& s);
    ~ElfParser();

    /**
     * Get EHDR at the given index.
     */
    Elf_Ehdr<> get_ehdr();

    /**
     * Get PHDR at the given index.
     * @param[in]  index  PHDR index.
     */
    Elf_Phdr<> get_phdr(size_t index);

    /**
     * Get segment/program data described by the PHDR at the given index.
     * @param[in]  index  PHDR index.
     */
    Buffer get_pdata(size_t index);

private:
    template <template<typename> typename S, typename T=Elf_TypeGeneric>
    S<T> parse() {
        switch (type) {
        case ElfType::LE_32:
            return generalize(s.read_t<S<Elf_Type32LE>>());
        case ElfType::BE_32:
            return generalize(s.read_t<S<Elf_Type32BE>>());
        case ElfType::LE_64:
            return generalize(s.read_t<S<Elf_Type64LE>>());
        case ElfType::BE_64:
            return generalize(s.read_t<S<Elf_Type64BE>>());
        }
    }

    template <typename T>
    static Elf_Ehdr<> generalize(const Elf_Ehdr<T>& ehdr_t) {
        Elf_Ehdr<> ehdr = {};
        memcpy(ehdr.e_ident, ehdr_t.e_ident, EI_NIDENT);
        ehdr.e_type      = ehdr_t.e_type;
        ehdr.e_machine   = ehdr_t.e_machine;
        ehdr.e_version   = ehdr_t.e_version;
        ehdr.e_entry     = ehdr_t.e_entry;
        ehdr.e_phoff     = ehdr_t.e_phoff;
        ehdr.e_shoff     = ehdr_t.e_shoff;
        ehdr.e_flags     = ehdr_t.e_flags;
        ehdr.e_ehsize    = ehdr_t.e_ehsize;
        ehdr.e_phentsize = ehdr_t.e_phentsize;
        ehdr.e_phnum     = ehdr_t.e_phnum;
        ehdr.e_shentsize = ehdr_t.e_shentsize;
        ehdr.e_shnum     = ehdr_t.e_shnum;
        ehdr.e_shstrndx  = ehdr_t.e_shstrndx;
        return ehdr;
    }

    template <typename T>
    static Elf_Phdr<> generalize(const Elf_Phdr<T>& phdr_t) {
        Elf_Phdr<> phdr = {};
        phdr.p_type      = phdr_t.p_type;
        phdr.p_flags     = phdr_t.p_flags;
        phdr.p_offset    = phdr_t.p_offset;
        phdr.p_vaddr     = phdr_t.p_vaddr;
        phdr.p_paddr     = phdr_t.p_paddr;
        phdr.p_filesz    = phdr_t.p_filesz;
        phdr.p_memsz     = phdr_t.p_memsz;
        phdr.p_align     = phdr_t.p_align;
        return phdr;
    }
};
