/**
 * PlayStation 4 machine.
 *
 * Copyright 2017-2020. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "ps4.h"
#include <orbital/software/bls.h>
#include <orbital/software/elf.h>
#include <orbital/software/pup.h>
#include <orbital/software/self.h>

constexpr U64 PS4_PUP_ENTRY_COREOS = 0x5;

PS4MachineConfig::PS4MachineConfig() {
    cpu_count = 1; // TODO: 8
}

PS4Machine::PS4Machine(const PS4MachineConfig& config) : Machine(config) {
    // Initialize RAM
    constexpr U64 ram_size = 8_GB;
    constexpr U64 ram_size_below_4g = 0x80000000;
    constexpr U64 ram_size_above_4g = ram_size - ram_size_below_4g;

    space_ram = new MemorySpace(this, ram_size);
    space_ram_below_4g = new AliasSpace(this, space_ram, 0x0'00000000ULL, ram_size_below_4g);
    space_ram_above_4g = new AliasSpace(this, space_ram, 0x1'00000000ULL, ram_size_above_4g);
}

PS4Machine::~PS4Machine() {
}

void PS4Machine::recover(std::filesystem::path file) {
    // Get kernel ELF image
    FileStream fs(file.string(), "rb");
    BlsParser bls(fs);
    BlsStream bs = bls.get("PS4UPDATE1.PUP");
    PupParser pup(bs);
    BufferStream coreos = pup.get(PS4_PUP_ENTRY_COREOS);
    BlsParser coreos_bls(coreos);
    BlsStream kernel_bs = coreos_bls.get("80010002");
    SelfParser kernel(kernel_bs);

    // Load kernel into RAM
    const auto ehdr = kernel.get_ehdr();
    for (size_t i = 0; i < ehdr.e_phnum; i++) {
        const auto phdr = kernel.get_phdr(i);
    }
}
