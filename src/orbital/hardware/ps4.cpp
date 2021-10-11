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
    // Create VM
    _vm = createVirtualMachine(this, HypervisorBackend_Core);

    // Initialize CPU
    for (int i = 0; i < config.cpu_count; i++) {
        auto cpu = new X86CPUDevice(this, space_mem, vm(), i);
        cpu->on_state_changed(std::bind(&PS4Machine::cpu_state_change_handler, this, std::placeholders::_1, std::placeholders::_2));
        _cpus.push_back(cpu);
    }

    // Initialize RAM
    constexpr U64 ram_size = 8_GB;
    constexpr U64 ram_size_below_4g = 0x80000000;
    constexpr U64 ram_size_above_4g = ram_size - ram_size_below_4g;

    space_ram = new MemorySpace(this, ram_size);
    space_ram_below_4g = new AliasSpace(this, space_ram, 0_GB, ram_size_below_4g);
    space_ram_above_4g = new AliasSpace(this, space_ram, ram_size_below_4g, ram_size_above_4g);
    space_mem->addSubspace(space_ram_below_4g, 0_GB);
    space_mem->addSubspace(space_ram_above_4g, 4_GB);

    // Initialize UBIOS area
    constexpr size_t ubios_size = 0x80000;
    space_ubios = new MemorySpace(this, ubios_size, {}, SpaceFlags::RW);
    space_mem->addSubspace(space_ubios, 4_GB - ubios_size);
}

PS4Machine::~PS4Machine() {
}

void PS4Machine::recover(std::filesystem::path file) {
    // Reset and pause the machine, if already running
    // TODO

    // Get kernel ELF image
    FileStream fs(file.string(), "rb");
    BlsParser bls(fs);
    BlsStream bs = bls.get("PS4UPDATE1.PUP");
    PupParser pup(bs);
    BufferStream coreos = pup.get(PS4_PUP_ENTRY_COREOS);
    BlsParser coreos_bls(coreos);
    BlsStream kernel_bs = coreos_bls.get("80010002");
    SelfParser kernel(kernel_bs);

    // Load kernel segment
    const auto ehdr = kernel.get_ehdr();
    assert(ehdr.e_phnum == 1);
    const auto phdr = kernel.get_phdr(0);
    const auto pdata = kernel.get_pdata(0);
    assert(phdr.p_type == PT_LOAD);

    // Load kernel and UBIOS into into memory
    space_ram->write(phdr.p_paddr, pdata.size(), pdata.data());
    space_ubios->write(0x0, space_ubios->size(), pdata.data());

    // Expose PS4UPDATE.PUP as USB mass-storage device
    // TODO

    resume();
}
