/**
 * PlayStation 4 machine.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <core.h>

#include <filesystem>

struct PS4MachineConfig : MachineConfig {
    PS4MachineConfig();
};

class PS4Machine : public Machine {
public:
    PS4Machine(const PS4MachineConfig& config = {});
    ~PS4Machine();

    /**
     * Reset the console and boot normally into the installed OrbisOS.
     */
    void boot();

    /**
     * Reset the console and boot into safe mode of the installed OrbisOS.
     * From there one can (re)install all OrbisOS contents in the virtual HDD
     * given a virtual USB storage device containing a recovery PUP.
     */
    void recover();

    /**
     * Begin recovery process by booting into safe mode from a PUP-contained kernel.
     * From there one can (re)install all OrbisOS contents in the virtual HDD.
     * The virtual USB storage device will be automatically created.
     * @param[in]  pup  Path to recovery PUP file
     */
    void recover(std::filesystem::path pup);

private:
    Space* space_ram;
    Space* space_ram_below_4g;
    Space* space_ram_above_4g;
};
