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

// Forward declarations
class AeoliaACPIDevice;
class AeoliaAHCIDevice;
class AeoliaDMACDevice;
class AeoliaGBEDevice;
class AeoliaMemDevice;
class AeoliaPCIeDevice;
class AeoliaSDHCIDevice;
class AeoliaXHCIDevice;
class LiverpoolHost;
class LiverpoolRCDevice;
class LiverpoolGCDevice;
class LiverpoolHDACDevice;
class LiverpoolIOMMUDevice;
class LiverpoolRPDevice;


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
    Space* space_ubios;

    // Liverpool
    std::vector<X86CPUDevice*> cpus;
    LiverpoolHost* lvp_host;
    LiverpoolRCDevice* lvp_rc;
    LiverpoolGCDevice* lvp_gc;
    LiverpoolHDACDevice* lvp_hdac;
    LiverpoolIOMMUDevice* lvp_iommu;
    LiverpoolRPDevice* lvp_rp;

    // Aeolia
    AeoliaACPIDevice* aeolia_acpi;
    AeoliaGBEDevice* aeolia_gbe;
    AeoliaAHCIDevice* aeolia_ahci;
    AeoliaSDHCIDevice* aeolia_sdhci;
    AeoliaPCIeDevice* aeolia_pcie;
    AeoliaDMACDevice* aeolia_dmac;
    AeoliaMemDevice* aeolia_mem;
    AeoliaXHCIDevice* aeolia_xhci;
};
