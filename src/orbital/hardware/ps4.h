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

#include <orbital/core.h>

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
class LiverpoolNBFnc0Device;
class LiverpoolNBFnc1Device;
class LiverpoolNBFnc2Device;
class LiverpoolNBFnc3Device;
class LiverpoolNBFnc4Device;
class LiverpoolNBFnc5Device;
class VulkanManager;

struct PS4MachineConfig : MachineConfig {
    CharHost* aeolia_uart0 = nullptr;
    CharHost* aeolia_uart1 = nullptr;
    VulkanManager* vk = nullptr;

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

    // Hardware

    /**
     * Get constant reference to the Graphics Controller (e.g. used for debugging).
     */
    const LiverpoolGCDevice& gc() const noexcept {
        return *lvp_gc;
    }

private:
    MemorySpace* space_ubios;
    MemorySpace* space_ram;
    AliasSpace* space_ram_below_4g;
    AliasSpace* space_ram_above_4g;

    // Liverpool
    std::vector<X86CPUDevice*> cpus;
    LiverpoolHost* lvp_host;
    LiverpoolRCDevice* lvp_rc;
    LiverpoolGCDevice* lvp_gc;
    LiverpoolHDACDevice* lvp_hdac;
    LiverpoolIOMMUDevice* lvp_iommu;
    LiverpoolRPDevice* lvp_rp;

    LiverpoolNBFnc0Device* lvp_fnc0;
    LiverpoolNBFnc1Device* lvp_fnc1;
    LiverpoolNBFnc2Device* lvp_fnc2;
    LiverpoolNBFnc3Device* lvp_fnc3;
    LiverpoolNBFnc4Device* lvp_fnc4;
    LiverpoolNBFnc5Device* lvp_fnc5;

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
