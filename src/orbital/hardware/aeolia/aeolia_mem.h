/**
 * Aeolia memory device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <core.h>

enum {
    AEOLIA_MEM_DEV = 0x14,
    AEOLIA_MEM_FNC = 0x6,
};

constexpr auto AEOLIA_MEM_VID = static_cast<PCIVendorId>(0x104D);
constexpr auto AEOLIA_MEM_DID = static_cast<PCIDeviceId>(0x90A3);

struct AeoliaMemDeviceConfig : PCIDeviceConfig {
    AeoliaMemDeviceConfig(PCI_DF df = PCI_DF(AEOLIA_MEM_DEV, AEOLIA_MEM_FNC))
        : PCIDeviceConfig(df, AEOLIA_MEM_VID, AEOLIA_MEM_DID, 0x0, PCI_CLASS_SYSTEM_OTHER) {
    }
};

class AeoliaMemDevice final : public PCIDevice {
public:
    AeoliaMemDevice(PCIBus* bus, const AeoliaMemDeviceConfig& config = {});
    ~AeoliaMemDevice();

    // Device interface
    void reset() override;

private:
    MemorySpace* bar0;
    MemorySpace* bar2;
    MemorySpace* bar4;
    MemorySpace* spm;

    U64 bar0_read(U64 addr, U64 size);
    void bar0_write(U64 addr, U64 value, U64 size);

    U64 bar2_read(U64 addr, U64 size);
    void bar2_write(U64 addr, U64 value, U64 size);

    U64 bar4_read(U64 addr, U64 size);
    void bar4_write(U64 addr, U64 value, U64 size);
};
