/**
 * Liverpool Graphics Controller (GC/Starsha) PCI device.
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
    LIVERPOOL_GC_DEV = 0x1,
    LIVERPOOL_GC_FNC = 0x0,
};

constexpr auto LIVERPOOL_GC_VID = static_cast<PCIVendorId>(0x1002);
constexpr auto LIVERPOOL_GC_DID = static_cast<PCIDeviceId>(0x9920);

struct LiverpoolGCDeviceConfig : PCIDeviceConfig {
    LiverpoolGCDeviceConfig(PCI_DF df = PCI_DF(LIVERPOOL_GC_DEV, LIVERPOOL_GC_FNC))
        : PCIDeviceConfig(df, LIVERPOOL_GC_VID, LIVERPOOL_GC_DID, 0x0, PCI_CLASS_DISPLAY_VGA) {
    }
};

class LiverpoolGCDevice final : public PCIDevice {
public:
    LiverpoolGCDevice(PCIBus* bus, const LiverpoolGCDeviceConfig& config = {});
    ~LiverpoolGCDevice();

    // Device interface
    void reset() override;

private:
    MemorySpace* bar0;
    MemorySpace* bar2;
    MemorySpace* pio;
    MemorySpace* mmio;

    U64 bar0_read(U64 addr, U64 size);
    void bar0_write(U64 addr, U64 value, U64 size);

    U64 bar2_read(U64 addr, U64 size);
    void bar2_write(U64 addr, U64 value, U64 size);

    U64 pio_read(U64 addr, U64 size);
    void pio_write(U64 addr, U64 value, U64 size);

    U64 mmio_read(U64 addr, U64 size);
    void mmio_write(U64 addr, U64 value, U64 size);
};
