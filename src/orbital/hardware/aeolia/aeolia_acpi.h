/**
 * Aeolia ACPI device.
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
    AEOLIA_ACPI_DEV = 0x14,
    AEOLIA_ACPI_FNC = 0x0,
};

constexpr auto AEOLIA_ACPI_VID = static_cast<PCIVendorId>(0x104D);
constexpr auto AEOLIA_ACPI_DID = static_cast<PCIDeviceId>(0x908F);

struct AeoliaACPIDeviceConfig : PCIDeviceConfig {
    AeoliaACPIDeviceConfig(PCI_DF df = PCI_DF(AEOLIA_ACPI_DEV, AEOLIA_ACPI_FNC))
        : PCIDeviceConfig(df, AEOLIA_ACPI_VID, AEOLIA_ACPI_DID, 0x0, PCI_CLASS_SYSTEM_OTHER) {
    }
};

class AeoliaACPIDevice final : public PCIDevice {
public:
    AeoliaACPIDevice(PCIBus* bus, const AeoliaACPIDeviceConfig& config = {});
    ~AeoliaACPIDevice();

    // Device interface
    void reset() override;

private:
    MemorySpace* mem;
    MemorySpace* io;

    U64 mem_read(U64 addr, U64 size);
    void mem_write(U64 addr, U64 value, U64 size);

    U64 io_read(U64 addr, U64 size);
    void io_write(U64 addr, U64 value, U64 size);
};
