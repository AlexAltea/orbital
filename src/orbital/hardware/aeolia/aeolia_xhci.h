/**
 * Aeolia XHCI device.
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
    AEOLIA_XHCI_DEV = 0x14,
    AEOLIA_XHCI_FNC = 0x7,
};

constexpr auto AEOLIA_XHCI_VID = static_cast<PCIVendorId>(0x104D);
constexpr auto AEOLIA_XHCI_DID = static_cast<PCIDeviceId>(0x90A4);

struct AeoliaXHCIDeviceConfig : PCIDeviceConfig {
    AeoliaXHCIDeviceConfig(PCI_DF df = PCI_DF(AEOLIA_XHCI_DEV, AEOLIA_XHCI_FNC))
        : PCIDeviceConfig(df, AEOLIA_XHCI_VID, AEOLIA_XHCI_DID, 0x0, PCI_CLASS_SYSTEM_OTHER) {
    }
};

class AeoliaXHCIDevice final : public PCIDevice {
public:
    AeoliaXHCIDevice(PCIBus* bus, const AeoliaXHCIDeviceConfig& config = {});
    ~AeoliaXHCIDevice();

    // Device interface
    void reset() override;

private:
    MemorySpace* xhci[3];

    U64 xhci0_read(U64 addr, U64 size);
    void xhci0_write(U64 addr, U64 value, U64 size);

    U64 xhci1_read(U64 addr, U64 size);
    void xhci1_write(U64 addr, U64 value, U64 size);

    U64 xhci2_read(U64 addr, U64 size);
    void xhci2_write(U64 addr, U64 value, U64 size);
};
