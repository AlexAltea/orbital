/**
 * Liverpool IOMMU PCI device.
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
    LIVERPOOL_IOMMU_DEV = 0x0,
    LIVERPOOL_IOMMU_FNC = 0x2,
};

constexpr auto LIVERPOOL_IOMMU_DID = static_cast<PCIDeviceId>(0x1437);

struct LiverpoolIOMMUDeviceConfig : PCIDeviceConfig {
    LiverpoolIOMMUDeviceConfig(PCI_DF df = PCI_DF(LIVERPOOL_IOMMU_DEV, LIVERPOOL_IOMMU_FNC))
        : PCIDeviceConfig(df, PCI_VENDOR_ID_AMD, LIVERPOOL_IOMMU_DID, 0x1, 0x0806) {
    }
};

class LiverpoolIOMMUDevice final : public PCIDevice {
public:
    LiverpoolIOMMUDevice(PCIBus* bus, const LiverpoolIOMMUDeviceConfig& config = {});
    ~LiverpoolIOMMUDevice();

    // Device interface
    void reset() override;

private:
    MemorySpace* mmio;

    U64 mmio_read(U64 addr, U64 size);
    void mmio_write(U64 addr, U64 value, U64 size);
};
