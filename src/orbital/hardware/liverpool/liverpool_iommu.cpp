/**
 * Liverpool IOMMU PCI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "liverpool_iommu.h"

LiverpoolIOMMUDevice::LiverpoolIOMMUDevice(PCIBus* bus, const LiverpoolIOMMUDeviceConfig& config)
    : PCIDevice(bus, config) {
    // Define BARs
    mmio = new MemorySpace(this, 0x4000, {
        static_cast<MemorySpaceReadOp>(&LiverpoolIOMMUDevice::mmio_read),
        static_cast<MemorySpaceWriteOp>(&LiverpoolIOMMUDevice::mmio_write),
    });

    // Register BARs
    register_bar(0, PCI_BASE_ADDRESS_SPACE_MEM, mmio);

    reset();
}

LiverpoolIOMMUDevice::~LiverpoolIOMMUDevice() {
}

void LiverpoolIOMMUDevice::reset() {
}

U64 LiverpoolIOMMUDevice::mmio_read(U64 addr, U64 size) {
    U64 value = 0;
    assert_always("Unimplemented");
    return value;
}

void LiverpoolIOMMUDevice::mmio_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}
