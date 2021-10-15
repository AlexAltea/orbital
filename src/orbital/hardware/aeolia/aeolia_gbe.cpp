/**
 * Aeolia GBE device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "aeolia_gbe.h"

// Logging
#define DEBUG_GBE 0
#define DPRINTF(...) \
do { \
    if (DEBUG_GBE) { \
        fprintf(stderr, "aeolia-gbe (%s:%d): ", __FUNCTION__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
    } \
} while (0)

enum {
    AGBE_DEVICE_ID  = 0x011B,
    AGBE_DEVICE_REV = 0x011A,
    AGBE_UNK2880    = 0x2880,
};

AeoliaGBEDevice::AeoliaGBEDevice(PCIBus* bus, const AeoliaGBEDeviceConfig& config)
    : PCIDevice(bus, config) {
    // Define BARs
    mmio = new MemorySpace(this, 0x4000, {
        static_cast<MemorySpaceReadOp>(&AeoliaGBEDevice::mmio_read),
        static_cast<MemorySpaceWriteOp>(&AeoliaGBEDevice::mmio_write),
    });

    // Register BARs
    register_bar(0, PCI_BASE_ADDRESS_SPACE_MEM, mmio);

#if 0
    msi_init(dev, 0x50, 1, true, false, NULL);
    if (pci_is_express(dev)) {
        pcie_endpoint_cap_init(dev, 0x70);
    }
#endif

    reset();
}

AeoliaGBEDevice::~AeoliaGBEDevice() {
}

void AeoliaGBEDevice::reset() {
    // PCI Configuration Space
    auto& header = config_header();
    header.command = PCI_COMMAND_MEMORY; // TODO: Is this needed?
    header.header_type |= PCI_HEADER_TYPE_MULTI_FUNCTION;
    header.class_prog = 0x01;
}

U64 AeoliaGBEDevice::mmio_read(U64 addr, U64 size) {
    U64 value = 0;
    assert_always("Unimplemented");

    DPRINTF("addr=0x%llX, size=0x%llX\n", addr, size);
    switch (addr) {
    case AGBE_DEVICE_ID:
        assert(size == 1);
        value = 0xBD;
        break;
    case AGBE_DEVICE_REV:
        assert(size == 1);
        value = 0x00; // TODO
        break;
    case AGBE_UNK2880:
        assert(size == 2);
        value = 0x10; // TODO
        break;
    }
    return value;
}

void AeoliaGBEDevice::mmio_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}
