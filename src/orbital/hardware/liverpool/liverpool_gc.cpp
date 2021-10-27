/**
 * Liverpool Graphics Controller (GC/Starsha) PCI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "liverpool_gc.h"

// Registers
#include "bif/bif_4_1_d.h"
#include "bif/bif_4_1_sh_mask.h"
#include "dce/dce_8_0_d.h"
#include "dce/dce_8_0_sh_mask.h"
#include "gca/gfx_7_2_d.h"
#include "gca/gfx_7_2_sh_mask.h"
#include "gmc/gmc_7_1_d.h"
#include "gmc/gmc_7_1_sh_mask.h"
#include "oss/oss_2_0_d.h"
#include "oss/oss_2_0_sh_mask.h"
#include "sam/sam.h"

// Logging
#define DEBUG_GC 0
#define DPRINTF(...) \
do { \
    if (DEBUG_GC) { \
        fprintf(stderr, "lvp-gc (%s:%d): ", __FUNCTION__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
    } \
} while (0)

LiverpoolGCDevice::LiverpoolGCDevice(PCIeBus* bus, const LiverpoolGCDeviceConfig& config)
    : PCIeDevice(bus, config) {
    // Define BARs
    space_bar0 = new MemorySpace(this, 0x4000000, {
        static_cast<MemorySpaceReadOp>(&LiverpoolGCDevice::bar0_read),
        static_cast<MemorySpaceWriteOp>(&LiverpoolGCDevice::bar0_write),
    });
    space_bar2 = new MemorySpace(this, 0x800000, {
        static_cast<MemorySpaceReadOp>(&LiverpoolGCDevice::bar2_read),
        static_cast<MemorySpaceWriteOp>(&LiverpoolGCDevice::bar2_write),
    });
    space_pio = new MemorySpace(this, 0x100, {
        static_cast<MemorySpaceReadOp>(&LiverpoolGCDevice::pio_read),
        static_cast<MemorySpaceWriteOp>(&LiverpoolGCDevice::pio_write),
    });
    space_mmio = new MemorySpace(this, 0x40000, {
        static_cast<MemorySpaceReadOp>(&LiverpoolGCDevice::mmio_read),
        static_cast<MemorySpaceWriteOp>(&LiverpoolGCDevice::mmio_write),
    });

    // Register BARs
    register_bar(0, PCI_BASE_ADDRESS_SPACE_MEM, space_bar0);
    register_bar(2, PCI_BASE_ADDRESS_SPACE_MEM, space_bar2);
    register_bar(4, PCI_BASE_ADDRESS_SPACE_IO, space_pio);
    register_bar(5, PCI_BASE_ADDRESS_SPACE_MEM, space_mmio);

    reset();
}

LiverpoolGCDevice::~LiverpoolGCDevice() {
    delete space_bar0;
    delete space_bar2;
    delete space_pio;
    delete space_mmio;
}

void LiverpoolGCDevice::reset() {
    // PCI Configuration Space
    auto& header = config_header();
    header.command = PCI_COMMAND_IO | PCI_COMMAND_MEMORY; // TODO: Is this needed?
    header.header_type |= PCI_HEADER_TYPE_MULTI_FUNCTION;

    mmio.fill(0);
    sam_ix.fill(0);
    sam_sab_ix.fill(0);
}

U64 LiverpoolGCDevice::bar0_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void LiverpoolGCDevice::bar0_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}

U64 LiverpoolGCDevice::bar2_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void LiverpoolGCDevice::bar2_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}

U64 LiverpoolGCDevice::pio_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void LiverpoolGCDevice::pio_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}

U64 LiverpoolGCDevice::mmio_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void LiverpoolGCDevice::mmio_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}
