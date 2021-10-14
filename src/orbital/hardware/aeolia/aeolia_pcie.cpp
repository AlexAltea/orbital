/**
 * Aeolia PCIe device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "aeolia_pcie.h"

struct OffsetRange {
    uint64_t base;
    uint64_t size;

    constexpr OffsetRange(uint64_t base, uint64_t size)
        : base(base), size(size) {
    }
    constexpr bool contains(uint64_t off) const noexcept {
        return (base <= off) && (off < base + size);
    }
    constexpr bool contains_strict(uint64_t off, uint64_t len) const noexcept {
        return contains(off) && (off + len <= base + size);
    }
};

constexpr auto range_wdt    = OffsetRange(0x081000, 0x1000);
constexpr auto range_unk1   = OffsetRange(0x084000, 0x1000); // ???
constexpr auto range_sflash = OffsetRange(0x0C2000, 0x2000);
constexpr auto range_uart0  = OffsetRange(0x140000, 0x1000);
constexpr auto range_uart1  = OffsetRange(0x141000, 0x1000);
constexpr auto range_unk2   = OffsetRange(0x180000, 0x2000); // ???
constexpr auto range_hpet   = OffsetRange(0x182000, 0x400);
constexpr auto range_icc    = OffsetRange(0x184000, 0x1000); // ???
constexpr auto range_unk3c  = OffsetRange(0x1B2000, 0x1000); // ???
constexpr auto range_unk3b  = OffsetRange(0x1B3000, 0x1000); // ???
constexpr auto range_unk3a  = OffsetRange(0x1B4000, 0x1000); // ???
constexpr auto range_bars   = OffsetRange(0x1C8000, 0x200);
constexpr auto range_msi    = OffsetRange(0x1C8400, 0x200);

AeoliaPCIeDevice::AeoliaPCIeDevice(PCIBus* bus, const AeoliaPCIeDeviceConfig& config)
    : PCIDevice(bus, config) {
    // Create sub-devices
    SerialDeviceConfig uart_config = {};
    uart_config.backend.type = host::CharHostType::Stdio;
    uart0 = std::make_unique<SerialDevice>(this, nullptr, uart_config);
    uart1 = std::make_unique<SerialDevice>(this, nullptr, uart_config);

    // Define BARs
    bar0 = new MemorySpace(this, 0x100000, {
        static_cast<MemorySpaceReadOp>(&AeoliaPCIeDevice::bar0_read),
        static_cast<MemorySpaceWriteOp>(&AeoliaPCIeDevice::bar0_write),
    });
    bar2 = new MemorySpace(this, 0x8000, {
        static_cast<MemorySpaceReadOp>(&AeoliaPCIeDevice::bar2_read),
        static_cast<MemorySpaceWriteOp>(&AeoliaPCIeDevice::bar2_write),
    });
    mmio_peripherals = new MemorySpace(this, 0x200000, {
        static_cast<MemorySpaceReadOp>(&AeoliaPCIeDevice::peripherals_read),
        static_cast<MemorySpaceWriteOp>(&AeoliaPCIeDevice::peripherals_write),
    });

    // Register BARs
    register_bar(0, PCI_BASE_ADDRESS_SPACE_MEM, bar0);
    register_bar(2, PCI_BASE_ADDRESS_SPACE_MEM, bar2);
    register_bar(4, PCI_BASE_ADDRESS_SPACE_MEM, mmio_peripherals);

    reset();
}

AeoliaPCIeDevice::~AeoliaPCIeDevice() {
    delete bar0;
    delete bar2;
    delete mmio_peripherals;
}

void AeoliaPCIeDevice::reset() {
    // PCI Configuration Space
    auto& header = config_header();
    header.command = PCI_COMMAND_MEMORY;
    header.header_type |= PCI_HEADER_TYPE_MULTI_FUNCTION;
    header.class_prog = 0x04;
}

U64 AeoliaPCIeDevice::bar0_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void AeoliaPCIeDevice::bar0_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}

U64 AeoliaPCIeDevice::bar2_read(U64 addr, U64 size) {
    assert_always("Unimplemented");
    return 0;
}

void AeoliaPCIeDevice::bar2_write(U64 addr, U64 value, U64 size) {
    assert_always("Unimplemented");
}

U64 AeoliaPCIeDevice::peripherals_read(U64 addr, U64 size) {
    U64 value = 0;

    if (range_wdt.contains(addr)) {
        assert_always("Unimplemented");
    }
    else if (range_unk1.contains(addr)) {
        fprintf(stderr, "AeoliaPCIeDevice::peripherals_read: addr=0x%llX, size=0x%llX\n", addr, size);
    }
    else if (range_sflash.contains(addr)) {
        assert_always("Unimplemented");
    }
    else if (range_uart0.contains(addr)) {
        addr -= range_uart0.base;
        uart0->io()->read(addr >> 2, 1, &value);
    }
    else if (range_uart1.contains(addr)) {
        addr -= range_uart1.base;
        uart1->io()->read(addr >> 2, 1, &value);
    }
    else if (range_unk2.contains(addr)) {
        fprintf(stderr, "AeoliaPCIeDevice::peripherals_read: addr=0x%llX, size=0x%llX\n", addr, size);
    }
    else if (range_hpet.contains(addr)) {
        assert_always("Unimplemented");
    }
    else if (range_icc.contains(addr)) {
        fprintf(stderr, "AeoliaPCIeDevice::peripherals_read: addr=0x%llX, size=0x%llX\n", addr, size);
    }
    else if (range_unk3c.contains(addr)) {
        fprintf(stderr, "AeoliaPCIeDevice::peripherals_read: addr=0x%llX, size=0x%llX\n", addr, size);
    }
    else if (range_unk3b.contains(addr)) {
        fprintf(stderr, "AeoliaPCIeDevice::peripherals_read: addr=0x%llX, size=0x%llX\n", addr, size);
    }
    else if (range_unk3a.contains(addr)) {
        fprintf(stderr, "AeoliaPCIeDevice::peripherals_read: addr=0x%llX, size=0x%llX\n", addr, size);
    }
    else if (range_bars.contains(addr)) {
        addr -= range_bars.base;
        assert_true(size == 4);
        assert_true((addr & 0x3) == 0);
        const size_t index = addr >> 3;
        value = ((addr & 0x4) == 0) ? bars[index].size : bars[index].base;
    }
    else if (range_msi.contains(addr)) {
        assert_always("Unimplemented");
    }
    else {
        assert_always("Unimplemented");
    }
    return value;
}

void AeoliaPCIeDevice::peripherals_write(U64 addr, U64 value, U64 size) {
    if (range_wdt.contains(addr)) {
        assert_always("Unimplemented");
    }
    else if (range_unk1.contains(addr)) {
        fprintf(stderr, "AeoliaPCIeDevice::peripherals_write: addr=0x%llX, value=0x%llX, size=0x%llX\n", addr, value, size);
    }
    else if (range_sflash.contains(addr)) {
        assert_always("Unimplemented");
    }
    else if (range_uart0.contains(addr)) {
        addr -= range_uart0.base;
        uart0->io()->write(addr >> 2, 1, &value);
    }
    else if (range_uart1.contains(addr)) {
        addr -= range_uart1.base;
        uart1->io()->write(addr >> 2, 1, &value);
    }
    else if (range_unk2.contains(addr)) {
        fprintf(stderr, "AeoliaPCIeDevice::peripherals_write: addr=0x%llX, value=0x%llX, size=0x%llX\n", addr, value, size);
    }
    else if (range_hpet.contains(addr)) {
        assert_always("Unimplemented");
    }
    else if (range_icc.contains(addr)) {
        fprintf(stderr, "AeoliaPCIeDevice::peripherals_write: addr=0x%llX, value=0x%llX, size=0x%llX\n", addr, value, size);
    }
    else if (range_unk3c.contains(addr)) {
        fprintf(stderr, "AeoliaPCIeDevice::peripherals_write: addr=0x%llX, value=0x%llX, size=0x%llX\n", addr, value, size);
    }
    else if (range_unk3b.contains(addr)) {
        fprintf(stderr, "AeoliaPCIeDevice::peripherals_write: addr=0x%llX, value=0x%llX, size=0x%llX\n", addr, value, size);
    }
    else if (range_unk3a.contains(addr)) {
        fprintf(stderr, "AeoliaPCIeDevice::peripherals_write: addr=0x%llX, value=0x%llX, size=0x%llX\n", addr, value, size);
    }
    else if (range_bars.contains(addr)) {
        addr -= range_bars.base;
        assert_true(size == 4);
        assert_true((addr & 0x3) == 0);
        const size_t index = addr >> 3;
        if ((addr & 0x4) == 0) {
            bars[index].size = value;
        } else {
            bars[index].base = value;
        }
        update_bars();
    }
    else if (range_msi.contains(addr)) {
        assert_always("Unimplemented");
    }
    else {
        assert_always("Unimplemented");
    }
}

void AeoliaPCIeDevice::update_bars() {

}
