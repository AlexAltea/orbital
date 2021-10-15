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
#include "aeolia_mem.h"

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

/* Constants */
enum {
    APCIE_ICC_REG_DOORBELL  = range_icc.base + 0x804,
    APCIE_ICC_REG_STATUS    = range_icc.base + 0x814,
    APCIE_ICC_REG_UNK820    = range_icc.base + 0x820,
    APCIE_ICC_REG_IRQ_MASK  = range_icc.base + 0x824,
};

constexpr U32 APCIE_ICC_MSG_PENDING = 0x1;
constexpr U32 APCIE_ICC_IRQ_PENDING = 0x2;
constexpr U32 APCIE_ICC_REPLY = 0x4000;
constexpr U32 APCIE_ICC_EVENT = 0x8000;

static U16 icc_checksum(const IccMessageHeader& message) {
    auto* data = reinterpret_cast<const U08*>(&message);
    U16 checksum = 0;
    for (size_t i = 0; i < ICC_MESSAGE_MAXSIZE; i++) {
        checksum += data[i];
    }
    return checksum;
}

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

    // ICC
    icc_doorbell = 0;
    icc_status = 0;
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

    switch (addr) {
    case APCIE_ICC_REG_DOORBELL:
        value = icc_doorbell;
        break;
    case APCIE_ICC_REG_STATUS:
        value = icc_status;
        break;
    default:
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
    }
    return value;
}

void AeoliaPCIeDevice::peripherals_write(U64 addr, U64 value, U64 size) {
    switch (addr) {
    case APCIE_ICC_REG_DOORBELL:
        icc_doorbell |= value;
        update_icc();
        break;
    case APCIE_ICC_REG_STATUS:
        icc_status &= ~value;
        break;
    case APCIE_ICC_REG_UNK820:
    case APCIE_ICC_REG_IRQ_MASK:
        fprintf(stderr, "AeoliaPCIeDevice::peripherals_write: addr=0x%llX, value=0x%llX, size=0x%llX\n", addr, value, size);
        break;
    default:
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
            }
            else {
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
}

void AeoliaPCIeDevice::update_bars() {
}

void AeoliaPCIeDevice::update_icc() {
    icc_doorbell &= ~APCIE_ICC_IRQ_PENDING;
    if ((icc_doorbell & APCIE_ICC_MSG_PENDING) == 0) {
        return;
    }

    // Access ICC message from SPM
    auto* spm_data = (uint8_t*)spm->ptr();
    auto& query = reinterpret_cast<const IccQueryMessage&>(spm_data[ASPM_ICC_QUERY]);
    auto& reply = reinterpret_cast<      IccReplyMessage&>(spm_data[ASPM_ICC_REPLY]);
    if (query.magic != 0x42) {
        fprintf(stderr, "AeoliaPCIeDevice::update_icc: Unexpected ICC command: 0x%X\n", query.magic);
    }

    // Process ICC query
    AeoliaPCIeDevice::IccReply status = { IccResult::OK, 0 };
    switch (query.major) {
    case ICC_CMD_SERVICE:
        switch (query.minor) {
        case ICC_CMD_SERVICE_VERSION:
            status = icc_cmd_service_version();
            break;
        default:
            fprintf(stderr, "icc: Unknown service query 0x%04X!\n", query.minor);
        }
        break;
    case ICC_CMD_BOARD:
        switch (query.minor) {
        case ICC_CMD_BOARD_OP_GET_BOARD_ID:
            status = icc_cmd_board_id();
            break;
        case ICC_CMD_BOARD_OP_GET_FW_VERSION:
            status = icc_cmd_board_version(reply.cmd_fwver);
            break;
        default:
            fprintf(stderr, "icc: Unknown board query 0x%04X!\n", query.minor);
        }
        break;
    case ICC_CMD_BUTTONS:
        switch (query.minor) {
        case ICC_CMD_BUTTONS_OP_STATE:
            status = icc_cmd_buttons_state();
            break;
        default:
            fprintf(stderr, "icc: Unknown buttons query 0x%04X!\n", query.minor);
        }
        break;
    case ICC_CMD_BUZZER:
        switch (query.minor) {
        default:
            fprintf(stderr, "icc: Unknown buzzer query 0x%04X!\n", query.minor);
        }
        break;
    case ICC_CMD_UNK0D:
        switch (query.minor) {
        default:
            fprintf(stderr, "icc: Unknown unk_0D query 0x%04X!\n", query.minor);
        }
        break;
    case ICC_CMD_NVRAM:
        switch (query.minor) {
        case ICC_CMD_NVRAM_OP_WRITE:
            status = icc_cmd_nvram_write(query.cmd_nvram);
            break;
        case ICC_CMD_NVRAM_OP_READ:
            status = icc_cmd_nvram_read(query.cmd_nvram, reply.cmd_nvram);
            break;
        default:
            fprintf(stderr, "icc: Unknown NVRAM query 0x%04X!\n", query.minor);
        }
        break;
    default:
        fprintf(stderr, "icc: Unknown query 0x%04X!\n", query.major);
    }

    // Create ICC reply
    reply = {};
    reply.magic = query.magic;
    reply.major = query.major;
    reply.minor = query.minor | APCIE_ICC_REPLY;
    reply.cookie = query.cookie;
    reply.length = std::get<1>(status) + sizeof(IccMessageHeader);
    reply.result = std::get<0>(status);
    reply.checksum = icc_checksum(reply);

    spm_data[ASPM_ICC_QUERY_W] = 0;
    spm_data[ASPM_ICC_QUERY_R] = 1;
    spm_data[ASPM_ICC_REPLY_W] = 1;
    spm_data[ASPM_ICC_REPLY_R] = 0;
    icc_status |= APCIE_ICC_MSG_PENDING | APCIE_ICC_IRQ_PENDING;
    icc_doorbell &= ~APCIE_ICC_MSG_PENDING;
    // apcie_msi_trigger(&s->msic, 4, APCIE_MSI_FNC4_ICC);
}

AeoliaPCIeDevice::IccReply AeoliaPCIeDevice::icc_cmd_service_version() {
    fprintf(stderr, "icc: icc_cmd_service_version\n");
    return { IccResult::OK, 0 };
}

AeoliaPCIeDevice::IccReply AeoliaPCIeDevice::icc_cmd_board_id() {
    fprintf(stderr, "icc: icc_cmd_board_id\n");
    return { IccResult::OK, 0 };
}

AeoliaPCIeDevice::IccReply AeoliaPCIeDevice::icc_cmd_board_version(IccReplyBoardVersion& reply) {
    reply.emc_version_major = 0x0002;
    reply.emc_version_minor = 0x0018;
    reply.emc_version_branch = 0x0001;
    reply.emc_version_revision = 0x0000;

    // Numbers are based on firmware version found in 5.00 recovery
    reply.syscon_version_major = 0x0100;
    reply.syscon_version_minor = 0x0;
    reply.syscon_version_branch = 0x7;
    reply.syscon_version_revision = 0x10;
    reply.syscon_version_modify = 0x45;
    reply.syscon_version_edition = 0x54;
    reply.syscon_version_reserved = 0x0;

    return { IccResult::OK, sizeof(reply) };
}

AeoliaPCIeDevice::IccReply AeoliaPCIeDevice::icc_cmd_buttons_state() {
    fprintf(stderr, "icc: icc_cmd_buttons_state\n");
    return { IccResult::OK, 0 };
}

AeoliaPCIeDevice::IccReply AeoliaPCIeDevice::icc_cmd_nvram_write(const IccQueryNvram& query) {
    fprintf(stderr, "icc: icc_cmd_nvram_write(addr=0x%X, size=0x%X)\n", query.addr, query.size);
    return { IccResult::OK, 0 };
}

AeoliaPCIeDevice::IccReply AeoliaPCIeDevice::icc_cmd_nvram_read(const IccQueryNvram& query, IccReplyNvram& reply) {
    fprintf(stderr, "icc: icc_cmd_nvram_read(addr=0x%X, size=0x%X)\n", query.addr, query.size);

    AeoliaPCIeDevice::IccReply status = { IccResult::OK, 0 };
    switch (query.addr) {
    case 0x18: // sceKernelHwHasWlanBt second bit as 1 for none
        reply.unk00 = 2;
        status = { IccResult::OK, 1 };
        break;
    case 0x20: // init_safe_mode
    case 0x21: // sysctl_machdep_cavern_dvt1_init_update current mode
    case 0x30: // wlan mode?
    case 0x38: // something gbe
    case 0x50: // ssb_rtc_init_exclock
    case 0xA0: // get_icc_max
    default:
        // ignore
        break;
    }
    return status;
}
