/**
 * Aeolia High-Precision Event Timer (HPET) device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "aeolia_hpet.h"

#include <chrono>

using namespace std::chrono_literals;

enum HPETGeneralReg {
    HPET_REG_CAP = 0x00,
    HPET_REG_CFG = 0x10,
    HPET_REG_IS  = 0x20,
    HPET_REG_CNT = 0xF0,
};

enum HPETTimerReg {
    HPET_REG_TNCFG_0 = 0x00,
    HPET_REG_TNCFG_1 = 0x04,
    HPET_REG_TNCMP_0 = 0x08,
    HPET_REG_TNCMP_1 = 0x0C,
    HPET_REG_TNROUTE_0 = 0x10,
    HPET_REG_TNROUTE_1 = 0x14,
};

AeoliaHpet::AeoliaHpet(ContainerSpace* mem, const AeoliaHpetConfig& config)
    : Device(nullptr, config), mem(mem) {
    // Initialize MMIO
    mmio = new MemorySpace(this, 0x1000, {
        static_cast<MemorySpaceReadOp>(&AeoliaHpet::mmio_read),
        static_cast<MemorySpaceWriteOp>(&AeoliaHpet::mmio_write),
    });
    mem->addSubspace(mmio, config.base);

    // Create timers
    assert_true(config.count >= 3);
    assert_true(config.count <= 32);
    timers.resize(config.count);

    // Capabilities
    s.cap.num_tim_cap = config.count - 1;
    s.cap.period = config.period_fs;

    reset();
}

AeoliaHpet::~AeoliaHpet() {}

void AeoliaHpet::reset() {
    for (auto& timer : timers) {
        timer.comparator = UINT64_MAX;
        // TODO
    }

    s.config.value = 0;
    s.counter.value = 0;
    // TODO
}

U64 AeoliaHpet::mmio_read(U64 addr, U64 size) {
    U64 value = 0;

    // Sanity checks
    assert_true(size == 4);

    if (addr < 0x100) {
        /* General access */
        switch (addr) {
        case HPET_REG_CAP + 0:
            value = s.cap.value_lo;
            break;
        case HPET_REG_CAP + 4:
            value = s.cap.value_hi;
            break;
        case HPET_REG_CFG + 0:
            value = s.config.value;
            break;
        case HPET_REG_IS + 0:
            value = s.isr.value_lo;
            break;
        case HPET_REG_IS + 4:
            value = s.isr.value_hi;
            break;
        case HPET_REG_CNT + 0:
            value = get_counter();
            break;
        case HPET_REG_CNT + 4:
            value = get_counter() >> 32;
            break;

        // Ignored upper-accesses
        case HPET_REG_CFG + 4:
            break;

        default:
            assert_always("Invalid register access");
        }
    }
    else {
        /* Timer-N access */
        const U64 index = (addr - 0x100) / 0x20;
        const U64 offset = addr % 0x20;
        assert_true(index < timers.size());
        const auto& timer = timers[index];

        switch (offset) {
        case HPET_REG_TNCFG_0:
            value = timer.config.value_lo;
            break;
        case HPET_REG_TNCFG_1:
            value = timer.config.value_hi;
            break;
        case HPET_REG_TNCMP_0:
            value = timer.comparator;
            break;
        case HPET_REG_TNCMP_1:
            value = timer.comparator >> 32;
            break;
        case HPET_REG_TNROUTE_0:
            value = timer.fsb.int_val;
            break;
        case HPET_REG_TNROUTE_1:
            value = timer.fsb.int_addr;
            break;
        default:
            assert_always("Invalid register access");
        }
    }
    return static_cast<U32>(value);
}

void AeoliaHpet::mmio_write(U64 addr, U64 value, U64 size) {
    // Sanity checks
    assert_true(size == 4);

    if (addr < 0x100) {
        // General access
        switch (addr) {
        case HPET_REG_CNT + 0:
            s.counter.lo = value;
            break;
        case HPET_REG_CNT + 4:
            s.counter.hi = value;
            break;
        case HPET_REG_CFG + 0:
            s.config.value = value;
            break;
        case HPET_REG_IS + 0:
            value &= s.isr.value_lo;
            for (int i = 0; i < timers.size(); i++) {
                if (value & (1 << i)) {
                    update_irq(timers[i], i);
                }
            }
            break;

        // Ignored accesses
        case HPET_REG_CAP + 0:
            break;

        default:
            assert_always("Invalid register access");
        }
    }
    else {
        // Timer-N access
        const U64 index = (addr - 0x100) / 0x20;
        const U64 offset = addr % 0x20;
        assert_true(index < timers.size());
        auto& tn = timers[index];

        switch (offset) {
        case HPET_REG_TNCFG_0:
            tn.config.value_lo = value;
            break;
        case HPET_REG_TNROUTE_0:
            tn.fsb.int_val = value;
            break;
        case HPET_REG_TNROUTE_1:
            tn.fsb.int_addr = value;
            break;
        default:
            assert_always("Invalid register access");
        }
    }
}

U64 AeoliaHpet::get_counter() {
    if (s.config.enable_cnf) {
        s.counter.value = get_ticks();
    }
    return s.counter.value;
}

U64 AeoliaHpet::get_ticks() {
    return Clock::now().time_since_epoch().count() / 100; // 100ns period
}

void AeoliaHpet::update_irq(HPETTimer& timer, bool set) {
    if (!s.config.enable_cnf) {
        assert_always("Unexpected");
        return;
    }

    /**
     * LegacyReplacement Route
     * =======================
     * If the ENABLE_CNF bit and the LEG_RT_CNF bit are both set,
     * then the interrupts will be routed as follows: 
     * - Timer 0 will be routed to IRQ0 in Non-APIC or IRQ2 in the I/O APIC 
     * - Timer 1 will be routed to IRQ8 in Non-APIC or IRQ8 in the I/O APIC 
     */
    if (s.config.leg_rt_cnf) {
        assert_always("Unimplemented");
        return;
    }

    // FSB IRQ route
    if (timer.config.fsb_en_cnf) {
        mem->write<U32>(timer.fsb.int_addr, timer.fsb.int_val);
        return;
    }
}
