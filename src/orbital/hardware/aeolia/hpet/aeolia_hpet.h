/**
 * Aeolia High-Precision Event Timer (HPET) device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <orbital/core.h>

struct HPETTimer {
    union {
        U64 value;
        struct {
            U32 value_lo;
            U32 value_hi;
        };
        Bit<U64, 1> int_type_cnf;
        Bit<U64, 2> int_enb_cnf;
        Bit<U64, 3> type_cnf;
        Bit<U64, 4> per_int_cap;
        Bit<U64, 5> size_cap;
        Bit<U64, 6> val_set_cnf;
        Bit<U64, 8> mode32_cnf;
        Bitrange<U64,  9, 13> int_route_cnf;
        Bitrange<U64, 14, 14> fsb_en_cnf;
        Bitrange<U64, 15, 15> fsb_int_del_cap;
        Bitrange<U64, 32, 63> int_route_cap;
    } config;
    U64 comparator;
    union {
        U64 value;
        struct {
            U32 int_val;
            U32 int_addr;
        };
    } fsb;
};

struct AeoliaHpetConfig : DeviceConfig {
    U64 base = 0xFED00000;
    U64 count = 4;
    U64 period_fs = 100 * 1000000; // 100ns
};

class AeoliaHpet : public Device {
public:
    AeoliaHpet(ContainerSpace* mem, const AeoliaHpetConfig& config = {});
    ~AeoliaHpet();

    void reset() override;

    U64 mmio_read(U64 addr, U64 size);
    void mmio_write(U64 addr, U64 value, U64 size);

private:
    Space* mem;
    MemorySpace* mmio;
    std::vector<HPETTimer> timers;

    struct {
        union {
            U64 value;
            struct {
                U32 value_lo;
                U32 value_hi;
            };
            Bitrange<U64,  0,  7> rev_id;
            Bitrange<U64,  8, 12> num_tim_cap;
            Bitrange<U64, 13, 13> count_size_cap;
            Bitrange<U64, 15, 15> leg_rt_cap;
            Bitrange<U64, 16, 21> vendor_id;
            Bitrange<U64, 32, 63> period;
        } cap;
        union {
            U64 value;
            struct {
                U32 value_lo;
                U32 value_hi;
            };
            Bit<U64, 1> leg_rt_cnf;
            Bit<U64, 0> enable_cnf;
        } config;
        union {
            U64 value;
            struct {
                U32 value_lo;
                U32 value_hi;
            };
            Bitset<64> tn_int_sts;
        } isr;
        union {
            U64 value;
            struct {
                U32 lo;
                U32 hi;
            };
        } counter;
    } s = {};

    // Helpers
    U64 get_counter();
    U64 get_ticks();

    // Interrupts
    void update_irq(HPETTimer& timer, bool set);
};
