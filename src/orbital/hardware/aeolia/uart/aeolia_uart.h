/**
 * Aeolia UART device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <orbital/core.h>

struct AeoliaUARTDeviceConfig : DeviceConfig {
    CharHost* backend = nullptr;

    AeoliaUARTDeviceConfig(CharHost* backend = nullptr)
        : backend(backend) {
    }
};

class AeoliaUARTDevice final : public Device {
public:
    AeoliaUARTDevice(Device* parent, Interrupt* irq, const AeoliaUARTDeviceConfig& config = {});
    ~AeoliaUARTDevice();

    void reset() override;

    // Helpers
    MemorySpace* io() const {
        return space_io;
    }

private:
    Interrupt* irq;

    FIFO<U8, 16> fifo_rx;
    FIFO<U8, 16> fifo_tx;
    bool thre_intr_pending = false;
    struct {
        U8 thr; // Transmitter Holding Register
        U8 rbr; // Receiver Buffer Register
        U8 ier; // Interrupt Enable Register
        U8 iir; // Interrupt Identification Register
        U8 lcr; // Line Control Register
        U8 mcr; // Modem Control Register
        U8 lsr; // Line Status Register
        U8 msr; // Modem Status Register
        U8 scr; // Scratch Register
        U8 fcr; // FIFO Control Register
        union {
            U16 div; // Divisor Latch
            struct {
                U8 dll;
                U8 dlh;
            };
        };
    } s = {};

    CharHost* char_backend{ nullptr };
    MemorySpace* space_io{ nullptr };

    void update_irq();

    U64 io_read(U64 addr, U64 size);
    void io_write(U64 addr, U64 value, U64 size);
};
