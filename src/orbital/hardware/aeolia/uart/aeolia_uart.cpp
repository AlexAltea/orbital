/**
 * Aeolia UART device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "aeolia_uart.h"

AeoliaUARTDevice::AeoliaUARTDevice(Device* parent, Interrupt* irq, const AeoliaUARTDeviceConfig& config)
    : Device(parent, config), char_backend(config.backend), irq(irq) {
    // Initialize IO
    const MemorySpaceOps serial_ops = {
        static_cast<MemorySpaceReadOp>(&AeoliaUARTDevice::io_read),
        static_cast<MemorySpaceWriteOp>(&AeoliaUARTDevice::io_write),
    };
    space_io = new MemorySpace(this, 0x8, serial_ops);

    reset();
}

AeoliaUARTDevice::~AeoliaUARTDevice() {}

void AeoliaUARTDevice::reset() {
    fifo_rx = {};
    fifo_tx = {};

    s.ier = 0;
    s.iir = IIR_NOPEND;
    s.lcr = 0;
    s.lsr = LSR_TEMT | LSR_THRE;
    s.msr = MSR_DCD | MSR_DSR | MSR_CTS;
    s.mcr = MCR_OUT2;
    s.div = 0x0C;
    s.fcr = 0;
};

void AeoliaUARTDevice::update_irq() {
    U8 tmp;

    // Update IIR
    if ((s.ier & IER_ERLS) && (s.lsr & LSR_OE)) {
        tmp = IIR_RLS;
    }
    else if ((s.ier & IER_ERDA) && (s.lsr & LSR_DR)) {
        tmp = IIR_RDA;
    }
    else if ((s.ier & IER_ERDA) && (s.fcr & FCR_FE) && fifo_rx.empty()) {
        assert_always("Unimplemented");
        tmp = IIR_CHRTMT;
    }
    else if ((s.ier & IER_ETHRE) && thre_intr_pending) {
        tmp = IIR_THRE;
    }
    else if ((s.ier & IER_EMSC) && (s.msr & UART_MSR_DELTA_MASK)) {
        tmp = IIR_MLSC;
    }
    else {
        tmp = IIR_NOPEND;
    }

    s.iir = tmp | (s.iir & ~IIR_IMASK);
    if (irq != nullptr) {
        if (tmp == IIR_NOPEND) {
            irq->lower();
        }
        else {
            irq->raise();
        }
    }
}

U64 AeoliaUARTDevice::io_read(U64 addr, U64 size) {
    U8 value = 0;

    // Sanity checks
    assert_true(size == 1);
    assert_true(addr < 0x8);

    if (s.lcr & LCR_DLAB) {
        switch (addr) {
        case UART_REG_DLL:
            value = s.dll;
            goto done;
        case UART_REG_DLH:
            value = s.dlh;
            goto done;
        }
    }

    switch (addr) {
    case UART_REG_DATA:
        if (s.fcr & FCR_FE) {
            value = fifo_rx.empty() ? 0x00 : fifo_rx.front();
            fifo_rx.pop();
        }
        else {
            value = s.rbr;
            s.lsr &= ~LSR_DR;
        }
        update_irq();
        break;
    case UART_REG_IER:
        value = s.ier;
        break;
    case UART_REG_IIR:
        value = s.iir;
        // Clear THRE Interrupt
        if ((value & IIR_THRE) != 0) {
            thre_intr_pending = false;
            update_irq();
        }
        break;
    case UART_REG_LCR:
        value = s.lcr;
        break;
    case UART_REG_MCR:
        value = s.mcr;
        break;
    case UART_REG_LSR:
        value = s.lsr;
        // Clear LSR Interrupts
        if (s.lsr & (LSR_BI | LSR_OE)) {
            s.lsr &= ~(LSR_BI | LSR_OE);
            update_irq();
        }
        break;
    case UART_REG_MSR:
        value = s.msr;
        // Clear MSR Interrupts
        if ((s.msr & UART_MSR_DELTA_MASK) != 0) {
            s.msr &= ~UART_MSR_DELTA_MASK;
            update_irq();
        }
        break;
    case UART_REG_SCR:
        value = s.scr;
        break;
    default:
        assert_always("Unknown register");
    }

done:
    return value;
}

void AeoliaUARTDevice::io_write(U64 addr, U64 rawval, U64 size) {
    U8 diff;
    U8 value = static_cast<U8>(rawval);

    // Sanity checks
    assert_true(size == 1);
    assert_true(addr < 0x8);

    if (s.lcr & LCR_DLAB) {
        switch (addr) {
        case UART_REG_DLL:
            s.dll = value;
            return;
        case UART_REG_DLH:
            s.dlh = value;
            return;
        }
    }

    switch (addr) {
    case UART_REG_DATA:
        if (s.fcr & FCR_FE) {
            // This shouldnt be hit
            assert_always("fifo mode not implmented");
            if (s.mcr & MCR_LOOPBACK) {
                s.lsr |= fifo_rx.push(value) ? 0 : LSR_OE;
            }
            else {
                // TODO: We are ignoring the write for now
            }
        }
        else {
            if (s.mcr & MCR_LOOPBACK) {
                s.rbr = value;
                if (s.lsr & LSR_DR)
                    s.lsr |= LSR_OE;
                s.lsr |= LSR_DR;
            }
            else {
                s.thr = value;
                // todo: move me into timer?
                if (char_backend)
                    char_backend->write({ s.thr });
            }
        }
        s.lsr |= (LSR_TEMT | LSR_THRE);
        thre_intr_pending = true;
        update_irq();
        break;
    case UART_REG_IER:
        diff = (s.ier ^ value) & 0xF;
        s.ier = value & 0x0F;
        if (diff) {
            if (diff & IER_ETHRE) {
                thre_intr_pending = (s.ier & IER_ETHRE) && (s.lsr & LSR_THRE);
            }
            update_irq();
        }
        break;
    case UART_REG_FCR:
        update_irq();
        break;
    case UART_REG_LCR:
        s.lcr = value;
        break;
    case UART_REG_MCR:
        s.mcr = value & 0x1F;
        s.msr &= UART_MSR_DELTA_MASK;
        if (s.mcr & MCR_LOOPBACK) {
            if (s.mcr & MCR_RTS && ~(s.msr & MSR_CTS))
                s.msr |= MSR_DCTS;
            if (s.mcr & MCR_DTR && ~(s.msr & MSR_DSR))
                s.msr |= MSR_DDSR;
            if (s.mcr & MCR_OUT1 && ~(s.msr & MSR_RI))
                s.msr |= MSR_TERI;
            if (s.mcr & MCR_OUT2 && ~(s.msr & MSR_DCD))
                s.msr |= MSR_DDCD;
        }
        break;
    case UART_REG_SCR:
        s.scr = value;
        break;

    // Ignore read-only registers
    case UART_REG_LSR:
    case UART_REG_MSR:
        break;

    default:
        assert_always("Unknown register");
    }
}
