/**
 * Aeolia MSI Controller (MSIC) device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <orbital/core.h>

// List of subfunctions for function #4 (PCIe)
#define APCIE_MSI_FNC4_GLUE      0
#define APCIE_MSI_FNC4_ICC       3
#define APCIE_MSI_FNC4_HPET      5
#define APCIE_MSI_FNC4_SFLASH   11
#define APCIE_MSI_FNC4_RTC      13
#define APCIE_MSI_FNC4_UART0    19
#define APCIE_MSI_FNC4_UART1    20
#define APCIE_MSI_FNC4_TWSI     21

// List of subfunctions for function #7 (XHCI)
#define APCIE_MSI_FNC7_XHCI0     0
#define APCIE_MSI_FNC7_XHCI1     1
#define APCIE_MSI_FNC7_XHCI2     2

class AeoliaMsic : public Device {
public:
    AeoliaMsic(Space* mem);

    void reset();

    /**
     * Perform 32-bit MMIO read at an offset relative to the MSI controller base.
     * @param[in]  offset  Offset to read from
     * @return             Value read
     */
    U32 mmio_read(U32 index);

    /**
     * Perform 32-bit MMIO write at an offset relative to the MSI controller base.
     * @param[in]  offset  Offset to write to
     * @param[in]  value   Value to be written
     */
    void mmio_write(U32 offset, U32 value);

    /**
     * Send an interrupt to the CPU given a function:subfunction.
     * @param[in]  func  Function identifier
     * @param[in]  sub   Subfunction identifier
     */
    void msi_trigger(U32 func, U32 sub);

private:
    Space* mem;

    U32 func_addr[8];
    U32 func_mask[8];
    U32 func_data[8];
    union {
        struct {
            U32 func0_data_lo[4];
            U32 func1_data_lo[4];
            U32 func2_data_lo[4];
            U32 func3_data_lo[4];
            U32 func4_data_lo[24];
            U32 func5_data_lo[4];
            U32 func6_data_lo[4];
            U32 func7_data_lo[4];
        };
        U32 data_lo[52];
    };
};
