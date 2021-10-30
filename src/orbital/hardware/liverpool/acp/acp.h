/**
 * AMD ACP device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

// ACP Control registers
#define mmACP_CONTROL                                    0x00005286
#define mmACP_STATUS                                     0x00005288
#define mmACP_DSP_RUNSTALL                               0x00005289
#define mmACP_DSP_VECT_SEL                               0x0000528A
#define mmACP_DSP_WAIT_MODE                              0x0000528B
#define mmACP_OCD_HALT_ON_RST                            0x0000528C
#define mmACP_SOFT_RESET                                 0x0000528D

// ACP DMA registers
#define mmACP_DMA_CH_STS                                 0x000051A0
#define mmACP_DMA_CNTL_(I)                        (0x00005130 + (I))
#define mmACP_DMA_CUR_DSCR_(I)                    (0x00005170 + (I))
#define mmACP_DMA_CUR_TRANS_CNT_(I)               (0x00005180 + (I))
#define mmACP_DMA_ERR_STS_(I)                     (0x00005190 + (I))

// ACP external interrupt registers
#define mmACP_EXTERNAL_INTR_ENB                          0x000051E4
#define mmACP_EXTERNAL_INTR_CNTL                         0x000051E5
#define mmACP_EXTERNAL_INTR_STAT                         0x000051EA
#define mmACP_DSP_SW_INTR_CNTL                           0x000051E8
#define mmACP_DSP_SW_INTR_STAT                           0x000051EB

// ACP unknown regs
#define mmACP_UNK512F_                                   0x0000512F
