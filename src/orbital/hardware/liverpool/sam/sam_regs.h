/**
 * AMD Secure Asset Management Unit (SAMU) device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

 // SAM block
#define mmSAM_IX_INDEX                    0x8800
#define mmSAM_IX_DATA                     0x8801
#define mmSAM_SAB_IX_INDEX                0x8802
#define mmSAM_SAB_IX_DATA                 0x8803
#define mmSAM_IND_INDEX                   0x8800
#define mmSAM_IND_DATA                    0x8801
#define mmSAM_AM32_BOOT_BASE              0x8809
#define mmSAM_AM32_BOOT_OFFSET            0x880A
#define mmSAM_AM32_BOOT_LENGTH            0x880B
#define mmSAM_AM32_BOOT_CTRL              0x880C
#define mmSAM_AM32_BOOT_STATUS            0x880D
#define mmSAM_AM32_BOOT_HASH0             0x880E
#define mmSAM_AM32_BOOT_HASH1             0x880F
#define mmSAM_AM32_BOOT_HASH2             0x8810
#define mmSAM_AM32_BOOT_HASH3             0x8811
#define mmSAM_AM32_BOOT_HASH4             0x8812
#define mmSAM_AM32_BOOT_HASH5             0x8813
#define mmSAM_AM32_BOOT_HASH6             0x8814
#define mmSAM_AM32_BOOT_HASH7             0x8815
#define mmSAM_EMU_SRCID                   0x8816
#define mmSAM_GPR_SCRATCH_4               0x8818
#define mmSAM_GPR_SCRATCH_5               0x8819
#define mmSAM_GPR_SCRATCH_6               0x881A
#define mmSAM_GPR_SCRATCH_7               0x881B
#define mmSAM_GPR_SCRATCH_0               0x881C
#define mmSAM_GPR_SCRATCH_1               0x881D
#define mmSAM_GPR_SCRATCH_2               0x881E
#define mmSAM_GPR_SCRATCH_3               0x881F
#define mmSAM_POWER_GATE                  0x8834
#define mmSAM_BOOT_PWR_UP                 0x8835
#define mmSAM_SMU_ALLOW_MEM_ACCESS        0x8836
#define mmSAM_PGFSM_CONFIG_REG            0x8837
#define mmSAM_PGFSM_WRITE_REG             0x8838
#define mmSAM_PGFSM_READ_REG              0x8839
#define mmSAM_PKI_FAIL_STATUS             0x883A

// SAMIND block
#define ixSAM_RST_HOST_SOFT_RESET         0x0001
#define ixSAM_CGC_HOST_CTRL               0x0003
#define ixSAM_IH_CPU_AM32_INT             0x0032
#define ixSAM_IH_CPU_AM32_INT_CTX_HIGH    0x0033
#define ixSAM_IH_CPU_AM32_INT_CTX_LOW     0x0034
#define ixSAM_IH_AM32_CPU_INT_CTX_HIGH    0x0035
#define ixSAM_IH_AM32_CPU_INT_CTX_LOW     0x0036
#define ixSAM_IH_AM32_CPU_INT_ACK         0x0037
#define ixSAM_SCRATCH_0                   0x0038
#define ixSAM_SCRATCH_1                   0x0039
#define ixSAM_SCRATCH_2                   0x003A
#define ixSAM_SCRATCH_3                   0x003B
#define ixSAM_SCRATCH_4                   0x003C
#define ixSAM_SCRATCH_5                   0x003D
#define ixSAM_SCRATCH_6                   0x003E
#define ixSAM_SCRATCH_7                   0x003F
#define ixSAM_IH_CPU_AM32_INT_STATUS      0x004A
#define ixSAM_IH_AM32_CPU_INT_STATUS      0x004B
#define ixSAM_RST_HOST_SOFT_RST_RDY       0x0051

// SABIND block
#define ixSAM_SAB_INIT_TLB_CONFIG         0x0004
#define ixSAM_SAB_EFUSE_STATUS_CNTL       0x0029
