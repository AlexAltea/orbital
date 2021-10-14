/**
 * Sony ICC protocol.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <core.h>

/* ICC commands */
enum IccCommand : U16 {
    ICC_CMD_SERVICE                             = 0x01,
    ICC_CMD_BOARD                               = 0x02,
    ICC_CMD_NVRAM                               = 0x03,
    ICC_CMD_UNK04                               = 0x04, // icc_power_init
    ICC_CMD_BUTTONS                             = 0x08,
    ICC_CMD_BUZZER                              = 0x09,
    ICC_CMD_SAVE_CONTEXT                        = 0x0B, // thermal
    ICC_CMD_LOAD_CONTEXT                        = 0x0C,
    ICC_CMD_UNK0D                               = 0x0D, // icc_configuration_get_devlan_setting
    ICC_CMD_UNK70                               = 0x70, // sceControlEmcHdmiService
    ICC_CMD_SNVRAM_READ                         = 0x8D,
};

enum IccCommandServiceOp : U16 {
    ICC_CMD_SERVICE_VERSION                     = 0x0000,
};

enum IccCommandBoardOp : U16 {
    ICC_CMD_BOARD_OP_GET_MAC_ADDR               = 0x0001,
    ICC_CMD_BOARD_OP_GET_BD_ADDR                = 0x0002,
    ICC_CMD_BOARD_OP_SET_BD_ADDR                = 0x0003,
    ICC_CMD_BOARD_OP_CLEAR_BD_ADDR              = 0x0004,
    ICC_CMD_BOARD_OP_GET_BOARD_ID               = 0x0005,
    ICC_CMD_BOARD_OP_GET_FW_VERSION             = 0x0006,
    ICC_CMD_BOARD_OP_GET_ERROR_LOG              = 0x0007,
    ICC_CMD_BOARD_OP_CLEAR_ERROR_LOG            = 0x0008,
    ICC_CMD_BOARD_OP_GET_DDR_CAPACITY           = 0x0009,
    ICC_CMD_BOARD_OP_SET_VDD                    = 0x000A,
    ICC_CMD_BOARD_OP_SAVE_CONTEXT               = 0x000B,
    ICC_CMD_BOARD_OP_LOAD_CONTEXT               = 0x000C,
    ICC_CMD_BOARD_OP_GET_DEVLAN                 = 0x000D,
    ICC_CMD_BOARD_OP_SET_DEVLAN                 = 0x000E,
    ICC_CMD_BOARD_OP_GET_CPU_INFOBIT            = 0x000F,
    ICC_CMD_BOARD_OP_SET_CPU_INFOBIT            = 0x0010,
    ICC_CMD_BOARD_OP_SET_DOWNLOAD_MODE          = 0x0011,
    ICC_CMD_BOARD_OP_GET_BDD_CHUCKING_STATE     = 0x0012,
    ICC_CMD_BOARD_OP_SET_PCIE_LINKDOWN_REC_MODE = 0x0013,
    ICC_CMD_BOARD_OP_GET_CP_MODE                = 0x0014,
    ICC_CMD_BOARD_OP_SET_CP_MODE                = 0x0015,
    ICC_CMD_BOARD_OP_GET_HDMI_CONFIG            = 0x0016,
    ICC_CMD_BOARD_OP_GET_OS_DEBUGINFO           = 0x0017,
    ICC_CMD_BOARD_OP_SET_OS_DEBUGINFO           = 0x0018,
    ICC_CMD_BOARD_OP_SET_ACIN_DET_MODE          = 0x0019,
    ICC_CMD_BOARD_OP_GET_L2_SWITCH_DETECT       = 0x001B,
    ICC_CMD_BOARD_OP_GET_SYSTEM_SUSPEND_STATE   = 0x001C,
};

enum IccCommandNvramOp : U16 {
    ICC_CMD_NVRAM_OP_WRITE                      = 0x0000,
    ICC_CMD_NVRAM_OP_READ                       = 0x0001,
};

enum IccCommandButtonsOp : U16 {
    ICC_CMD_BUTTONS_OP_STATE                    = 0x0000,
    ICC_CMD_BUTTONS_OP_LIST                     = 0x0001,
};

/* ICC result code */
enum class IccResult : U16 {
    OK = 0,
};

/* ICC message header */
CORE_PACKED(struct IccMessageHeader {
    LE<U08> magic;
    LE<U08> major;
    LE<U16> minor;
    LE<U16> reserved;
    LE<U16> cookie;
    LE<U16> length;
    LE<U16> checksum;
    LE<IccResult> result;
});

/* ICC message queries */
CORE_PACKED(struct IccQueryNvram {
    LE<U16> addr;
    LE<U16> size;
});

/* ICC message replies */
CORE_PACKED(struct IccReplyBoardVersion {
    // NOTE: These fields are named based on some unreferenced strings.
    // TODO: Double-check once you find the corresponding Xref.
    LE<U32> emc_version_major;
    LE<U32> emc_version_minor;
    LE<U32> emc_version_branch;
    LE<U32> emc_version_revision;
    LE<U32> emc_version_modify;
    LE<U32> emc_version_edition;
    LE<U32> emc_version_sec_dsc;
    LE<U32> emc_version_reserved;

    LE<U16> syscon_version_major;
    LE<U16> syscon_version_minor;
    LE<U16> syscon_version_branch;
    LE<U16> syscon_version_revision;

    LE<U08> syscon_version_modify;
    LE<U08> syscon_version_edition;
    LE<U08> syscon_version_sec_dsc;
    LE<U08> syscon_version_reserved;
});
static_assert(sizeof(IccReplyBoardVersion) == 0x2C);

CORE_PACKED(struct IccReplyNvram {
    LE<U08> unk00;
});

/* ICC messages */
constexpr size_t ICC_MESSAGE_MAXSIZE = 0x7F0;

struct IccQueryMessage : IccMessageHeader {
    union {
        U08 data[ICC_MESSAGE_MAXSIZE - sizeof(IccMessageHeader)];

        // ICC_CMD_NVRAM_OP_WRITE
        // ICC_CMD_NVRAM_OP_READ
        IccQueryNvram cmd_nvram;
    };
};
struct IccReplyMessage : IccMessageHeader {
    union {
        U08 data[ICC_MESSAGE_MAXSIZE - sizeof(IccMessageHeader)];

        // ICC_CMD_BOARD_OP_GET_FW_VERSION
        IccReplyBoardVersion cmd_fwver;
        // ICC_CMD_NVRAM_OP_READ
        IccReplyNvram cmd_nvram;
    };
};

static_assert(sizeof(IccQueryMessage) == ICC_MESSAGE_MAXSIZE,
    "Invalid ICC message size");
static_assert(sizeof(IccReplyMessage) == ICC_MESSAGE_MAXSIZE,
    "Invalid ICC message size");
