/**
 * AMD Cryptographic Co-Processor (CCP) device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <core.h>

enum CcpOp {
    CCP_OP_AES           =  0,
    CCP_OP_AES_INSITU    =  1,
    CCP_OP_XTS           =  2,
    CCP_OP_SHA           =  3,
    CCP_OP_RSA           =  4,
    CCP_OP_PASS          =  5,
    CCP_OP_ECC           =  6,
    CCP_OP_ZLIB          =  7,
    CCP_OP_TRNG          =  8,
    CCP_OP_HMAC          =  9,
    CCP_OP_SNVS          = 10,
};

enum CcpAesSize {
    CCP_AES_SIZE_128     = 0,
    CCP_AES_SIZE_192     = 1,
    CCP_AES_SIZE_256     = 2,
};

enum CcpAesMode {
    CCP_AES_MODE_DEC     = 0,
    CCP_AES_MODE_ENC     = 1,
};

enum CcpAesMode {
    CCP_AES_MODE_ECB     = 0,
};

#define CCP_FLAG_SLOT_KEY      0x40000
#define CCP_FLAG_SLOT_OUT      0x80000

#define CCP_OP_AES_KEY(M)      M(11,10)
#define CCP_OP_AES_TYPE(M)     M(12,12)
#define CCP_OP_AES_MODE(M)     M(15,13)
