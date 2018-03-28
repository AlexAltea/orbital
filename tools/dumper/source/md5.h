/**
  Copyright © 2015 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#ifndef MD5_H
#define MD5_H

#include "ksdk.h"

#define MD5_CBLOCK  64
#define MD5_DIGEST_LENGTH 16
#define MD5_LBLOCK MD5_DIGEST_LENGTH/4

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

#pragma pack(push, 1)
typedef struct _MD5_CTX {
  union {
    uint8_t b[MD5_DIGEST_LENGTH];
    uint32_t w[MD5_DIGEST_LENGTH/4];
  } s;
  union {
    uint8_t b[MD5_CBLOCK];
    uint32_t w[MD5_CBLOCK/4];
    uint64_t q[MD5_CBLOCK/8];
  } buf;
  uint64_t len;
} MD5_CTX;
#pragma pack(pop)

#ifdef __cplusplus
extern "C" {
#endif

  void MD5_Init (MD5_CTX*);
  void MD5_Update (MD5_CTX*, const void *, uint32_t);
  void MD5_Final (void*, MD5_CTX*);

#ifdef __cplusplus
}
#endif

#endif
