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

#include "md5.h"

#define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z) F (z, x, y)
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

#ifdef DYNAMIC

#include <math.h>

#pragma intrinsic (fabs, pow, sin)

uint32_t tc (uint32_t i)
{
  uint32_t r;
  r = (uint32_t)(fabs(sin(i)*pow(2,32)));
  return r;
}
#endif

/************************************************
 *
 * transform a block of data.
 *
 ************************************************/
void MD5_Transform (MD5_CTX* ctx)
{
    uint32_t a, b, c, d, i, t, s;
    uint8_t rotf[]={7,12,17,22};
    uint8_t rotg[]={5, 9,14,20};
    uint8_t roth[]={4,11,16,23};
    uint8_t roti[]={6,10,15,21};

    uint8_t sigma[]=
    { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
      1,6,11,0,5,10,15,4,9,14,3,8,13,2,7,12,
      5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2,
      0,7,14,5,12,3,10,1,8,15,6,13,4,11,2,9 };

  #ifndef DYNAMIC
  uint32_t tc[64] =
  { 0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391 };
  #endif

    a = ctx->s.w[0];
    b = ctx->s.w[1];
    c = ctx->s.w[2];
    d = ctx->s.w[3];

    for (i=0; i<64; i++) {
      #ifdef DYNAMIC
        t=tc(i+1);
      #else
        t=tc[i];
      #endif
      if (i < 16) {
        s = rotf[i%4];
        a += F (b, c, d);
      } else if (i < 32) {
        s = rotg[i%4];
        a += G (b, c, d);
      } else if (i < 48) {
        s = roth[i%4];
        a += H (b, c, d);
      } else {
        s = roti[i%4];
        a += I (b, c, d);
      }
      a += ctx->buf.w[sigma[i]] + t;
      a = ROTL32(a, s);
      a += b;
      t=a;
      a=d;
      d=c;
      c=b;
      b=t;
    }

    ctx->s.w[0] += a;
    ctx->s.w[1] += b;
    ctx->s.w[2] += c;
    ctx->s.w[3] += d;
}

/************************************************
 *
 * initialize context
 *
 ************************************************/
void MD5_Init (MD5_CTX* c) {
    c->len    = 0;
    c->s.w[0] = 0x67452301;
    c->s.w[1] = 0xefcdab89;
    c->s.w[2] = 0x98badcfe;
    c->s.w[3] = 0x10325476;
}

/************************************************
 *
 * update state with input
 *
 ************************************************/
void MD5_Update (MD5_CTX* c, const void *in, uint32_t len) {
    uint8_t *p = (uint8_t*)in;
    uint32_t  r, idx;

    if (len==0) return;

    // get buffer index
    idx = c->len & (MD5_CBLOCK - 1);

    // update length
    c->len += len;

    while (len > 0) {
      r = MIN(len, (MD5_CBLOCK - idx));
      memcpy (&c->buf.b[idx], p, r);
      if ((idx + r) < MD5_CBLOCK) break;

      MD5_Transform (c);
      len -= r;
      idx = 0;
      p += r;
    }
}

/************************************************
 *
 * Finalize.
 *
 ************************************************/
void MD5_Final (void* dgst, MD5_CTX* c)
{
    // see what length we have ere..
    uint32_t len=c->len & (MD5_CBLOCK - 1);

    memset (&c->buf.b[len], 0, MD5_CBLOCK - len);
    // add the end bit
    c->buf.b[len] = 0x80;
    // if exceeding 56 bytes, transform it
    if (len >= 56) {
      MD5_Transform (c);
      memset (c->buf.b, 0, MD5_CBLOCK);
    }
    // add total bits
    c->buf.q[7] = c->len * 8;
    // compress
    MD5_Transform(c);
    // copy digest to buffer
    memcpy (dgst, c->s.b, MD5_DIGEST_LENGTH);
}
