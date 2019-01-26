/**
 * (c) 2017-2018 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 */

#ifndef KSDK_H
#define KSDK_H

#include "ps4.h"

#include "ksdk_bsd.h"
#include "ksdk_gpu.h"
#include "ksdk_sbl.h"
#include "ksdk_util.h"

#ifdef __GNUC__
#define __cdecl    __attribute__((cdecl))
#define __fastcall __attribute__((fastcall))
#endif

#define false  0
#define true   1

#define KFUNC(slide, name, ret, args) \
    extern ret (*name) args
#define KDATA(slide, name, type) \
    extern type* name
#include "ksdk.inc"
#undef KFUNC
#undef KDATA

void init_ksdk();

#endif /* KSDK_H */
