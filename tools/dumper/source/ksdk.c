/**
 * (c) 2017-2018 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 */

#include "ksdk.h"

#define KFUNC(slide, name, ret, args) \
    ret (*name) args
#define KDATA(slide, name, type) \
    type* name
#include "ksdk.inc"
#undef KFUNC
#undef KDATA

static inline __attribute__((always_inline))
uint64_t get_kbase() {
    uint64_t base;
    uint32_t edx, eax;
    __asm__ ("rdmsr" : "=d"(edx), "=a"(eax) : "c"(0xC0000082));
    base = ((((uint64_t)edx) << 32) | (uint64_t)eax) - 448;
    return base;
}

#define KSLIDE(offset) \
    (void*)(kbase + offset);

void init_ksdk() {
    uint8_t* kbase = (uint8_t*)get_kbase();
#define KFUNC(slide, name, ret, args) \
    name = KSLIDE(slide)
#define KDATA(slide, name, type) \
    name = KSLIDE(slide)
#include "ksdk.inc"
#undef KFUNC
#undef KDATA
}
