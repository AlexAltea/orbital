#!/usr/bin/env python

import idc
import idaapi
import os

# Configuration
TYPED_FUNCS_ONLY = True
TYPED_DATA_ONLY = True
OUTPUT_NAME = "ksdk"
OUTPUT_PATH = "."
XFAST_SYSCALL_SLIDE = 0x1C0

CODE_PREFIX = """/* Auto-generated file. Do not edit */
"""

CODE_HEADER = """{1}
#ifndef KERNEL_SDK_H
#define KERNEL_SDK_H

#include "ps4.h"

#ifdef __GNUC__
#define __cdecl    __attribute__((cdecl))
#define __fastcall __attribute__((fastcall))
#endif

#define KFUNC(slide, name, ret, args) \\
    extern ret (*name) args
#define KDATA(slide, name, type) \\
    extern type* name
#include "{0}.inc"
#undef KFUNC
#undef KDATA

void init_{0}();

#endif /* KERNEL_SDK_H */
""".format(OUTPUT_NAME, CODE_PREFIX)

CODE_SOURCE = """{1}
#include "{0}.h"

#define KFUNC(slide, name, ret, args) \\
    ret (*name) args
#define KDATA(slide, name, type) \\
    type* name
#include "{0}.inc"
#undef KFUNC
#undef KDATA

static inline __attribute__((always_inline))
uint64_t get_kbase() {{
    uint64_t base;
    uint32_t edx, eax;
    __asm__ ("rdmsr" : "=d"(edx), "=a"(eax) : "c"(0xC0000082));
    base = ((((uint64_t)edx) << 32) | (uint64_t)eax) - {2};
    return base;
}}

#define KSLIDE(offset) \\
    (void*)(kbase + offset);

void init_{0}() {{
    uint8_t* kbase = (uint8_t*)get_kbase();
#define KFUNC(slide, name, ret, args) \\
    name = KSLIDE(slide)
#define KDATA(slide, name, type) \\
    name = KSLIDE(slide)
#include "{0}.inc"
#undef KFUNC
#undef KDATA
}}
""".format(OUTPUT_NAME, CODE_PREFIX, XFAST_SYSCALL_SLIDE)

def generate_sdk(define_funcs, define_data):
    olddir = os.getcwd()
    newdir = OUTPUT_PATH
    os.chdir(newdir)
    with open(OUTPUT_NAME + '.h', 'w') as f:
        f.write(CODE_HEADER)
    with open(OUTPUT_NAME + '.c', 'w') as f:
        f.write(CODE_SOURCE)
    with open(OUTPUT_NAME + '.inc', 'w') as f:
        f.write(CODE_PREFIX)
        f.write('\n/* functions */\n')
        for d in define_funcs:
            fname, fslide, ftype = d
            f.write('KFUNC(0x{0:08X}, {1}, {2}, {3});\n'.format(
                fslide, fname,
                ftype[:ftype.index('(')],
                ftype[ftype.index('('):]))
        f.write('\n/* globals */\n')
        for d in define_data:
            dname, dslide, dtype = d
            f.write('KDATA(0x{0:08X}, {1}, {2});\n'.format(
                dslide, dname, dtype))
    os.chdir(olddir)

def main():
    kbase = min(Segments())
    define_funcs = []
    define_data = []

    # Add functions
    for ea in Functions():
        fname = idc.get_name(ea)
        ftype = idc.get_type(ea)
        fslide = ea - kbase
        if fname.startswith('sub_'):
            continue
        if ftype is None:
            if TYPED_FUNCS_ONLY:
                continue
            ftype = 'uint64_t (...)'
        define_funcs.append((fname, fslide, ftype))

    # Add data
    for ea, _ in Names():
        dname = idc.get_name(ea)
        dtype = idc.get_type(ea)
        dslide = ea - kbase
        flags = GetFlags(ea)
        if idc.is_code(flags) or idc.is_strlit(flags):
            continue
        if dtype is None:
            if TYPED_DATA_ONLY:
                continue
            dtype = 'void'
        define_data.append((dname, dslide, dtype))

    # Generate source files
    generate_sdk(define_funcs, define_data)

if __name__ == '__main__':
    main()
