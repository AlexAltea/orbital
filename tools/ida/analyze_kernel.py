#!/usr/bin/env python

import idaapi

from define_syscalls import *

def analyze_sysinit():
    # Create sysinit type
    sysinit_name = "sysinit_t"
    sysinit_type = get_struc_id(sysinit_name)
    if sysinit_type == BADADDR:
        sysinit_type = add_struc(-1, sysinit_name, 0)
        add_struc_member(sysinit_type, "subsystem",
            -1, (FF_DWRD | FF_DATA), -1, 4)
        add_struc_member(sysinit_type, "order",
            -1, (FF_DWRD | FF_DATA), -1, 4)
        add_struc_member(sysinit_type, "func",
            -1, (FF_QWRD | FF_DATA), -1, 8)
        add_struc_member(sysinit_type, "udata",
            -1, (FF_QWRD | FF_DATA), -1, 8)
    sysinit_size = get_struc_size(sysinit_type)
    assert(sysinit_size == 0x18)

    # Define sysinit pointers
    sysinit_start = get_name_ea_simple("__start_set_sysinit_set")
    sysinit_stop = get_name_ea_simple("__stop_set_sysinit_set")
    if sysinit_start == BADADDR or \
       sysinit_stop == BADADDR:
        print("Define __start_set_sysinit_set and __stop_set_sysinit_set!")
        exit(1)
    for ea in range(sysinit_start, sysinit_stop, 8):
        create_qword(ea)
        create_struct(get_qword(ea), sysinit_size, sysinit_name)

def analyze_syscalls():
    # Create sysent type
    sysent_name = "sysent_t"
    sysent_type = get_struc_id(sysent_name)
    if sysent_type == BADADDR:
        sysent_type = add_struc(-1, sysent_name, 0)
        add_struc_member(sysent_type, "sy_narg",
            0x00, (FF_DWRD | FF_DATA), -1, 4)
        add_struc_member(sysent_type, "sy_call",
            0x08, (FF_QWRD | FF_DATA), -1, 8)
        add_struc_member(sysent_type, "sy_auevent",
            0x10, (FF_WORD | FF_DATA), -1, 2)
        add_struc_member(sysent_type, "sy_systrace_args_func",
            0x18, (FF_QWRD | FF_DATA), -1, 8)
        add_struc_member(sysent_type, "sy_entry",
            0x20, (FF_DWRD | FF_DATA), -1, 4)
        add_struc_member(sysent_type, "sy_return",
            0x24, (FF_DWRD | FF_DATA), -1, 4)
        add_struc_member(sysent_type, "sy_flags",
            0x28, (FF_DWRD | FF_DATA), -1, 4)
        add_struc_member(sysent_type, "sy_thrcnt",
            0x2C, (FF_DWRD | FF_DATA), -1, 4)
    sysent_size = get_struc_size(sysent_type)
    assert(sysent_size == 0x30)

    # Define sysent pointers
    sysent_start = get_name_ea_simple("sysent")
    sysent_stop = get_name_ea_simple("sysent") + 0x8000
    for ea in range(sysent_start, sysent_stop, sysent_size):
        syscall_id = (ea - sysent_start) / sysent_size
        syscall_name = syscall_list.get(syscall_id, None)
        syscall_args = get_qword(ea + 0x0)
        syscall_func = get_qword(ea + 0x8)
        if syscall_args > 0x80:
            break
        del_items(ea, 0, sysent_size)
        create_struct(ea, sysent_size, sysent_name)
        if syscall_name is not None:
            set_name(syscall_func, syscall_name)

def analyze_qwords():
    # Get kernel boundaries
    kernel_start = BADADDR
    kernel_stop = 0x0
    seg_count = 0
    for ea in Segments():
        seg_count += 1
        kernel_start = min(kernel_start, SegStart(ea))
        kernel_stop = max(kernel_stop, SegEnd(ea))

    # Transform every potential kernel pointer to a qword
    for i in range(seg_count):
        seg = idaapi.getnseg(i)
        for ea in range(seg.startEA, seg.endEA, 8):
            if get_item_size(ea) >= 8:
                continue
            value = get_qword(ea)
            if kernel_start <= value < kernel_stop:
                create_qword(ea)

def analyze_code():
    seg = idaapi.getnseg(0)
    for ea in range(seg.startEA, seg.endEA, 1):
        MakeCode(ea)

def main():
    analyze_sysinit()
    analyze_syscalls()
    analyze_qwords()
    #analyze_code() # TODO: OOB!

if __name__ == '__main__':
    main()
