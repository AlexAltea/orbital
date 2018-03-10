import idaapi

# Constants
NOT_FOUND = 0xFFFFFFFFFFFFFFFF

def analyze_sysinit():
    # Create sysinit type
    sysinit_name = "sysinit_t"
    sysinit_type = get_struc_id(sysinit_name)
    if sysinit_type == NOT_FOUND:
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
    if sysinit_start == NOT_FOUND or \
       sysinit_stop == NOT_FOUND:
        print("Define __start_set_sysinit_set and __stop_set_sysinit_set!")
        exit(1)
    for ea in range(sysinit_start, sysinit_stop, 8):
        create_qword(ea)
        create_struct(get_qword(ea), sysinit_size, sysinit_name)

def analyze_qwords():
    # Get kernel boundaries
    kernel_start = NOT_FOUND
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

def main():
    analyze_sysinit()
    analyze_qwords()

if __name__ == '__main__':
    main()
