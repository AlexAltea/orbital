#!/usr/bin/env python

import idaapi
import idautils
import re

# Regex patterns
pattern_function_outside = [
    # Found in safemode.elf
    "([0-9A-Za-z:_]+) failed! \(result:%#x\)",
]
pattern_function_inside = [
    # Found in safemode.elf
    "([0-9A-Za-z:_]+) failed! \(standby page is NULL\)"
]

### Utilities ###

def get_last_direct_call(block, strict=True):
    """
    Iterate predecessor instructions backwards until first direct call.
    Strict-mode ensure that the match is actually the last call in the block.
    """
    for head in reversed(list(Heads(block.startEA, block.endEA))):
        instr = idautils.DecodeInstruction(head)
        mnem = instr.get_canon_mnem()
        if mnem != "call":
            continue
        refs = list(CodeRefsFrom(head, 1))
        if len(refs) > 1:
            return refs[1]
        if strict:
            return BADADDR
    return BADADDR

def get_predecessors(blocks, blacklist=set()):
    """
    Get set of predecessor blocks of a given set of blocks.
    Optionally, it can be filtered with set of blacklisted blocks.
    """
    preds = set()
    for block in blocks:
        preds |= set(block.preds())
    preds = preds.difference(blacklist)
    return preds

def rename_function_outside(name, string_ea):
    functions = set()
    # Get set of functions called prior to basic blocks that xref the string
    for instr_xref in XrefsTo(string_ea):
        instr_ea = instr_xref.frm
        func = idaapi.get_func(instr_ea)
        if not func:
            continue
        cfg = idaapi.FlowChart(func, flags=ida_gdl.FC_PREDS) 
        # Get predecessor block(s)
        preds = {}
        blacklist = {}
        for block in cfg:
            if block.startEA <= instr_ea and block.endEA > instr_ea:
                blacklist = {block}
                preds = get_predecessors({block}, blacklist)
                break
        # Scan predecessors recursively for last direct calls
        found = False
        while True:
            for pred in preds:
                target_ea = get_last_direct_call(pred)
                if target_ea != BADADDR:
                    functions.add(target_ea)
                    found = True
            # Exit on candidates or no predecessors
            if found or not preds:
                break
            # Update predecessors
            blacklist |= preds
            preds = get_predecessors(preds, blacklist)

    # Ensure we only have exactly one candidate function
    if len(functions) != 1:
        print "None or multiple candidates detected @ string:0x%X" % (string_ea)
        return
    # Rename the candidate function
    func_ea = next(iter(functions))
    print "Renaming function 0x%X to %s" % (func_ea, name)
    idc.MakeNameEx(func_ea, name, idc.SN_NOWARN)

def rename_function_inside(name, string_ea):
    functions = set()
    # Get set of functions that contain xrefs the string
    for instr_xref in XrefsTo(string_ea):
        instr_ea = instr_xref.frm
        func = idaapi.get_func(instr_ea)
        functions.add(func.startEA)
    # Ensure we only have exactly one candidate function
    if len(functions) != 1:
        print "None or multiple candidates detected @ string:0x%X" % (string_ea)
        return
    # Rename the candidate function
    func_ea = next(iter(functions))
    print "Renaming function 0x%X to %s" % (func_ea, name)
    idc.MakeNameEx(func_ea, name, idc.SN_NOWARN)


### Analysis ###

def analyze_functions():
    # Reconstruct function names from strings
    for pattern in pattern_function_outside:
        for string in idautils.Strings():
            match = re.match(pattern, str(string))
            if match:
                rename_function_outside(match.group(1), string.ea)
    for pattern in pattern_function_inside:
        for string in idautils.Strings():
            match = re.match(pattern, str(string))
            if match:
                rename_function_inside(match.group(1), string.ea)

def analyze_qwords():
    # Get user boundaries
    user_start = BADADDR
    user_stop = 0x0
    seg_count = 0
    for ea in Segments():
        seg_count += 1
        user_start = min(user_start, SegStart(ea))
        user_stop = max(user_stop, SegEnd(ea))

    # Transform every potential user pointer to a qword
    for i in range(seg_count):
        seg = idaapi.getnseg(i)
        for ea in range(seg.startEA, seg.endEA, 8):
            if get_item_size(ea) >= 8:
                continue
            value = get_qword(ea)
            if user_start <= value < user_stop:
                create_qword(ea)

def analyze_prologues():
    # Target prologue: push rbp; mov rbp, rsp
    prologue = "55 48 89"
    # For each user code segment
    for ea in Segments():
        if ida_segment.segtype(ea) != SEG_CODE:
            continue
        user_start = SegStart(ea)
        user_stop = SegEnd(ea)
        # Find solitary prologues
        ea = user_start
        while True:
            ea = idc.FindBinary(ea+1, idc.SEARCH_DOWN, prologue)
            if ea > user_stop:
                break
            func = idaapi.get_func(ea)
            if func is None:
                idc.MakeFunction(ea)

### Main ###

def main():
    """
    The order of the following analysis stages is not arbitrary:
    They are ordered according to these two rules:
    1. Analysis dependencies must be considered,
       e.g. first detect functions, then process functions.
    2. Analysis with higher success rate go last.
       e.g. first do pattern based search, then rename syscalls.
    """
    # Detection stage
    analyze_qwords()
    analyze_prologues()
    # Renaming stage
    analyze_functions()

if __name__ == '__main__':
    main()
