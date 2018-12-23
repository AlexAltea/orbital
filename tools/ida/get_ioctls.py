#!/usr/bin/env python

import idaapi
import idautils
import re
import sys
import collections

# Configuration
generate_markdown_rows = True
sys_ioctl_addr = 0x438C00
backtrack_limit_ioctl = 100
backtrack_limit_esi = 100

ioctl_dict = {}

for string in idautils.Strings():
    ioctl_name = ""

    # First heuristic
    match = re.search("ioctl\( ([0-9A-Z_]+) ([0-9A-Z_]+) \)", str(string))
    if match:
        ioctl_name = "SCE_{}_IOCTL_{}".format(match.group(1), match.group(2))
    else:
        match = re.search("ioctl\(([0-9A-Z_]+)\)", str(string))
        if match:
            ioctl_name = match.group(1)
        else:
            match = re.search("([0-9A-Z_]+) ioctl failed", str(string))
            if match:
                ioctl_name = match.group(1)

    if match:
        ioctl_dict[ioctl_name] = 0
        for str_data_ref in DataRefsTo(string.ea):
            for str_code_ref in CodeRefsTo(str_data_ref, True):
                backtrack_esi_times = 0
                instr_esi = str_code_ref

                while backtrack_esi_times < backtrack_limit_esi:
                    prev_instr_esi = DecodePreviousInstruction(instr_esi)
                    if prev_instr_esi == None:
                        break
                    if prev_instr_esi.get_canon_mnem() == "mov":
                        if prev_instr_esi.Op1.reg == 6: # esi
                            ioctl_val_candidate = prev_instr_esi.Op2.value
                            if ioctl_val_candidate != 0:
                                ioctl_dict[ioctl_name] = prev_instr_esi.Op2.value & 0xFFFFFFFF
                                break
                    instr_esi = prev_instr_esi.ea
                    backtrack_esi_times += 1

    # Second heuristic, stricter than the first one, so don't change the order
    match = re.search("SCE_([0-9A-Z_]+)_IOCTL_([0-9A-Z_]+)", str(string))
    if match:
        ioctl_name = "SCE_{}_IOCTL_{}".format(match.group(1), match.group(2))

        if ioctl_name not in ioctl_dict:
            ioctl_dict[ioctl_name] = 0
        for str_data_ref in DataRefsTo(string.ea):
            for str_code_ref in CodeRefsTo(str_data_ref, True):
                backtrack_ioctl_times = 0
                instr_ioctl = str_code_ref
                while backtrack_ioctl_times < backtrack_limit_ioctl:
                    prev_instr_ioctl = DecodePreviousInstruction(instr_ioctl)
                    if prev_instr_ioctl == None:
                        break
                    if prev_instr_ioctl.get_canon_mnem() == "call":
                        if prev_instr_ioctl.Op1.addr == sys_ioctl_addr:
                            backtrack_esi_times = 0

                            instr_esi = instr_ioctl
                            while backtrack_esi_times < backtrack_limit_esi:
                                prev_instr_esi = DecodePreviousInstruction(instr_esi)
                                if prev_instr_esi == None:
                                    break
                                if prev_instr_esi.get_canon_mnem() == "mov":
                                    if prev_instr_esi.Op1.reg == 6: # esi
                                        ioctl_val_candidate = prev_instr_esi.Op2.value
                                        if ioctl_val_candidate != 0:
                                            ioctl_dict[ioctl_name] = prev_instr_esi.Op2.value & 0xFFFFFFFF
                                            break
                                instr_esi = prev_instr_esi.ea
                                backtrack_esi_times += 1
                    instr_ioctl = prev_instr_ioctl.ea
                    backtrack_ioctl_times += 1

if ioctl_dict:
    ioctl_dict_ordered = collections.OrderedDict(sorted(ioctl_dict.items()))

    print("Found the following IOCTLs:")
    if generate_markdown_rows:
        for ioctl_name, ioctl_value in ioctl_dict_ordered.iteritems():
            print("| *{: <37} | 0x{:08X} |".format(str(ioctl_name)+'*', ioctl_value))
    else:
        for ioctl_name, ioctl_value in ioctl_dict_ordered.iteritems():
            print("{: <37} 0x{:08X}".format(ioctl_name, ioctl_value))
else:
    print("No IOCTLs found.")
