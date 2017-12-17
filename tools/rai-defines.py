#!/usr/bin/python
import os
import sys
from rai import *

def should_avoid_expension(reg):
    if not reg.fields:
        return True
    base = reg.fields[0].name[:-1]
    for i in xrange(len(reg.fields)):
        field = reg.fields[i]
        if field.name == base+str(i) and field.hi == field.lo == i:
            return True
    return False

def define_reg(addr, reg):
    print "#define %-48s 0x%08X" % (reg.name, addr)
    if should_avoid_expension(reg):
        return
    for field in reg.fields:
        if (field.hi, field.lo) == (31, 0):
            return
        macro = "  " + field.name + "(M)"
        mask = "M(0x%02X,0x%02X)" % (field.hi, field.lo)
        print "#define %-46s %8s" % \
            (macro, mask)
        
def main():
    if len(sys.argv) <= 1:
        print("Generate C/C++ preprocessor #define's for RAI-defined MMIO regs")
        print("Requires Python 2.x.")
        print("\nUsage: python %s <space>" % os.path.basename(__file__))
        print("\nExample:")
        print("  1. Clone https://github.com/fail0verflow/radeon-tools")
        print("  2. Copy this file to radeon-tools/rai")
        print("  3. Enter that folder and enter:")
        print("     - python raiparse.py grammar.rai grammar.pickle")
        print("     - python %s GpuF0Reg" % os.path.basename(__file__))
    else:
        rai = load_default_rai()
        space = sys.argv[1]
        space = rai.chip_spaces[space]
        for addr, reg in sorted(space.addrs.items()):
            define_reg(addr, reg)

if __name__ == '__main__':
    main()
