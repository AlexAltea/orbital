#Goes through every reference to "sys_ioctl", and attempts to print the second argument's value.
#@author dtu
#@category PS4
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.util.task import TaskMonitor

results = currentProgram.getSymbolTable().getLabelOrFunctionSymbols("sys_ioctl", None)
if len(results) > 0:
    ioctl_fun = results[0]
    xrefs = ioctl_fun.getReferences(TaskMonitor.DUMMY)
    for xref in xrefs:
        instr = getInstructionAt(xref.fromAddress)
        should_break = False		

        while True:
            instr = instr.previous
            for obj in instr.resultObjects:
                if obj.name == "ESI" or obj.name == "RSI":
                    print xref.fromAddress.toString() + ": " + instr.inputObjects[0].toString()
                    should_break = True
                    break
            if should_break:
                break
else:
    print "Could not find symbol 'sys_ioctl'! Did you create it yet?"
