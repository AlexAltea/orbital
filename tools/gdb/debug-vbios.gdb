tui enable
layout split
layout asm
layout regs
target remote localhost:1234
set disassembly-flavor intel

define vc
  disable $arg0
  stepi
  enable $arg0
  continue
end

define atomsi
  vc $arg0
  print/x $bx
end

# Continue
hbreak *0xC0003
continue
