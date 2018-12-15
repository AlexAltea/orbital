tui enable
layout split
layout asm
layout regs
target remote localhost:1234
set disassembly-flavor intel

###########
# FW 4.55 #
###########

define env_orbis_455
  #symbol-file orbisys-455.sym
  #break btext
end

###########
# FW 5.00 #
###########

define env_orbis_500
  #symbol-file orbisys-500.sym
  #break btext
end

# Continue
env_orbis_500
continue
