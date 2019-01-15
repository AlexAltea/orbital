CC ?= gcc

CFLAGS  = -Wall -Wextra -Og -g
SRC     = $(wildcard *.c)
OBJ     = $(wildcard *.o)
BIN     = $(patsubst %.c, %.elf, $(SRC))

.PHONY: all clean

all: $(BIN)

clean:
	rm -f $(OBJ)
	rm -f $(BIN)

# Tests
test_gcn_disasm.elf: test_gcn_disasm.c
	$(CC) $(CFLAGS) -o $@ $< \
		../orbital-qemu/hw/ps4/liverpool/gca/gcn_parser.c \
		../orbital-qemu/hw/ps4/liverpool/gca/gcn_disasm.c \
		-I../orbital-qemu/hw/ps4/liverpool/gca/
