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

test_gcn_analyzer.elf: test_gcn_analyzer.c
	$(CC) $(CFLAGS) -o $@ $< \
		../orbital-qemu/hw/ps4/liverpool/gca/gcn_parser.c \
		../orbital-qemu/hw/ps4/liverpool/gca/gcn_analyzer.c \
		-I../orbital-qemu/hw/ps4/liverpool/gca/

test_gcn_translator.elf: test_gcn_translator.c
	$(CC) $(CFLAGS) -o $@ $< \
		../orbital-qemu/hw/ps4/liverpool/gca/gcn_parser.c \
		../orbital-qemu/hw/ps4/liverpool/gca/gcn_analyzer.c \
		../orbital-qemu/hw/ps4/liverpool/gca/gcn_translator.c \
		-I../orbital-qemu/hw/ps4/liverpool/gca/
