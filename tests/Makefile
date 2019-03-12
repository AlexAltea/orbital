CC ?= gcc
AR  ?= ar
CC  ?= gcc
CXX ?= g++

CFLAGS    = -Wall -Wextra -Og -g
CXXFLAGS  = -Wall -Wextra -Og -g -std=c++11
ARC       = $(wildcard *.a)
OBJ       = $(wildcard *.o)
BIN       = $(patsubst %.cpp, %.elf, $(wildcard *.cpp)) \
            $(patsubst %.c,   %.elf, $(wildcard *.c))

.PHONY: all clean

all: $(BIN)

clean:
	rm -f $(ARC)
	rm -f $(OBJ)
	rm -f $(BIN)

# Tests
test_gcn_disasm.elf: test_gcn_disasm.c
	$(CC) $(CFLAGS) -o $@ $< \
		../orbital-qemu/hw/ps4/liverpool/gca/gcn_parser.c \
		../orbital-qemu/hw/ps4/liverpool/gca/gcn_disasm.c \
		-I../orbital-qemu/hw/ps4/liverpool/gca

test_gcn_analyzer.elf: test_gcn_analyzer.c
	$(CC) $(CFLAGS) -o $@ $< \
		../orbital-qemu/hw/ps4/liverpool/gca/gcn_parser.c \
		../orbital-qemu/hw/ps4/liverpool/gca/gcn_analyzer.c \
		../orbital-qemu/hw/ps4/liverpool/gca/gcn_resource.c \
		-I../orbital-qemu/hw/ps4/liverpool/gca

test_gcn_translator.elf: test_gcn_translator.cpp libspirv.a
	$(CC) $(CFLAGS) -c \
		../orbital-qemu/hw/ps4/liverpool/gca/gcn_parser.c \
		../orbital-qemu/hw/ps4/liverpool/gca/gcn_analyzer.c \
		../orbital-qemu/hw/ps4/liverpool/gca/gcn_resource.c \
		-I../orbital-qemu/hw/ps4/liverpool/gca
	$(CXX) $(CXXFLAGS) -o $@ $< gcn_parser.o gcn_analyzer.o  gcn_resource.o \
		../orbital-qemu/hw/ps4/liverpool/gca/gcn_translator.cpp \
		-I../orbital-qemu/hw/ps4/liverpool/gca \
		-lSPIRV
