CC ?= gcc
AR  ?= ar
CC  ?= gcc
CXX ?= g++

CFLAGS    = -Wall -Wextra -Og -g
CXXFLAGS  = -Wall -Wextra -Og -g -std=c++11
ARC       = $(wildcard *.a)
SRC       = $(wildcard *.c)
OBJ       = $(wildcard *.o)
BIN       = $(patsubst %.c, %.elf, $(SRC))

.PHONY: all clean

all: $(BIN)

clean:
	rm -f $(ARC)
	rm -f $(OBJ)
	rm -f $(BIN)

# Dependencies
libspirv.a:
	$(CXX) $(CXXFLAGS) -c \
		../orbital-qemu/spirv/InReadableOrder.cpp \
		../orbital-qemu/spirv/Logger.cpp \
		../orbital-qemu/spirv/SpvBuilder.cpp
	$(AR) rvs $@ \
		InReadableOrder.o Logger.o SpvBuilder.o
	rm -f \
		InReadableOrder.o Logger.o SpvBuilder.o

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
		-I../orbital-qemu/hw/ps4/liverpool/gca

test_gcn_translator.elf: test_gcn_translator.c libspirv.a
	$(CXX) $(CXXFLAGS) -c \
		../orbital-qemu/hw/ps4/liverpool/gca/gcn_translator.cpp \
		-I../orbital-qemu
	$(AR) rvs libgcn_translator.a gcn_translator.o
	$(CC) $(CFLAGS) -o $@ $^ libgcn_translator.a \
		../orbital-qemu/hw/ps4/liverpool/gca/gcn_parser.c \
		../orbital-qemu/hw/ps4/liverpool/gca/gcn_analyzer.c \
		-I../orbital-qemu/hw/ps4/liverpool/gca
