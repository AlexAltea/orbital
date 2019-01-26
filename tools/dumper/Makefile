LIBPS4  := $(PS4SDK)/libPS4

TEXT    := 0x926200000
DATA    := 0x926300000

CC      := gcc
AS      := gcc
OBJCOPY := objcopy
ODIR    := build
SDIR    := source
IDIRS   := -I$(LIBPS4)/include -I. -Iinclude
LDIRS   := -L$(LIBPS4) -L. -Llib
LIBS    := -lPS4
CFLAGS  := $(IDIRS) -O2 -std=c11 -fno-builtin -nostartfiles -nostdlib -Wall -masm=intel -march=btver2 -mtune=btver2 -m64 -mabi=sysv -mcmodel=large -DTEXT_ADDRESS=$(TEXT) -DDATA_ADDRESS=$(DATA)
SFLAGS  := -nostartfiles -nostdlib -march=btver2 -mtune=btver2
LFLAGS  := $(LDIRS) -Xlinker -T $(LIBPS4)/linker.x -Wl,--build-id=none -Ttext=$(TEXT) -Tdata=$(DATA)
CFILES  := $(wildcard $(SDIR)/*.c)
SFILES  := $(wildcard $(SDIR)/*.s)
OBJS    := $(patsubst $(SDIR)/%.c, $(ODIR)/%.o, $(CFILES)) \
           $(patsubst $(SDIR)/%.s, $(ODIR)/%.o, $(SFILES))

TARGET = $(shell basename $(CURDIR)).bin

.PHONY: all
all: 5.00

.PHONY: 1.76
1.76: CFLAGS += -DVERSION_176
1.76: $(TARGET)

.PHONY: 4.55
4.55: CFLAGS += -DVERSION_455 
4.55: $(TARGET)

.PHONY: 5.00
5.00: CFLAGS += -DVERSION_500
5.00: $(TARGET)

.PHONY: 5.05
5.05: CFLAGS += -DVERSION_505 
5.05: $(TARGET)

$(TARGET): $(ODIR) $(OBJS)
	$(CC) $(LIBPS4)/crt0.s $(ODIR)/*.o -o temp.t $(CFLAGS) $(LFLAGS) $(LIBS)
	$(OBJCOPY) -O binary temp.t $(TARGET)
	rm -f temp.t

$(ODIR)/%.o: $(SDIR)/%.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR)/%.o: $(SDIR)/%.s
	$(AS) -c -o $@ $< $(SFLAGS)

$(ODIR):
	@mkdir $@

.PHONY: clean
clean:
	rm -f $(TARGET) $(ODIR)/*.o
