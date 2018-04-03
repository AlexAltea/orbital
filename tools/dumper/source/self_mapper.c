/**
 * (c) 2017-2018 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Based in previous tools and research by: m0rph3us1987.
 */

#include "self_mapper.h"
#include "self_decrypter.h"

#include "ksdk.h"
#include "blob.h"
#include "debug.h"

#include "elf32.h"
#include "elf64.h"

#define MAP_SELF 0x80000
#define PT_NID 0x61000000

#define assert(cond) if (!(cond)) { \
        dprintf("%s:%d: failed.\n", __FUNCTION__, __LINE__); \
        goto error; \
    }

static int valid_elf_magic(const uint8_t *magic)
{
    return
        (magic[0] == 0x7F) &&
        (magic[1] == 0x45) &&
        (magic[2] == 0x4C) &&
        (magic[3] == 0x46);
}

uint8_t* self_decrypt(
    uint8_t *self_data, size_t self_size, int self_fd,
    size_t *elf_sizep)
{
    uint8_t *elf_data;
    size_t ehdr_off;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    uint8_t *elf_base;
    uint8_t *elf_segment;
    size_t elf_size;
    size_t i, j, off;

    // Determine actual format
    ehdr_off = 0;
    ehdr = (void*)&self_data[ehdr_off];
    if (valid_elf_magic(ehdr->e_ident)) {
        elf_data = malloc(self_size);
        memcpy(elf_data, self_data, self_size);
        *elf_sizep = self_size;
        return elf_data;
    } else {
        self_header_t *self_hdr = (void*)self_data;
        ehdr_off += sizeof(self_header_t);
        ehdr_off += sizeof(self_entry_t) * self_hdr->num_entries;
        ehdr = (void*)&self_data[ehdr_off];
        elf_base = (void*)ehdr;
    }

    // Parse EHDR
    if (!valid_elf_magic(ehdr->e_ident)) {
        return NULL;
    }
    ehdr->e_shoff = 0;
    ehdr->e_shnum = 0;
    elf_size = ehdr->e_phoff + (ehdr->e_phnum * ehdr->e_phentsize) + (ehdr->e_shnum * ehdr->e_shentsize);

    // Parse PHDRs
    phdr = (void*)&elf_base[ehdr->e_phoff];
    for (i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD ||
            phdr[i].p_type == PT_NID  ||
            phdr[i].p_type == PT_DYNAMIC)
        {
            elf_size = MAX(elf_size, phdr[i].p_offset + phdr[i].p_filesz);
        }
    }

    *elf_sizep = elf_size;
    elf_data = malloc(elf_size);

    // Copy EHDR
    for (i = 0; i < ehdr->e_ehsize; i++)
        elf_data[i] = elf_base[i];

    // Copy PHDRs and segments
    for (i = 0; i < ehdr->e_phnum; i++) {
        for (j = 0; j < ehdr->e_phentsize; j++) {
            off = ehdr->e_phoff + (i * ehdr->e_phentsize) + j;
            elf_data[off] = elf_base[off];
        }
        if (phdr[i].p_type == PT_LOAD || phdr[i].p_type == PT_NID) {
            lseek(self_fd, 0, SEEK_SET);
            elf_segment = mmap(NULL, phdr[i].p_filesz, PROT_READ, MAP_SHARED | MAP_SELF, self_fd, i << 32);
            for (j = 0; j < phdr[i].p_filesz; j++) {
                elf_data[phdr[i].p_offset + j] = elf_segment[j];
            }
            munmap(elf_segment, phdr[i].p_filesz);
        }
    }
    return elf_data;
}

uint8_t* self_decrypt_fd(int fd,
    size_t *elf_sizep)
{
    uint8_t *elf_data = NULL;
    uint8_t *self_data = NULL;
    size_t self_size;
    size_t off;

    off = lseek(fd, 0, SEEK_END);
    assert(off >= 0);
    self_size = off;
    off = lseek(fd, 0, SEEK_SET);
    assert(off >= 0);
    self_data = malloc(self_size);
    assert(self_data);
    off = read(fd, self_data, self_size);
    assert(off == self_size);
    elf_data = self_decrypt(self_data, self_size, fd, elf_sizep);

error:
    free(self_data);
    return elf_data;
}

uint8_t* self_decrypt_file(const char *file,
    size_t *elf_sizep)
{
    uint8_t *elf_data = NULL;
    int fd;

    fd = open(file, O_RDONLY, 0);
    assert(fd >= 0);
    elf_data = self_decrypt_fd(fd, elf_sizep);
    close(fd);

error:
    return elf_data;
}
