/**
 * (c) 2017-2018 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Based in previous tools and research by: m0rph3us1987.
 */

#ifndef SELF_MAPPER_H
#define SELF_MAPPER_H

#include "ksdk.h"

/* functions */
uint8_t* self_decrypt(
    uint8_t *self_data, size_t self_size, int self_fd,
    size_t *elf_sizep);

uint8_t* self_decrypt_fd(int fd,
    size_t *elf_sizep);
uint8_t* self_decrypt_file(const char *file,
    size_t *elf_sizep);

#endif /* SELF_MAPPER_H */
