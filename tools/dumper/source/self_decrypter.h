/**
 * (c) 2017-2018 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Based in previous tools and research by: fail0verflow, flatz.
 */

#ifndef SELF_DECRYPTER_H
#define SELF_DECRYPTER_H

#include "ksdk.h"

#include "elf32.h"
#include "elf64.h"

// Format
typedef struct self_entry_t {
    uint32_t props;
    uint32_t reserved;
    uint64_t offset;
    uint64_t filesz;
    uint64_t memsz;
} self_entry_t;

typedef struct self_header_t {
    uint32_t magic;
    uint8_t version;
    uint8_t mode;
    uint8_t endian;
    uint8_t attr;
    uint32_t key_type;
    uint16_t header_size;
    uint16_t meta_size;
    uint64_t file_size;
    uint16_t num_entries;
    uint16_t flags;
    uint32_t reserved;
    self_entry_t entries[0];
} self_header_t;

// Context
struct self_auth_info_t {
    uint8_t buf[0x88];
};

typedef struct self_t {
    int fd;
    char *file_path;
    size_t file_size;
    size_t entries_size;
    size_t data_offset;
    size_t data_size;
    /* contents */
    struct self_header_t header;
    struct self_entry_t *entries;
    uint8_t *data;
    /* kernel */
    struct self_auth_info_t auth_info;
    struct self_context_t *ctx;
    int auth_ctx_id;
    int ctx_id;
    int svc_id;
    int verified;
    /* blobs */
    struct blob_t *blobs;
} self_t;

/* functions */
self_t* self_open(const char *file);
int self_verify_header(self_t *self);
int self_load_segments(self_t *self);
void self_close(self_t *self);

#endif /* SELF_DECRYPTER_H */
