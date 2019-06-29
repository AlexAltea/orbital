/**
 * (c) 2017-2018 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Based in previous research by: flatz.
 */

#ifndef PUP_DECRYPTER_H
#define PUP_DECRYPTER_H

#include "ksdk.h"

// Format
typedef struct bls_entry_t {
    uint32_t block_offset;
    uint32_t file_size;
    uint32_t reserved[2];
    uint8_t  file_name[0x20];
} bls_entry_t;

typedef struct bls_header_t {
    uint32_t magic;
    uint32_t version;
    uint32_t flags;
    uint32_t entry_count;
    uint32_t block_count;
    uint32_t reserved[3];
    bls_entry_t entries[0];
} bls_header_t;

typedef struct pup_t {
    int fd;
    char *file_path;
    size_t file_size;
    size_t entries_size;
    /* contents */
    struct bls_header_t header;
    struct bls_entry_t *entries;
    /* kernel */
    int svc_id;
    /* blobs */
    struct blob_t *blobs;
} pup_t;

/* functions */
pup_t* pup_open(const char *file);
int pup_verify_header(pup_t *pup);
int pup_decrypt_segments(pup_t *pup);
void pup_close(pup_t *pup);

#endif /* PUP_DECRYPTER_H */
