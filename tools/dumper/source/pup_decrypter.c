/**
 * (c) 2017-2018 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Based in previous research by: flatz.
 */

#include "pup_decrypter.h"

#include "ksdk.h"
#include "blob.h"
#include "debug.h"

/* debugging */
#define DEBUG_PUP 1

#define assert(cond) if (!(cond)) { \
        dprintf("%s:%d: failed.\n", __FUNCTION__, __LINE__); \
        goto error; \
    }
#define kassert(cond) if (!(cond)) { \
        kdprintf("%s:%d: failed.\n", __FUNCTION__, __LINE__); \
        goto error; \
    }

/* constants */
#define BLS_MAGIC 0x32424C53
#define PUP_MAGIC 0x1D3D154F

/* debug */
void trace_pup(pup_t *pup)
{
    uint32_t i;
    bls_entry_t *entry;

    dprintf("pup:\n");
    dprintf("  file-path:      %s\n", pup->file_path);
    dprintf("  file-size:      0x%llX bytes\n", pup->file_size);
    dprintf("  header:\n");
    dprintf("    magic:        0x%08X\n", pup->header.magic);
    dprintf("    version:      0x%08X\n", pup->header.version);
    dprintf("    flags:        0x%08X\n", pup->header.flags);
    dprintf("    entry_count:  0x%08X\n", pup->header.entry_count);
    dprintf("    block_count:  0x%08X\n", pup->header.block_count);

    dprintf("  entries:\n");
    for (i = 0; i < pup->header.entry_count; i++) {
        entry = &pup->entries[i];
        dprintf("    [%u]\n", i);
        dprintf("      block_offset:     0x%08X\n", entry->block_offset);
        dprintf("      file_size:        0x%08X\n", entry->file_size);
        dprintf("      file_name:        %s\n", entry->file_name);
    }
}

pup_t* pup_open(const char* file)
{
    pup_t* pup;
    ssize_t size;
    off_t off;
    int fd;

    /* allocate object */
    pup = malloc(sizeof(pup_t));
    assert(pup);
    memset(pup, 0, sizeof(pup_t));

    /* open file */
    fd = open(file, O_RDONLY, 0);
    assert(fd >= 0);
    pup->fd = fd;

    /* get pup size */
    off = lseek(fd, 0, SEEK_END);
    assert(off >= 0);
    pup->file_size = off;
    off = lseek(fd, 0, SEEK_SET);
    assert(off >= 0);

    /* get bls header */
    size = read(fd, &pup->header, sizeof(bls_header_t));
    assert(size == sizeof(bls_header_t));
    assert(pup->header.magic == BLS_MAGIC);
    assert(pup->header.entry_count > 0);

    /* get bls entries */
    pup->entries_size = pup->header.entry_count * sizeof(bls_entry_t);
    pup->entries = malloc(pup->entries_size);
    assert(pup->entries);
    memset(pup->entries, 0, pup->entries_size);
    size = read(fd, pup->entries, pup->entries_size);
    assert(size == pup->entries_size);

    /* return pup object */
    pup->fd = fd;
    pup->file_path = strdup(file);
    if (DEBUG_PUP) {
        trace_pup(pup);
    }
    return pup;

error:
    pup_close(pup);
    return NULL;
}

int pup_verify_header(pup_t *pup)
{
    return 0;
}

int pup_decrypt_segments(pup_t *pup)
{
    return 0;
}

void pup_close(pup_t *pup)
{
    struct blob_t *blob;
    struct blob_t *next;
    if (!pup) {
        return;
    }

    /* remove blobs */
    blob = pup->blobs;
    while (blob) {
        next = blob->next;
        free(blob->data);
        free(blob);
        blob = next;
    }
    /* close file */
    if (pup->fd) {
        close(pup->fd);
    }
    free(pup->file_path);
    free(pup->entries);
    free(pup);
}
