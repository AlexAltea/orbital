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

/* kernel */
typedef struct pup_kdecrypt_segment_args_t {
    unsigned int segment_index;
    uint8_t *segment_data_user;
    size_t segment_data_user_size;
} pup_kdecrypt_segment_args_t;

typedef struct pup_kmethod_uap_t {
    void *kmethod;
    pup_t *pup;
    void *args;
} pup_kmethod_uap_t;

int pup_kpupmgr_open(
    struct thread *td, struct pup_kmethod_uap_t *uap)
{
    int ret;
    pup_t *pup = uap->pup;

    kassert(pup->svc_id == 0);
    ret = sceSblServiceSpawn("80010006", 0, 0, 0, 0, &pup->svc_id);
    kassert(!ret);
    kassert(pup->svc_id != 0);

error:
    return ret;
}

int pup_kpupmgr_close(
    struct thread *td, struct pup_kmethod_uap_t *uap)
{
    int ret;
    char payload[0x80];
    sbl_pupmgr_exit_t *cmd = (void*)&payload[0];
    pup_t *pup = uap->pup;

    kassert(pup->svc_id != 0);
    memset(payload, 0, sizeof(payload));
    cmd->function = 0xFFFF;
    cmd->status = 0;
    sceSblServiceMailbox_locked(ret, pup->svc_id, &payload, &payload);
    kassert(ret == 0);
    sceSblServiceMailbox_locked(ret, pup->svc_id, &payload, &payload);
    kassert(ret == -3);
    pup->svc_id = 0;

error:
    return ret;
}

int pup_kdecrypt_segment(
    struct thread *td, struct pup_kmethod_uap_t *uap)
{
    int ret;
    char payload[0x80];
    size_t segment_data_size;
    uint64_t segment_data_gpu_paddr = NULL;
    uint64_t segment_data_gpu_desc = NULL;
    uint8_t *segment_data = NULL;
    uint64_t chunk_table_gpu_paddr = NULL;
    uint64_t chunk_table_gpu_desc = NULL;
    uint8_t *chunk_table = NULL;
    pup_kdecrypt_segment_args_t *args = uap->args;
    pup_t *pup = uap->pup;
    ret = 1;

    /* copy segment data */
    segment_data_size = ALIGN_PAGE(args->segment_data_user_size);
    segment_data = kmalloc(segment_data_size, M_AUTHMGR, 0x102);
    kassert(segment_data);
    memset(segment_data, 0, segment_data_size);
    memcpy(segment_data, args->segment_data_user, args->segment_data_user_size);

    /* create chunk table */
    chunk_table = kmalloc(0x4000, M_AUTHMGR, 0x102);
    kassert(chunk_table);
    ret = make_chunk_table(
        &segment_data_gpu_paddr,
        &segment_data_gpu_desc,
        segment_data,
        segment_data_size,
        chunk_table,
        0x4000, 0);
    kassert(!ret);
    kassert(segment_data_gpu_paddr);
    kassert(segment_data_gpu_desc);
    ret = map_chunk_table(
        &chunk_table_gpu_paddr,
        &chunk_table_gpu_desc,
        chunk_table);
    kassert(!ret);
    kassert(chunk_table_gpu_paddr);
    kassert(chunk_table_gpu_desc);

    /* decrypt segment  */
    sbl_pupmgr_decrypt_segment_t *cmd = (void*)&payload[0];
    memset(payload, 0, sizeof(payload));
    cmd->function = PUPMGR_CMD_DECRYPT_SEGMENT;
    cmd->status = 0;
    cmd->chunk_table_addr = chunk_table_gpu_paddr;
    cmd->segment_index = args->segment_index;

    kdprintf("Sending PUPMGR_CMD_DECRYPT_SEGMENT...\n");
    sceSblServiceMailbox_locked(ret, pup->svc_id, &payload, &payload);
    kassert(!ret);
    kassert(!cmd->status);
    kassert(cmd->function == PUPMGR_CMD_DECRYPT_SEGMENT);
    memcpy(args->segment_data_user, segment_data, args->segment_data_user_size);
    ret = 0;

error:
    if (chunk_table_gpu_paddr)
        kassert(!sceSblDriverUnmapPages(chunk_table_gpu_desc));
    if (segment_data_gpu_paddr)
        kassert(!sceSblDriverUnmapPages(segment_data_gpu_desc));
    if (chunk_table)
        kfree(chunk_table, M_AUTHMGR);
    if (segment_data)
        kfree(segment_data, M_AUTHMGR);
    return ret;
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

    /* open pupmgr */
    syscall(11, pup_kpupmgr_open, pup);

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

    /* close pupmgr */
    syscall(11, pup_kpupmgr_close, pup);

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
