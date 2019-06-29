/**
 * (c) 2017-2018 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Based in previous tools and research by: fail0verflow, flatz.
 */

#include "self_decrypter.h"

#include "ksdk.h"
#include "blob.h"
#include "debug.h"

/* debugging */
#define DEBUG_SELF 0

#define assert(cond) if (!(cond)) { \
        dprintf("%s:%d: failed.\n", __FUNCTION__, __LINE__); \
        goto error; \
    }
#define kassert(cond) if (!(cond)) { \
        kdprintf("%s:%d: failed.\n", __FUNCTION__, __LINE__); \
        goto error; \
    }

/* constants */
#define SELF_MAGIC 0x1D3D154F
#define SELF_VERSION 0x0
#define SELF_MODE 0x1
#define SELF_ENDIANNESS 0x1

#define SELF_AUTH_INFO_SIZE 0x88
#define SELF_KEY_SIZE 0x10
#define SELF_DIGEST_SIZE 0x20
#define SELF_SEGMENT_BLOCK_ALIGNMENT 0x10

/* fields */
#define SELF_PROPS_ORDERED(B)        B( 0,  0)
#define SELF_PROPS_ENCRYPTED(B)      B( 1,  1)
#define SELF_PROPS_SIGNED(B)         B( 2,  2)
#define SELF_PROPS_COMPRESSED(B)     B( 3,  3)
#define SELF_PROPS_WINDOW(B)         B(10,  8)
#define SELF_PROPS_BLOCKED(B)        B(11, 11)
#define SELF_PROPS_BLOCK_SIZE(B)     B(15, 12)
#define SELF_PROPS_HAS_DIGESTS(B)    B(16, 16)
#define SELF_PROPS_HAS_EXTENTS(B)    B(17, 17)
#define SELF_PROPS_SEGMENT_INDEX(B)  B(31, 20)

typedef struct self_block_extent_t {
    uint32_t offset;
    uint32_t size;
} self_block_extent_t;

typedef struct self_block_info_t {
    uint32_t size;
    uint16_t index;
    struct self_block_extent_t extent;
    uint8_t digest[SELF_DIGEST_SIZE];
} self_block_info_t;

/* debug */
void trace_self(self_t *self)
{
#define BOOL(x) ((x) ? "true" : "false")
    int i;
    self_entry_t *entry;

    dprintf("self:\n");
    dprintf("  file-path:      %s\n", self->file_path);
    dprintf("  file-size:      0x%llX bytes\n", self->file_size);
    dprintf("  header:\n");
    dprintf("    magic:        0x%08X\n", self->header.magic);
    dprintf("    version:      0x%02X\n", self->header.version);
    dprintf("    mode:         0x%02X\n", self->header.mode);
    dprintf("    endian:       %s (0x%02X)\n",
        self->header.endian == 1 ? "little-endian" : (
        self->header.endian == 2 ? "big-endian" : "???"),
        self->header.endian);
    dprintf("    attr:         0x%02X\n", self->header.attr);
    dprintf("    header-size:  0x%llX bytes\n", self->header.header_size);
    dprintf("    meta-size:    0x%llX bytes\n", self->header.meta_size);
    dprintf("    file-size:    0x%llX bytes\n", self->header.file_size);
    dprintf("    num-entries:  0x%X\n", self->header.num_entries);

    dprintf("  entries:\n");
    for (i = 0; i < self->header.num_entries; i++) {
        entry = &self->entries[i];
        dprintf("    [%d]\n", i);
        dprintf("      props:        0x%08X\n", entry->props);
        dprintf("        ordered:        %s\n", BOOL(EXTRACT(entry->props, SELF_PROPS_ORDERED)));
        dprintf("        encrypted:      %s\n", BOOL(EXTRACT(entry->props, SELF_PROPS_ENCRYPTED)));
        dprintf("        signed:         %s\n", BOOL(EXTRACT(entry->props, SELF_PROPS_SIGNED)));
        dprintf("        compressed:     %s\n", BOOL(EXTRACT(entry->props, SELF_PROPS_COMPRESSED)));
        if (EXTRACT(entry->props, SELF_PROPS_COMPRESSED))
            dprintf("        window:         0x%llX\n",
                (1 << EXTRACT(entry->props, SELF_PROPS_WINDOW)) - 1);
        dprintf("        has-blocks:     %s\n", BOOL(EXTRACT(entry->props, SELF_PROPS_BLOCKED)));
        if (EXTRACT(entry->props, SELF_PROPS_BLOCKED))
            dprintf("        block-size:     0x%llX\n",
                (1 << (EXTRACT(entry->props, SELF_PROPS_BLOCK_SIZE) + 12)));
        dprintf("        has-digests:    %s\n", BOOL(EXTRACT(entry->props, SELF_PROPS_HAS_DIGESTS)));
        dprintf("        has-extents:    %s\n", BOOL(EXTRACT(entry->props, SELF_PROPS_HAS_EXTENTS)));
        dprintf("        segment-index:  %d\n", EXTRACT(entry->props, SELF_PROPS_SEGMENT_INDEX));
        dprintf("      offset:  0x%llX\n", entry->offset);
        dprintf("      filesz:  0x%llX bytes\n", entry->filesz);
        dprintf("      memsz:   0x%llX bytes\n", entry->memsz);
    }
#undef BOOL
}

/* kernel */
#define SELF_MAX_CONTEXTS 4

typedef struct self_kdecrypt_segment_args_t {
    unsigned int segment_idx;
    unsigned int is_block_table;
    uint8_t *segment_data_user;
    size_t segment_data_user_size;
} self_kdecrypt_segment_args_t;

typedef struct self_kdecrypt_block_args_t {
    struct self_block_info_t *block;
    unsigned int segment_idx;
    uint8_t *blob_data;
    size_t blob_size;
} self_kdecrypt_block_args_t;

typedef struct self_kmethod_uap_t {
    void *kmethod;
    self_t *self;
    void *args;
} self_kmethod_uap_t;

int self_kacquire_context(
    struct thread *td, struct self_kmethod_uap_t *uap)
{
    return 0;
}

int self_krelease_context(
    struct thread *td, struct self_kmethod_uap_t *uap)
{
    int ctx_id;
    self_t *self = uap->self;

    ctx_id = self->ctx_id;
    if (0 <= ctx_id && ctx_id <= 3) {
        self_ctx_status[ctx_id] = 3;
        self->ctx_id = -1;
    }
    return 0;
}

int self_kverify_header(
    struct thread *td, struct self_kmethod_uap_t *uap)
{
    int ret, ctx_id;
    char payload[0x80];
    void* header_data = NULL;
    uint64_t header_data_size;
    uint64_t header_data_mapped = NULL;
    uint64_t header_data_mapdesc = NULL;
    void* auth_info = NULL;
    uint64_t auth_info_size;
    uint64_t auth_info_mapped = NULL;
    uint64_t auth_info_mapdesc = NULL;
    self_t *self = uap->self;

    /* acquire context */
    kdprintf("Waiting for free context...\n");
    if (self->ctx_id == -1) {
        ctx_id = 0;
        while (self_ctx_status[ctx_id] != 3) {
            ctx_id = (ctx_id + 1) % SELF_MAX_CONTEXTS;
        }
        kdprintf("Available context ID: %d\n", ctx_id);
        self_ctx_status[ctx_id] = 1;
        self->ctx_id = ctx_id;
    }
    if (self->svc_id == -1) {
        self->svc_id = *sceSblAuthMgrModuleId;
    }
    kassert(self->ctx_id >= 0);
    kassert(self->ctx_id <= 3);
    self->ctx = &self_contexts[self->ctx_id];
    _sceSblAuthMgrSmFinalize(self->ctx);

    /* allocate memory for command */
    header_data_size = ALIGN_PAGE(self->header.header_size + self->header.meta_size);
    header_data = kmalloc(header_data_size, M_AUTHMGR, 0x102);
    kassert(header_data);
    memset(header_data, 0, header_data_size);
    memcpy(header_data, self->data, MIN(self->file_size, header_data_size));
    kassert(!sceSblDriverMapPages(&header_data_mapped, header_data, 1, 0x61, NULL, &header_data_mapdesc));

    auth_info_size = ALIGN_PAGE(SELF_AUTH_INFO_SIZE);
    auth_info = kmalloc(auth_info_size, M_AUTHMGR, 0x102);
    kassert(auth_info);
    memset(auth_info, 0, auth_info_size);
    kassert(!sceSblDriverMapPages(&auth_info_mapped, auth_info, 1, 0x61, NULL, &auth_info_mapdesc));

    /* send command */
    sbl_authmgr_verify_header_t *args = (void*)&payload[0];
    memset(payload, 0, sizeof(payload));
    args->function = AUTHMGR_CMD_VERIFY_HEADER;
    args->status = 0;
    args->header_addr = header_data_mapped;
    args->header_size = self->header.header_size + self->header.meta_size;
    args->context_id = self->ctx_id;
    args->auth_info_addr = auth_info_mapped;
    args->key_id = 0;
    memset(&args->key, 0, SELF_KEY_SIZE);

    kdprintf("Sending AUTHMGR_CMD_VERIFY_HEADER...\n");
    sceSblServiceMailbox_locked(ret, self->svc_id, &payload, &payload);
    kassert(!ret);
    kassert(!args->status);
    kassert(args->function == AUTHMGR_CMD_VERIFY_HEADER);

    kdprintf("Confirmed context ID: %d\n", self->ctx_id);
    self->auth_ctx_id = args->context_id;
    memcpy(&self->auth_info, auth_info, sizeof(self->auth_info));
    self->verified = 1;

    if (auth_info_mapped)
        kassert(!sceSblDriverUnmapPages(auth_info_mapdesc));
    if (header_data_mapped)
        kassert(!sceSblDriverUnmapPages(header_data_mapdesc));
    return 0;

error:
    self_krelease_context(td, uap);
    if (auth_info_mapped)
        kassert(!sceSblDriverUnmapPages(auth_info_mapdesc));
    if (header_data_mapped)
        kassert(!sceSblDriverUnmapPages(header_data_mapdesc));
    return 1;
}

int self_kdecrypt_segment(
    struct thread *td, struct self_kmethod_uap_t *uap)
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
    self_kdecrypt_segment_args_t *args = uap->args;
    self_t *self = uap->self;
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
    make_chunk_table(
        &segment_data_gpu_paddr,
        &segment_data_gpu_desc,
        segment_data,
        segment_data_size,
        chunk_table,
        0x4000, 1);
    kassert(segment_data_gpu_paddr);
    kassert(segment_data_gpu_desc);
    map_chunk_table(
        &chunk_table_gpu_paddr,
        &chunk_table_gpu_desc,
        chunk_table);
    kassert(chunk_table_gpu_paddr);
    kassert(chunk_table_gpu_desc);

    /* decrypt segment  */
    sbl_authmgr_load_self_segment_t *cmd = (void*)&payload[0];
    memset(payload, 0, sizeof(payload));
    cmd->function = AUTHMGR_CMD_LOAD_SELF_SEGMENT;
    cmd->status = 0;
    cmd->chunk_table_addr = chunk_table_gpu_paddr;
    cmd->segment_index = args->segment_idx;
    cmd->is_block_table = args->is_block_table;
    cmd->context_id = self->auth_ctx_id;

    kdprintf("Sending AUTHMGR_CMD_LOAD_SELF_SEGMENT...\n");
    sceSblServiceMailbox_locked(ret, self->svc_id, &payload, &payload);
    kassert(!ret);
    kassert(!cmd->status);
    kassert(cmd->function == AUTHMGR_CMD_LOAD_SELF_SEGMENT);
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

int self_kdecrypt_block(
    struct thread *td, struct self_kmethod_uap_t *uap)
{
    int ret;
    char payload[0x80];
    void* input_data = NULL;
    uint64_t input_size;
    uint64_t input_mapped = NULL;
    uint64_t input_mapdesc = NULL;
    void* output_data = NULL;
    uint64_t output_size;
    uint64_t output_mapped = NULL;
    uint64_t output_mapdesc = NULL;
    self_kdecrypt_block_args_t *args = uap->args;
    self_block_info_t *block = args->block;
    self_t *self = uap->self;
    ret = 1;

    /* allocate memory for command */
    input_size = ALIGN_PAGE(args->blob_size);
    input_data = kmalloc(input_size, M_AUTHMGR, 0x102);
    kassert(input_data);
    memset(input_data, 0, input_size);
    memcpy(input_data, args->blob_data, args->blob_size);
    kassert(!sceSblDriverMapPages(&input_mapped, input_data, 1, 0x61, NULL, &input_mapdesc));

    output_size = ALIGN_PAGE(args->blob_size);
    output_data = kmalloc(output_size, M_AUTHMGR, 0x102);
    kassert(output_data);
    memset(output_data, 0, output_size);
    kassert(!sceSblDriverMapPages(&output_mapped, output_data, 1, 0x61, NULL, &output_mapdesc));

    /* decrypt block  */
    sbl_authmgr_load_self_block_t *cmd = (void*)&payload[0];
    memset(payload, 0, sizeof(payload));
    memcpy(&cmd->digest, &block->digest, sizeof(block->digest));
    memcpy(&cmd->extent, &block->extent, sizeof(block->extent));
    cmd->function = AUTHMGR_CMD_LOAD_SELF_BLOCK;
    cmd->status = 0;
    cmd->pages_addr = output_mapped;
    cmd->segment_index = args->segment_idx;
    cmd->context_id = self->auth_ctx_id;
    cmd->block_index = block->index;
    cmd->data_offset = 0;
    cmd->data_size = args->blob_size;
    cmd->data_start_addr = input_mapped;
    cmd->data_end_addr = 0;

    kdprintf("Sending AUTHMGR_CMD_LOAD_SELF_BLOCK...\n");
    sceSblServiceMailbox_locked(ret, self->svc_id, &payload, &payload);
    kassert(!ret);
    kassert(!cmd->status);
    kassert(cmd->function == AUTHMGR_CMD_LOAD_SELF_BLOCK);
    memcpy(args->blob_data, output_data, args->blob_size);
    ret = 0;

error:
    if (input_mapped)
        kassert(!sceSblDriverUnmapPages(input_mapdesc));
    if (output_mapped)
        kassert(!sceSblDriverUnmapPages(output_mapdesc));
    if (input_data)
        kfree(input_data, M_AUTHMGR);
    if (output_data)
        kfree(output_data, M_AUTHMGR);
    return ret;
}

/* functions */
static void self_get_block_info(self_t *self, unsigned int target_entry_idx, self_block_info_t *info)
{
    struct self_entry_t* table_segment;
    struct self_entry_t* target_segment;
    struct self_block_extent_t* extents;
    const uint8_t* segment_data;
    unsigned int target_num_blocks;
    unsigned int i;

    memset(&info->digest, 0, sizeof(info->digest));
    memset(&info->extent, 0, sizeof(info->extent));

    for (i = 0; i < self->header.num_entries; ++i) {
        table_segment = &self->entries[i];
        if (!EXTRACT(table_segment->props, SELF_PROPS_HAS_DIGESTS) &&
            !EXTRACT(table_segment->props, SELF_PROPS_HAS_EXTENTS))
            continue;
        if (EXTRACT(table_segment->props, SELF_PROPS_SEGMENT_INDEX) != target_entry_idx)
            continue;

        target_segment = &self->entries[target_entry_idx];
        target_num_blocks = (target_segment->memsz + (info->size - 1)) / info->size;
        segment_data = &self->data[table_segment->offset];
        if (EXTRACT(table_segment->props, SELF_PROPS_HAS_DIGESTS)) {
            memcpy(&info->digest, &segment_data[info->index * sizeof(info->digest)], sizeof(info->digest));
        }
        if (EXTRACT(table_segment->props, SELF_PROPS_HAS_EXTENTS)) {
            if (EXTRACT(table_segment->props, SELF_PROPS_HAS_DIGESTS))
                extents = (void*)(&segment_data[target_num_blocks * sizeof(info->digest)]);
            else
                extents = (void*)(&segment_data[0]);
            memcpy(&info->extent, &extents[info->index], sizeof(info->extent));
        }
        return;
    }
}

self_t* self_open(const char* file)
{
    self_t* self;
    ssize_t size;
    off_t off;
    int fd;

    /* allocate object */
    self = malloc(sizeof(self_t));
    assert(self);
    memset(self, 0, sizeof(self_t));

    /* open file */
    fd = open(file, O_RDONLY, 0);
    assert(fd >= 0);
    self->fd = fd;

    /* get self size */
    off = lseek(fd, 0, SEEK_END);
    assert(off >= 0);
    self->file_size = off;
    off = lseek(fd, 0, SEEK_SET);
    assert(off >= 0);

    /* get self header */
    size = read(fd, &self->header, sizeof(self_header_t));
    assert(size == sizeof(self_header_t));
    assert(self->header.magic == SELF_MAGIC);
    assert(self->header.version == SELF_VERSION);
    assert(self->header.mode == SELF_MODE);
    assert(self->header.endian == SELF_ENDIANNESS);
    assert(self->header.file_size == self->file_size);

    /* get self entries */
    self->entries_size = self->header.num_entries * sizeof(self_entry_t);
    self->entries = malloc(self->entries_size);
    assert(self->entries);
    assert(self->header.header_size >= sizeof(self_header_t) + self->entries_size);
    assert(self->header.header_size + self->header.meta_size <= 0x4000);
    memset(self->entries, 0, self->entries_size);
    size = read(fd, self->entries, self->entries_size);
    assert(size == self->entries_size);

    /* copy file contents */
    self->data = malloc(self->file_size);
    off = lseek(fd, 0, SEEK_SET);
    assert(off >= 0);
    size = read(fd, self->data, self->file_size);
    assert(size == self->file_size);

    self->fd = fd;
    self->file_path = strdup(file);
    self->ctx_id = -1;
    if (DEBUG_SELF) {
        trace_self(self);
    }
    return self;

error:
    self_close(self);
    return NULL;
}

int self_verify_header(self_t *self)
{
    syscall(11, self_kverify_header, self);
    return 0;
}

int self_load_segments(self_t *self)
{
    struct self_kdecrypt_segment_args_t args_ds;
    struct self_kdecrypt_block_args_t args_db;
    struct self_block_info_t block;
    struct self_entry_t* segment;
    struct blob_t *blob;
    unsigned int this_segment_idx;
    unsigned int that_segment_idx;
    unsigned int num_blocks;
    unsigned int block_idx_offset;
    unsigned int block_offset;
    unsigned int block_size;
    unsigned int i, j;

    if (!self->verified)
        goto error;

    /* prepare linked list of blobs */
    blob = malloc(sizeof(blob_t));
    memset(blob, 0, sizeof(blob_t));
    self->blobs = blob;

    /* load block table segments */
    for (i = 0; i < self->header.num_entries; i++) {
        segment = &self->entries[i];
        if (!EXTRACT(segment->props, SELF_PROPS_HAS_DIGESTS) &&
            !EXTRACT(segment->props, SELF_PROPS_HAS_EXTENTS))
            continue;

        dprintf("Processing block table segment @ entry #%u...\n", i);
        that_segment_idx = EXTRACT(segment->props, SELF_PROPS_SEGMENT_INDEX);
        this_segment_idx = EXTRACT(self->entries[that_segment_idx].props, SELF_PROPS_SEGMENT_INDEX);
        dprintf("  that-segment-idx: %u\n", that_segment_idx);
        dprintf("  this-segment-idx: %u\n", this_segment_idx);

        blob->size = segment->filesz;
        blob->data = malloc(blob->size);
        assert(blob->data);
        assert(segment->offset + segment->filesz <= self->file_size);
        memcpy(blob->data, &self->data[segment->offset], blob->size);
        blob_set_path_hash(blob, blob->data, blob->size);

        args_ds.segment_idx = this_segment_idx;
        args_ds.is_block_table = 1;
        args_ds.segment_data_user = blob->data;
        args_ds.segment_data_user_size = blob->size;
        syscall(11, self_kdecrypt_segment, self, &args_ds);
        memcpy(&self->data[segment->offset], blob->data, blob->size);
        blob = blob_add(blob);
    }

    /* load blocked segments */
    for (i = 0; i < self->header.num_entries; i++) {
        segment = &self->entries[i];
        if (!EXTRACT(segment->props, SELF_PROPS_BLOCKED))
            continue;

        dprintf("Processing blocked segment @ entry #%u...\n", i);
        memset(&block, 0, sizeof(block));
        block.size = (1 << (EXTRACT(segment->props, SELF_PROPS_BLOCK_SIZE) + 12));
        this_segment_idx = EXTRACT(segment->props, SELF_PROPS_SEGMENT_INDEX);
        num_blocks = (segment->memsz + block.size - 1) / block.size;

        for (j = 0; j < num_blocks; j++) {
            block.index = j;
            self_get_block_info(self, i, &block);
            block_idx_offset = block.extent.offset & ~(block.size - 1);
            block_offset = block.extent.offset & (block.size - 1);
            block_size = block.extent.size & ~(SELF_SEGMENT_BLOCK_ALIGNMENT - 1);
            if (block_size == 0) {
                block_idx_offset = block.index * block.size;
                block_size = (block_idx_offset + block.size <= segment->memsz) ?
                    (block.size) :
                    (segment->memsz - block_idx_offset);
            } else if (block.index * block.size + block.extent.size == segment->memsz) {
                block_size = block.extent.size;
            }

            blob->size = block_size;
            blob->data = malloc(blob->size);
            assert(blob->data);
            memcpy(blob->data, &self->data[segment->offset + block_idx_offset + block_offset], blob->size);
            blob_set_path_hash(blob, blob->data, blob->size);

            args_db.block = &block;
            args_db.segment_idx = this_segment_idx;
            args_db.blob_data = blob->data;
            args_db.blob_size = blob->size;
            syscall(11, self_kdecrypt_block, self, &args_db);
            blob = blob_add(blob);
        }
    }
    return 0;

error:
    return 1;
}

void self_close(self_t *self)
{
    struct blob_t *blob;
    struct blob_t *next;
    if (!self) {
        return;
    }

    /* remove blobs */
    blob = self->blobs;
    while (blob) {
        next = blob->next;
        free(blob->data);
        free(blob);
        blob = next;
    }
    /* close file */
    if (self->fd) {
        close(self->fd);
    }
    syscall(11, self_krelease_context, self);
    free(self->file_path);
    free(self->entries);
    free(self);
}
