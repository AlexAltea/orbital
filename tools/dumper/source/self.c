/**
 * (c) 2017-2018 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Based in previous tools and research by: flatz.
 */

#include "self.h"

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
#define SELF_CONTENT_ID_SIZE 0x13
#define SELF_KEY_SIZE 0x10

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

/* format */
typedef struct self_control_block_t {
    uint16_t type;
    union {
        struct {
            uint16_t type;
            uint16_t pad1;
            uint32_t pad2;
            uint32_t pad3;
            uint32_t pad4;
            char content_id[SELF_CONTENT_ID_SIZE];
        } npdrm;
    };
} self_control_block_t;

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

typedef struct self_kmethod_args_t {
    void *kmethod;
    self_t *self;
    uint64_t args[3];
} self_kmethod_args_t;

int self_kacquire_context(
    struct thread *td, struct self_kmethod_args_t *uap)
{
    return 0;
}

int self_krelease_context(
    struct thread *td, struct self_kmethod_args_t *uap)
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
    struct thread *td, struct self_kmethod_args_t *uap)
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
    struct thread *td, struct self_kmethod_args_t *uap)
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
    ret = 1;

    /* arguments */
    unsigned int is_block_table = 1;
    unsigned int segment_idx;
    uint8_t *segment_data_user;
    size_t segment_data_user_size;
    self_t *self;

    self = uap->self;
    segment_idx = (int)uap->args[0];
    segment_data_user = (uint8_t*)uap->args[1];
    segment_data_user_size = (size_t)uap->args[2];

    /* copy segment data */
    segment_data_size = ALIGN_PAGE(segment_data_user_size);
    segment_data = kmalloc(segment_data_size, M_AUTHMGR, 0x102);
    kassert(segment_data);
    memset(segment_data, 0, segment_data_size);
    memcpy(segment_data, segment_data_user, segment_data_user_size);

    /* create chunk table */
    chunk_table = kmalloc(0x4000, M_AUTHMGR, 0x102);
    kassert(chunk_table);
    make_chunk_table_system(
        &segment_data_gpu_paddr,
        &segment_data_gpu_desc,
        segment_data,
        segment_data_size,
        chunk_table,
        0x4000);
    kassert(segment_data_gpu_paddr);
    kassert(segment_data_gpu_desc);
    map_chunk_table(
        &chunk_table_gpu_paddr,
        &chunk_table_gpu_desc,
        chunk_table);
    kassert(chunk_table_gpu_paddr);
    kassert(chunk_table_gpu_desc);

    /* decrypt segment  */
    sbl_authmgr_load_self_segment_t *args = (void*)&payload[0];
    memset(payload, 0, sizeof(payload));
    args->function = AUTHMGR_CMD_LOAD_SELF_SEGMENT;
    args->status = 0;
    args->chunk_table_addr = chunk_table_gpu_paddr;
    args->segment_index = segment_idx;
    args->is_block_table = is_block_table;
    args->context_id = self->auth_ctx_id;

    kdprintf("Sending AUTHMGR_CMD_LOAD_SELF_SEGMENT...\n");
    sceSblServiceMailbox_locked(ret, self->svc_id, &payload, &payload);
    kassert(!ret);
    kassert(!args->status);
    kassert(args->function == AUTHMGR_CMD_LOAD_SELF_SEGMENT);
    memcpy(segment_data_user, segment_data, segment_data_user_size);
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

/* functions */
static void self_allocate_blobs(self_t* self)
{
    dprintf("self_allocate_blobs: unimplemented");
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
    struct self_entry_t* segment;
    struct blob_t *blob;
    unsigned int this_segment_idx;
    unsigned int that_segment_idx;
    unsigned int num_blocks;
    unsigned int i, j;
    int success = 0;

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

        dprintf("Processing block table @ segment #%u...\n", i);
        that_segment_idx = EXTRACT(segment->props, SELF_PROPS_SEGMENT_INDEX);
        this_segment_idx = EXTRACT(self->entries[that_segment_idx].props, SELF_PROPS_SEGMENT_INDEX);
        dprintf("  that-segment-idx: %u\n", that_segment_idx);
        dprintf("  this-segment-idx: %u\n", this_segment_idx);

        blob->size = segment->filesz;
        blob->data = malloc(blob->size);
        assert(blob->data);
        assert(segment->offset + segment->filesz <= self->file_size);
        memcpy(blob->data, &self->data[segment->offset], blob->size);
        blob_hash(blob, blob->data, blob->size);
        syscall(11, self_kdecrypt_segment, self,
            this_segment_idx, blob->data, blob->size);
        blob = blob_add(blob);
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
