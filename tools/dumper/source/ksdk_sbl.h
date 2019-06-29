/**
 * (c) 2017-2018 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 */

#ifndef KSDK_SBL_H
#define KSDK_SBL_H

/* pupmgr */
#define PUPMGR_CMD_DECRYPT_HEADER        0x01
#define PUPMGR_CMD_DECRYPT_SEGMENT       0x04
#define PUPMGR_CMD_VERIFY_HEADER         0x0F

typedef struct sbl_pupmgr_decrypt_segment_t {
    uint32_t function;
    uint32_t status;
    uint64_t chunk_table_addr;
    uint16_t segment_index;
    uint16_t unk_0A; // zero
    uint32_t unk_0C; // zero
} sbl_pupmgr_decrypt_segment_t;

typedef struct sbl_pupmgr_exit_t {
    uint32_t function;
    uint32_t status;
} sbl_pupmgr_exit_t;

/* authmgr */
#define AUTHMGR_CMD_VERIFY_HEADER        0x01
#define AUTHMGR_CMD_LOAD_SELF_SEGMENT    0x02
#define AUTHMGR_CMD_LOAD_SELF_BLOCK      0x06

typedef struct sbl_authmgr_chunk_entry_t {
    uint64_t data_addr;
    uint64_t data_size;
} sbl_authmgr_chunk_entry_t;

typedef struct sbl_authmgr_chunk_table_t {
    uint64_t data_addr;
    uint64_t data_size;
    uint64_t num_entries;
    uint64_t reserved;
    sbl_authmgr_chunk_entry_t entries[0];
} sbl_authmgr_chunk_table_t;

typedef struct sbl_authmgr_verify_header_t {
    uint32_t function;
    uint32_t status;
    uint64_t header_addr;
    uint32_t header_size;
    uint32_t zero_0C;
    uint32_t zero_10;
    uint32_t context_id;
    uint64_t auth_info_addr;
    uint32_t unk_20;
    uint32_t key_id;
    uint8_t key[0x10];
} sbl_authmgr_verify_header_t;

typedef struct sbl_authmgr_load_self_segment_t {
    uint32_t function;
    uint32_t status;
    uint64_t chunk_table_addr;
    uint32_t segment_index;
    uint32_t is_block_table;
    uint64_t zero_10;
    uint64_t zero_18;
    uint32_t zero_20;
    uint32_t zero_24;
    uint32_t context_id;
} sbl_authmgr_load_self_segment_t;

typedef struct sbl_authmgr_load_self_block_t {
    uint32_t function;
    uint32_t status;
    uint64_t pages_addr;
    uint32_t segment_index;
    uint32_t context_id;
    uint8_t digest[0x20];
    uint8_t extent[0x8];
    uint32_t block_index;
    uint32_t data_offset;
    uint32_t data_size;
    uint64_t data_start_addr;
    uint64_t data_end_addr;
    uint32_t zero;
} sbl_authmgr_load_self_block_t;

/* self */
typedef struct self_context_t {
    uint32_t format;
    uint32_t elf_auth_type;
    uint32_t total_header_size;
    uint32_t unk_0C;
    void *segment;
    uint32_t unk_18;
    uint32_t ctx_id;
    uint64_t svc_id;
    uint64_t unk_28;
    uint32_t buf_id;
    uint32_t unk_34;
    struct self_header_t *header;
    uint8_t mtx_struct[0x20];
} self_context_t;

#define sceSblServiceMailbox_locked(ret, id, iptr, optr) do { \
        _sx_xlock(authmgr_sm_xlock, 0, NULL, 0); \
        ret = sceSblServiceMailbox((id), (iptr), (optr)); \
        _sx_xunlock(authmgr_sm_xlock, NULL, 0); \
    } while (0)

#endif /* KSDK_SBL_H */
