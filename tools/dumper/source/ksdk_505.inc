/* functions */
KFUNC(0x000F5E10, _sx_xlock, int, (void *sx, int opts, const char *file, int line));
KFUNC(0x000F5FD0, _sx_xunlock, void, (void *sx, const char *file, int line));
KFUNC(0x0010E250, kmalloc, void *, (uint64_t size, void *area, uint64_t flags));
KFUNC(0x0010E460, kfree, void, (void *ptr, void *area));
KFUNC(0x00152FC0, sys_write, void, (void *td, void *uap));
KFUNC(0x0061BD90, sceSblDriverMapPages, int, (uint64_t *gpu_paddr, void *cpu_vaddr, uint32_t npages, uint64_t flags, uint64_t unk, uint64_t *gpu_desc));
KFUNC(0x0061C460, sceSblDriverUnmapPages, int, (uint64_t gpu_desc));
KFUNC(0x006303B0, map_chunk_table, int, (uint64_t *gpu_paddr, uint64_t *gpu_desc, void *cpu_vaddr));
KFUNC(0x00630400, make_chunk_table, int, (uint64_t *segment_info_gpu_paddr, uint64_t *segment_info_gpu_desc, void *segment_info_cpu_vaddr, size_t segment_info_size, void *chunk_table_cpu_vaddr, size_t chunk_table_size, int type));
KFUNC(0x00632540, sceSblServiceMailbox, int, (uint64_t module_id, void *query, void *reply));
KFUNC(0x006323F0, sceSblServiceSpawn, int, (char *module_name, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4, uint64_t *module_id));
KFUNC(0x00642840, _sceSblAuthMgrSmFinalize, int, (void *ctx));

/* globals */
KDATA(0x010986A0, prison0, void*);
KDATA(0x01A727E0, M_AUTHMGR, void);
KDATA(0x022C1A70, rootvnode, void*);
KDATA(0x02768310, sceSblAuthMgrModuleId, uint64_t);
KDATA(0x027680D0, authmgr_sm_xlock, void);
KDATA(0x02768140, self_ctx_status, uint32_t);
KDATA(0x02768150, self_contexts, self_context_t);
