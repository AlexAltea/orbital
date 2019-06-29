/* functions */
KFUNC(0x0038FA30, _sx_xlock, int, (void *sx, int opts, const char *file, int line));
KFUNC(0x0038FBC0, _sx_xunlock, void, (void *sx, const char *file, int line));
KFUNC(0x003F7750, kmalloc, void *, (uint64_t size, void *area, uint64_t flags));
KFUNC(0x003F7930, kfree, void, (void *ptr, void *area));
KFUNC(0x0005F1A0, sys_write, void, (void *td, void *uap));
KFUNC(0x005FFD90, sceSblDriverMapPages, int, (uint64_t *gpu_paddr, void *cpu_vaddr, uint32_t npages, uint64_t flags, uint64_t unk, uint64_t *gpu_desc));
KFUNC(0x00600450, sceSblDriverUnmapPages, int, (uint64_t gpu_desc));
KFUNC(0x00612940, map_chunk_table, int, (uint64_t *gpu_paddr, uint64_t *gpu_desc, void *cpu_vaddr));
KFUNC(0x006146C0, sceSblServiceMailbox, int, (uint64_t module_id, void *query, void *reply));
KFUNC(0x0061FB50, _sceSblAuthMgrSmFinalize, int, (void *ctx));

/* globals */
KDATA(0x010399B0, prison0, void*);
KDATA(0x01A3A330, M_AUTHMGR, void);
KDATA(0x021AFA30, rootvnode, void*);
KDATA(0x025642F0, sceSblAuthMgrModuleId, uint64_t);
KDATA(0x025640A8, authmgr_sm_xlock, void);
KDATA(0x02564110, self_ctx_status, uint32_t);
KDATA(0x02564120, self_contexts, self_context_t);

// TODO: Apply the patches below
#if 0
////// main.c //////
void kpatch_enablemapself(struct thread *td)
{
    uint8_t *kmem;
    cpu_disable_wp();

    /* update offsets (4.55) */
    uint8_t* kernel_base = &((uint8_t*)read_msr(0xC0000082))[-0x3095D0];
    uint8_t* map_self_patch1 = &kernel_base[0x143BF2];
    uint8_t* map_self_patch2 = &kernel_base[0x143E0E];

    
    kmem = (uint8_t*)map_self_patch1;
    kmem[0] = 0x90;
    kmem[1] = 0xE9;
    
    kmem = (uint8_t*)map_self_patch2;
    kmem[0] = 0x90;
    kmem[1] = 0x90;

    cpu_enable_wp();
}
#endif
