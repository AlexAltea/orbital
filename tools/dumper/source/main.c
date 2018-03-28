/**
 * (c) 2017-2018 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Based/inspired by previous tools and research by:
 * flatz, m0rph3us1987, wildcard.
 */

#include "ps4.h"

#include "blob.h"
#include "debug.h"
#include "ksdk.h"
#include "self.h"

/* kernel payloads */
int kpatch_getroot(struct thread *td)
{
    /* Resolve credentials */
    struct ucred *cred;
    struct filedesc *fd;

    fd = td->td_proc->p_fd;
    cred = td->td_proc->p_ucred;

    /* Escalate process to uid0 */
    cred->cr_uid = 0;
    cred->cr_ruid = 0;
    cred->cr_rgid = 0;
    cred->cr_groups[0] = 0;

    /* Break out of FreeBSD jail */
    cred->cr_prison = prison0[0];

    /* Escalate ucred privs */
    void *td_ucred = *(void **)(((char *)td) + 304);
    // sceSblACMgrIsSystemUcred
    uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
    *sonyCred = 0xffffffffffffffff;
    // sceSblACMgrGetDeviceAccessType
    uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
    *sceProcType = 0x3801000000000013;
    // sceSblACMgrHasSceProcessCapability
    uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
    *sceProcCap = 0xffffffffffffffff;

    /* Set vnode to real root "/" to defeat sandbox */
    fd->fd_rdir = rootvnode[0];
    fd->fd_jdir = rootvnode[0];

    /* Return back to usermode */
    return 0;
}

void kpatch_enablemapself(struct thread *td)
{
    uint8_t *kmem;
    cpu_disable_wp();

    /* update offsets (5.00) */
    uint8_t* kernel_base = &((uint8_t*)read_msr(0xC0000082))[-0x1C0];
    uint8_t* map_self_patch1 = &kernel_base[0x117B0];
    uint8_t* map_self_patch2 = &kernel_base[0x117C0];
    uint8_t* map_self_patch3 = &kernel_base[0x13EF2F];

    // sceSblACMgrIsAllowedToMmapSelf result
    kmem = (uint8_t*)map_self_patch1;
    kmem[0] = 0xB8;
    kmem[1] = 0x01;
    kmem[2] = 0x00;
    kmem[3] = 0x00;
    kmem[4] = 0x00;
    kmem[5] = 0xC3;

    // sceSblACMgrHasMmapSelfCapability result
    kmem = (uint8_t*)map_self_patch2;
    kmem[0] = 0xB8;
    kmem[1] = 0x01;
    kmem[2] = 0x00;
    kmem[3] = 0x00;
    kmem[4] = 0x00;
    kmem[5] = 0xC3;

    // sceSblAuthMgrIsLoadable bypass
    kmem = (uint8_t*)map_self_patch3;
    kmem[0] = 0x31;
    kmem[1] = 0xC0;
    kmem[2] = 0x90;
    kmem[3] = 0x90;
    kmem[4] = 0x90;

    cpu_enable_wp();
}

static int decrypt_self_file(const char *file)
{
    int err;
    self_t *self;

    self = self_open(file);
    if (!self) {
        return 1;
    }

    err = self_verify_header(self);
    if (err)
        goto fail;
    err = self_load_segments(self);
    if (err)
        goto fail;
    blob_transfer_all(self->blobs, BLOB_TRANSFER_NET);

fail:
    self_close(self);
    return 0;
}

static int decrypt_selfs_dir(const char *dir, int recursive)
{
    void *dp;
    struct dirent *entry;
    char name[1024];

    dp = opendir(dir);
	if (!dp) {
		dprintf("Invalid directory.\n");
		return 1;
	}

    while ((entry = readdir(dp)) != NULL) {
        if (entry->d_type == DT_DIR && recursive) {
            if (!strcmp(entry->d_name, ".")  ||
                !strcmp(entry->d_name, "..") ||
                !strcmp(entry->d_name, "sandbox")) {
                continue;
            }
            snprintf(name, sizeof(name), "%s/%s", dir, entry->d_name);
            decrypt_selfs_dir(name, recursive);
        }
        if (entry->d_type == DT_REG) {
            snprintf(name, sizeof(name), "%s/%s", dir, entry->d_name);
            const char *dot = strrchr(name, '.');
            if (!dot) continue;
            if (!strcmp(dot, ".self") ||
                !strcmp(dot, ".sprx") ||
                !strcmp(dot, ".elf")  ||
                !strcmp(dot, ".bin")) {
                decrypt_self_file(name);
            }
        }
    }
    closedir(dp);
    return 0;
}

static int decrypt_selfs(void)
{
    decrypt_selfs_dir("/", true);
    return 0;
}

int _main(struct thread *td)
{
    /* Prepare userland environment */
    initKernel();
    initLibc();
    initNetwork();

    debug_init();
    blob_transfer_init();
    dprintf("Starting dump...\n");

    /* Prepare kernel environment*/
    syscall(11, init_ksdk);
    syscall(11, kpatch_getroot);
    syscall(11, kpatch_enablemapself);

    /* Dump data */
    decrypt_self_file("/mini-syscore.elf");

    /* Return back to browser */
    dprintf("Dump finished!\n");
    blob_transfer_close();
    debug_close();
    return 0;
}
