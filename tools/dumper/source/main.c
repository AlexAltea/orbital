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

#include "gpu_dumper.h"
#include "pup_decrypter.h"
#include "self_decrypter.h"
#include "self_mapper.h"

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
#ifdef VERSION_500
    uint8_t* map_self_patch3 = &kernel_base[0x13EF2F];
#elif VERSION_505
    uint8_t* map_self_patch3 = &kernel_base[0x13F03F];
#else
    #error "Target firmware not yet supported."
#endif

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

static int traverse_dir(const char *dir, int recursive, void(*handler)(const char*))
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
                !strcmp(entry->d_name, "$RECYCLE.BIN") ||
                !strcmp(entry->d_name, "sandbox")) {
                continue;
            }
            snprintf(name, sizeof(name), "%s/%s", dir, entry->d_name);
            traverse_dir(name, recursive, handler);
        }
        if (entry->d_type == DT_REG) {
            snprintf(name, sizeof(name), "%s/%s", dir, entry->d_name);
            handler(name);
        }
    }
    closedir(dp);
    return 0;
}

static void decrypt_self_to_blobs(const char *file)
{
    int err;
    self_t *self;
    const char *dot;

    // Check filename and open file
    dot = strrchr(file, '.');
    if (!dot) return;
    if (strcmp(dot, ".self") &&
        strcmp(dot, ".sprx") &&
        strcmp(dot, ".elf")  &&
        strcmp(dot, ".bin")) {
        return;
    }
    dprintf("Decrypting %s to blobs.\n", file);
    self = self_open(file);
    if (!self) {
        return;
    }

    // Decrypt SELF
    err = self_verify_header(self);
    if (err)
        goto fail;
    err = self_load_segments(self);
    if (err)
        goto fail;
    blob_transfer_all(self->blobs, BLOB_TRANSFER_NET);

fail:
    self_close(self);
    return;
}

static void decrypt_self_to_elf(const char *file)
{
    const char *dot;
    char path[256];
    uint8_t *elf_data;
    size_t elf_size;
    blob_t blob;

    // Check filename and open file
    dot = strrchr(file, '.');
    if (!dot) return;
    if (strcmp(dot, ".self") &&
        strcmp(dot, ".sprx") &&
        strcmp(dot, ".elf")  &&
        strcmp(dot, ".bin")) {
        return;
    }
    dprintf("Decrypting %s to ELF.\n", file);
    elf_data = self_decrypt_file(file, &elf_size);
    if (!elf_data)
        return;

    blob.next = NULL;
    blob.data = elf_data;
    blob.size = elf_size;
    snprintf(path, sizeof(path), "elfs/%s", file);
    blob_set_path(&blob, path);
    blob_transfer(&blob, BLOB_TRANSFER_NET);
    free(elf_data);
}

static void decrypt_pup_to_blobs(const char *file)
{
    int err;
    pup_t *pup;
    const char *dot;

    // Check filename and open file
    dot = strrchr(file, '.');
    if (!dot) return;
    if (strcmp(dot, ".PUP") &&
        strcmp(dot, ".pup")) {
        return;
    }
    dprintf("Decrypting %s to blobs.\n", file);
    pup = pup_open(file);
    if (!pup) {
        return;
    }

    // Decrypt PUP
    err = pup_verify_header(pup);
    if (err)
        goto fail;
    err = pup_decrypt_segments(pup);
    if (err)
        goto fail;
    blob_transfer_all(pup->blobs, BLOB_TRANSFER_NET);

fail:
    pup_close(pup);
    return;
}

static void decrypt_selfs(void)
{
    traverse_dir("/", true, decrypt_self_to_blobs);
    traverse_dir("/", true, decrypt_self_to_elf);
}

static void decrypt_pups(void)
{
    traverse_dir("/mnt/usb0", true, decrypt_pup_to_blobs);
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

    /* Dump/decrypt data */
    decrypt_selfs();
    decrypt_pups();
    //gpu_dump_ih();

    /* Return back to browser */
    dprintf("Dump finished!\n");
    blob_transfer_close();
    debug_close();
    return 0;
}
