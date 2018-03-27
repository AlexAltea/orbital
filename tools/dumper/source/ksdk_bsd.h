/**
 * (c) 2017-2018 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 */

#ifndef KSDK_BSD_H
#define KSDK_BSD_H

/* constants */
#define DT_DIR      0x0004
#define DT_REG      0x0008

#define M_NOWAIT    0x0001
#define M_WAITOK    0x0002
#define M_ZERO      0x0100

struct auditinfo_addr {
    char useless[184];
};

struct ucred {
    uint32_t cr_ref;
    uint32_t cr_uid;
    uint32_t cr_ruid;
    uint32_t cr_svuid;
    uint32_t cr_ngroups;
    uint32_t cr_rgid;
    uint32_t cr_svgid;
    void *cr_uidinfo;
    void *cr_ruidinfo;
    void *cr_prison;
    void *cr_loginclass;
    uint32_t cr_flags;
    void *cr_pspare2[2];
    void *cr_label;
    struct auditinfo_addr cr_audit;
    uint32_t *cr_groups;
    uint32_t cr_agroups;
};

struct filedesc {
    void *useless1[3];
    void *fd_rdir;
    void *fd_jdir;
};

struct proc {
    char useless[64];
    struct ucred *p_ucred;
    struct filedesc *p_fd;
};

struct thread {
    void *useless;
    struct proc *td_proc;
};

typedef struct write_args {
    int64_t fd;
    const void *buf;
    size_t nbyte;
} write_args;

#endif /* KSDK_BSD_H */
