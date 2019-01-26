/**
 * (c) 2017-2019 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Based in previous tools and research by: fail0verflow, flatz.
 */

#ifdef VERSION_500

#include "gpu_dumper.h"
#include "debug.h"

#include "ksdk.h"

typedef struct gpu_dump_ih_info_t {
    /* gpu information */
    uint32_t rb_rptr;
    uint32_t rb_wptr;
    /* cpu information */
    void *rb_base;
    /* ih ringbuffer */
    uint8_t rb[0x1000];
} gpu_dump_ih_info_t;

/* kernel */
typedef struct gpu_kdump_ih_args_t {
    gpu_dump_ih_info_t *uinfo;
} gpu_kdump_ih_args_t;

typedef struct gpu_kmethod_uap_t {
    void *kmethod;
    void *args;
} gpu_kmethod_uap_t;

int gpu_kdump_ih(
    struct thread *td, struct gpu_kmethod_uap_t *uap)
{
    int ret;
    gpu_kdump_ih_args_t *args = uap->args;
    gpu_dump_ih_info_t info;

    ret = 0;
    info.rb_wptr = 0x4567;
    info.rb_base = g_ih_mgr->rb_base;
    memcpy(&info.rb, g_ih_mgr->rb_base, 0x1000);
    memcpy(args->uinfo, &info, sizeof(info));

    return ret;
}

int gpu_dump_ih()
{
    gpu_dump_ih_info_t info;
    gpu_kdump_ih_args_t args;

    args.uinfo = &info;
    info.rb_rptr = 0x1234;
    syscall(11, gpu_kdump_ih, &args);
    dprintf("rb_rptr %X\n", info.rb_rptr);
    dprintf("rb_wptr %X\n", info.rb_wptr);
    dprintf("rb_base %p\n", info.rb_base);
    hexdump("rb", &info.rb, 0x1000);
    return 0;
}

#endif
