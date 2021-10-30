/**
 * AMD Interrupt Handler (IH) device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "ih.h"
#include <orbital/hardware/liverpool/gmc/gmc.h>

#include "oss_2_0_d.h"
#include "oss_2_0_sh_mask.h"

IhDevice::IhDevice(PCIeDevice& gc, GmcDevice& gmc)
    : Device(nullptr), gc(gc), gmc(gmc) {
    reset();
}

void IhDevice::reset() {
    // TODO: Do we actually need to zero-initialize anything? Non-status registers might just be undefined.
    memset(vmid_lut, 0, sizeof(vmid_lut));
    rb_cntl = 0;
    rb_base = 0;
    rb_rptr = 0;
    rb_wptr = 0;
    rb_wptr_addr = 0;

    cntl = 0;
    level_status = 0;
    status = 0;
    status_idle = true;
    status_input_idle = true;
    status_rb_idle = true;

    perfmon_cntl = 0;
    perfcounter0_result = 0;
    perfcounter1_result = 0;
    advfault_cntl = 0;
}

U32 IhDevice::mmio_read(U32 index) {
    U32 value = 0;

    switch (index) {
    case mmIH_RB_BASE:
        value = rb_base;
        break;
    case mmIH_RB_WPTR:
        value = rb_wptr;
        break;
    case mmIH_RB_WPTR_ADDR_LO:
        value = rb_wptr_addr_lo;
        break;
    case mmIH_RB_WPTR_ADDR_HI:
        value = rb_wptr_addr_hi;
        break;
    case mmIH_STATUS:
        value = status;
        break;
    default:
        assert_always("Unimplemented");
    }

    return value;
}

void IhDevice::mmio_write(U32 index, U32 value) {
    switch (index) {
    case mmIH_RB_CNTL:
        rb_cntl = value;
        break;
    case mmIH_RB_BASE:
        rb_base = value;
        break;
    case mmIH_RB_WPTR:
        rb_wptr = value;
        break;
    case mmIH_RB_WPTR_ADDR_LO:
        rb_wptr_addr_lo = value;
        break;
    case mmIH_RB_WPTR_ADDR_HI:
        rb_wptr_addr_hi = value;
        break;
    default:
        assert_always("Unimplemented");
    }
}

void IhDevice::push_iv(U32 vmid, U32 src_id, U32 src_data) {
    const U08 ringid = 0; // TODO
    const U16 pasid = 0; // TODO
    assert(vmid < 16);
    assert(src_id < 0x100);
    assert(src_data < 0x10000000);

    std::unique_lock<std::mutex> lock(mutex);
    rb_push(src_id);
    rb_push(src_data);
    rb_push(((pasid << 16) | (vmid << 8) | ringid));
    rb_push(0 /* TODO: timestamp & 0xFFFFFFF */);
    lock.unlock();

    if (gc.msi_ready()) {
        gc.msi_notify(0);
    }
}

void IhDevice::rb_push(U32 value) {
    auto& vm = static_cast<Space&>(gmc.get(mc_vmid));
    uint64_t addr;

    // Push value
    addr = ((U64)rb_base << 8) + rb_wptr;
    vm.write<U32>(addr, value);
    rb_wptr += 4;
    rb_wptr &= rb_size() - 1;

    // Update WPTR
    vm.write<U32>(rb_wptr_addr, rb_wptr);
}
