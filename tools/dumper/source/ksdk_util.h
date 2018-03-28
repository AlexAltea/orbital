/**
 * (c) 2017-2018 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 */

#ifndef UTIL_H
#define UTIL_H

#define MIN(X, Y) \
    (((X) < (Y)) ? (X) : (Y))
#define MAX(X, Y) \
    (((X) > (Y)) ? (X) : (Y))

#define ROTL16(v, n) \
  ((uint16_t)((v) << (n)) | ((v) >> (16 - (n))))
#define ROTL32(v, n) \
  ((uint32_t)((v) << (n)) | ((v) >> (32 - (n))))

#define ALIGN(size, alignment) \
    (((size) + ((alignment) - 1)) & ~((alignment) - 1))
#define ALIGN_PAGE(size) \
    ALIGN(size, 0x4000)

/* bitfields */
#define GET_HI(hi, lo) (hi)
#define GET_LO(hi, lo) (lo)
#define GET_MASK(hi, lo) \
    (((1 << ((hi) - (lo) + 1)) - 1) << (lo))

#define EXTRACT(value, field) \
    (((value) & field(GET_MASK)) >> field(GET_LO))

/* helpers */
#define X86_CR0_WP (1 << 16)

static inline __attribute__((always_inline))
uint64_t read_msr(uint32_t reg) {
    uint32_t edx;
    uint32_t eax;
    __asm__ ("rdmsr" : "=d"(edx), "=a"(eax) : "c"(reg));
    return (((uint64_t)edx) << 32) | (uint64_t)eax;
}

static inline __attribute__((always_inline))
uint64_t read_cr0(void) {
    uint64_t cr0;
    __asm__ ("movq %0, %%cr0" : "=r" (cr0) : : "memory");
    return cr0;
}

static inline __attribute__((always_inline))
void write_cr0(uint64_t cr0) {
    __asm__ ("movq %%cr0, %0" : : "r" (cr0) : "memory");
}

static inline __attribute__((always_inline))
void cpu_enable_wp(void)
{
    uint64_t cr0 = read_cr0();
    write_cr0(cr0 | X86_CR0_WP);
}

static inline __attribute__((always_inline))
void cpu_disable_wp(void)
{
    uint64_t cr0 = read_cr0();
    write_cr0(cr0 & ~X86_CR0_WP);
}

static inline __attribute__((always_inline))
void* curthread(void)
{
    uint64_t td;
    __asm__ ("movq %0, %%gs:0" : "=r" (td) : : "memory");
    return (void*)td;
}

#endif /* UTIL_H */
