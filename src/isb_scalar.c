/* isb_scalar.c —— isbench 组1: 标量整数族
 *
 * 迁移来源: legacy insn_probe.c(add_r64/mul_r64), hf_probe.c(crc32/popcnt),
 *           sse_state_probe.c 组3 GPR 侧(lzcnt 等语义)。
 * 每用例双内核: lat = 稳态单依赖链 ns/op; tput = 4 独立链定时长吞吐。
 * 依赖链纪律(与 legacy 同): 链主变量必须不被编译器闭式折叠 —— 迭代数为
 * 运行时参数且结果经签名输出, GCC 无法预先求闭式。
 *
 * 编码纪律: 本组整体构建 flags 不带 -mavx*; crc32/popcnt/lzcnt 由
 * __attribute__((target(...))) 单函数发射; bsr/bsf 用内联 asm 钉死编码。
 */
#include "ib.h"

/* ---------------- add_r64: 延迟参考下限 ----------------
 * 线性递推 a+=b 会被 GCC 闭式折叠(实测 0.00 ns/op), 用 asm 钉死依赖链。 */
static uint64_t k_add_r64(unsigned long long iters)
{
    unsigned long long i;
#ifdef __x86_64__
    uint64_t a = 0x1122334455667788ULL, b = 0x9e3779b97f4a7c15ULL;
    for (i = 0; i < iters; i++)
        __asm__("addq %1,%0" : "+r"(a) : "r"(b));
    return a;
#else
    uint32_t a = 0x11223344u, b = 0x9e3779b9u;
    for (i = 0; i < iters; i++)
        __asm__("addl %1,%0" : "+r"(a) : "r"(b));
    return a;
#endif
}
static uint64_t k_add_r64_tp(unsigned long long iters)
{
    unsigned long long i;
#ifdef __x86_64__
    uint64_t a = 0x1122334455667788ULL, b = 0x9e3779b97f4a7c15ULL;
    uint64_t c = 0x243f6a8885a308d3ULL, d = 0x13198a2e03707344ULL;
    uint64_t k = 0xa4093822299f31d0ULL;
    for (i = 0; i < iters; i++) {
        __asm__("addq %1,%0" : "+r"(a) : "r"(b));
        __asm__("addq %1,%0" : "+r"(b) : "r"(c));
        __asm__("addq %1,%0" : "+r"(c) : "r"(d));
        __asm__("addq %1,%0" : "+r"(d) : "r"(k));
    }
    return a ^ b ^ c ^ d;
#else
    uint32_t a = 0x11223344u, b = 0x9e3779b9u;
    uint32_t c = 0x243f6a88u, d = 0x13198a2eu;
    for (i = 0; i < iters; i++) {
        __asm__("addl %1,%0" : "+r"(a) : "r"(b));
        __asm__("addl %1,%0" : "+r"(b) : "r"(c));
        __asm__("addl %1,%0" : "+r"(c) : "r"(d));
        __asm__("addl %1,%0" : "+r"(d) : "r"(a));
    }
    return (uint64_t)a ^ ((uint64_t)b << 16) ^ ((uint64_t)c << 32) ^ ((uint64_t)d << 48);
#endif
}

/* ---------------- mul_r64: 乘法延迟链(链不可闭式折叠) ---------------- */
static uint64_t k_mul_r64(unsigned long long iters)
{
    uint64_t a = 0x1122334455667788ULL, k = 0x9e3779b97f4a7c15ULL;
    unsigned long long i;
    for (i = 0; i < iters; i++)
        a *= k;
    return a;
}
static uint64_t k_mul_r64_tp(unsigned long long iters)
{
    uint64_t a = 0x1122334455667788ULL, b = 0x9e3779b97f4a7c15ULL,
             c = 0x243f6a8885a308d3ULL, d = 0x13198a2e03707344ULL;
    unsigned long long i;
    for (i = 0; i < iters; i++) {
        a *= 0x9e3779b97f4a7c15ULL;
        b *= 0x243f6a8885a308d3ULL;
        c *= 0x13198a2e03707344ULL;
        d *= 0xa4093822299f31d0ULL;
    }
    return a ^ b ^ c ^ d;
}

/* ---------------- crc32: 混合链(rng 依赖 + crc32 旁路, 与 legacy 同构) ---------------- */
__attribute__((target("sse4.2")))
static uint64_t k_crc32(unsigned long long iters)
{
    uint32_t k = 0x12345678u;
    uint32_t a = 0xdeadbeefu;
    unsigned long long i;
    for (i = 0; i < iters; i++) {
        k = k * 2654435761u + 1u;
        a = _mm_crc32_u32(a, k);
    }
    return a;
}
__attribute__((target("sse4.2")))
static uint64_t k_crc32_tp(unsigned long long iters)
{
    uint32_t a = 0xdeadbeefu, b = 0x13579bdfu, c = 0xcafef00du, d = 0x0badf00du;
    uint32_t k1 = 0x12345678u, k2 = 0x23456789u, k3 = 0x3456789au, k4 = 0x456789abu;
    unsigned long long i;
    for (i = 0; i < iters; i++) {
        k1 = k1 * 2654435761u + 1u;
        k2 = k2 * 2654435761u + 1u;
        k3 = k3 * 2654435761u + 1u;
        k4 = k4 * 2654435761u + 1u;
        a = _mm_crc32_u32(a, k1);
        b = _mm_crc32_u32(b, k2);
        c = _mm_crc32_u32(c, k3);
        d = _mm_crc32_u32(d, k4);
    }
    return (uint64_t)a ^ ((uint64_t)b << 16) ^ ((uint64_t)c << 32) ^ ((uint64_t)d << 48);
}

/* ---------------- popcnt ---------------- */
__attribute__((target("popcnt")))
static uint64_t k_popcnt(unsigned long long iters)
{
    uint32_t k = 0x12345678u;
    uint64_t acc = 0;
    unsigned long long i;
    for (i = 0; i < iters; i++) {
        k = k * 2654435761u + 1u;
        acc += (uint32_t)__builtin_popcount(k);
    }
    return acc;
}
__attribute__((target("popcnt")))
static uint64_t k_popcnt_tp(unsigned long long iters)
{
    uint32_t k1 = 0x12345678u, k2 = 0x23456789u, k3 = 0x3456789au, k4 = 0x456789abu;
    uint64_t acc = 0;
    unsigned long long i;
    for (i = 0; i < iters; i++) {
        k1 = k1 * 2654435761u + 1u;
        k2 = k2 * 2654435761u + 1u;
        k3 = k3 * 2654435761u + 1u;
        k4 = k4 * 2654435761u + 1u;
        acc += (uint32_t)__builtin_popcount(k1);
        acc += (uint32_t)__builtin_popcount(k2);
        acc += (uint32_t)__builtin_popcount(k3);
        acc += (uint32_t)__builtin_popcount(k4);
    }
    return acc;
}

/* ---------------- lzcnt(ABM): 同 popcnt 混合链 ---------------- */
__attribute__((target("lzcnt")))
static uint64_t k_lzcnt(unsigned long long iters)
{
    uint32_t k = 0x80000001u;   /* 非 0 种子 */
    uint64_t acc = 0;
    unsigned long long i;
    for (i = 0; i < iters; i++) {
        k = k * 2654435761u + 1u;
        acc += _lzcnt_u32(k ? k : 1u);   /* lzcnt(0)=32 亦确定, 保底仅防 __builtin 语义差 */
    }
    return acc;
}
__attribute__((target("lzcnt")))
static uint64_t k_lzcnt_tp(unsigned long long iters)
{
    uint32_t k1 = 0x80000001u, k2 = 0x80000003u, k3 = 0x80000005u, k4 = 0x80000007u;
    uint64_t acc = 0;
    unsigned long long i;
    for (i = 0; i < iters; i++) {
        k1 = k1 * 2654435761u + 1u;
        k2 = k2 * 2654435761u + 1u;
        k3 = k3 * 2654435761u + 1u;
        k4 = k4 * 2654435761u + 1u;
        acc += _lzcnt_u32(k1 ? k1 : 1u);
        acc += _lzcnt_u32(k2 ? k2 : 1u);
        acc += _lzcnt_u32(k3 ? k3 : 1u);
        acc += _lzcnt_u32(k4 ? k4 : 1u);
    }
    return acc;
}

/* ---------------- bsr / bsf: 真延迟链(x->bit scan->x), asm 钉 32 位编码 ---------------- */
static uint64_t k_bsr(unsigned long long iters)
{
    uint32_t x = 0x80000001u;
    unsigned long long i;
    for (i = 0; i < iters; i++) {
        uint32_t t;
        __asm__("bsrl %1,%0" : "=r"(t) : "r"(x));
        x = ((x << 1) ^ t) | 1u;   /* 非 0 保持; 链经 bsr */
    }
    return x;
}
static uint64_t k_bsr_tp(unsigned long long iters)
{
    uint32_t x = 0x80000001u, y = 0x40000003u, z = 0x20000005u, w = 0x10000007u;
    unsigned long long i;
    for (i = 0; i < iters; i++) {
        uint32_t t;
        __asm__("bsrl %1,%0" : "=r"(t) : "r"(x));
        x = ((x << 1) ^ t) | 1u;
        __asm__("bsrl %1,%0" : "=r"(t) : "r"(y));
        y = ((y << 1) ^ t) | 1u;
        __asm__("bsrl %1,%0" : "=r"(t) : "r"(z));
        z = ((z << 1) ^ t) | 1u;
        __asm__("bsrl %1,%0" : "=r"(t) : "r"(w));
        w = ((w << 1) ^ t) | 1u;
    }
    return (uint64_t)x ^ ((uint64_t)y << 16) ^ ((uint64_t)z << 32) ^ ((uint64_t)w << 48);
}
static uint64_t k_bsf(unsigned long long iters)
{
    uint32_t x = 0x80000001u;
    unsigned long long i;
    for (i = 0; i < iters; i++) {
        uint32_t t;
        __asm__("bsfl %1,%0" : "=r"(t) : "r"(x));
        x = ((x << 1) ^ t) | 1u;
    }
    return x;
}
static uint64_t k_bsf_tp(unsigned long long iters)
{
    uint32_t x = 0x80000001u, y = 0x40000003u, z = 0x20000005u, w = 0x10000007u;
    unsigned long long i;
    for (i = 0; i < iters; i++) {
        uint32_t t;
        __asm__("bsfl %1,%0" : "=r"(t) : "r"(x));
        x = ((x << 1) ^ t) | 1u;
        __asm__("bsfl %1,%0" : "=r"(t) : "r"(y));
        y = ((y << 1) ^ t) | 1u;
        __asm__("bsfl %1,%0" : "=r"(t) : "r"(z));
        z = ((z << 1) ^ t) | 1u;
        __asm__("bsfl %1,%0" : "=r"(t) : "r"(w));
        w = ((w << 1) ^ t) | 1u;
    }
    return (uint64_t)x ^ ((uint64_t)y << 16) ^ ((uint64_t)z << 32) ^ ((uint64_t)w << 48);
}

/* ---------------- 用例表(声明式; 名字首段=ISA 段: x86 基线/sse42/popcnt/abm;
 * 原名首段即能力名者(popcnt)不叠加; cap 空 = 恒支持) ---------------- */
static const ib_case g_cases[] = {
    { "x86_add_r64", NULL,        k_add_r64,   k_add_r64_tp,  0 },
    { "x86_mul_r64", NULL,        k_mul_r64,   k_mul_r64_tp,  0 },
    { "sse42_crc32", "sse4.2",    k_crc32,     k_crc32_tp,    0 },
    { "popcnt",      "popcnt",    k_popcnt,    k_popcnt_tp,   0 },
    { "abm_lzcnt",   "abm",       k_lzcnt,     k_lzcnt_tp,    0 },
    { "x86_bsr",     NULL,        k_bsr,       k_bsr_tp,      0 },
    { "x86_bsf",     NULL,        k_bsf,       k_bsf_tp,      0 },
};
#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

int main(int argc, char **argv)
{
    ib_init(argc, argv);
    ib_hdr("scalar", NCASES);
    ib_run_cases("scalar", g_cases, NCASES);
    return 0;
}
