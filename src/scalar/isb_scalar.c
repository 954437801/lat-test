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
#include "ib_core.h"
#include "ib_buf.h"           /* KAT 输入推导(IB_KIN8/IB_KFL)与标志注入(IB_SETF/IB_GETF) */
#include "isb_scalar_kat.h"   /* KAT 真值表(采集后生成; 未取数时全 UNSET) */

/* ---------------- add_r64: 延迟参考下限 ----------------
 * 线性递推 a+=b 会被 GCC 闭式折叠(实测 0.00 ns/op), 用 asm 钉死依赖链。 */
static uint64_t k_add_r64(ib_uw iters)
{
    ib_uw i;
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
static uint64_t k_add_r64_tp(ib_uw iters)
{
    ib_uw i;
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

/* ---- x86_add_r64 的 b8: 连续8指令块执行时间(同行新列, 不新建 case 行) ----
 * 块 = 8 条连续相同指令(addq/addl), 各作用于独立累加链, 操作数来自
 * g_b8 确定性缓冲的 8 个相位(同轮互异、8B 步进轮转不重复) —— 与单指令
 * tput 的固定常数源区分, 防"同值重复"被数据级优化利用;
 * 测每块(8 连)平均执行 ns, 与同 run 单指令行 lat_ns/tput_ops 对照判块级
 * 优化(判定口径见 docs/设计/功能测试与KAT.md)。x86-64: 8 链; i386(仅 7 GPR): 4 链 x 每轮 2
 * 相位, 块内仍 8 条连续指令。asm volatile 单基址+位移: 防 "m" 地址提升。 */
static uint64_t g_b8[144] __attribute__((aligned(64)));  /* 18x64B: o+位移 最大 1072B 不越界 */
static uint64_t k_add_r64_b8(ib_uw iters)
{
    uintptr_t o = 0;
    ib_uw i;
#ifdef __x86_64__
    uint64_t a0 = 0x1122334455667788ULL, a1 = 0x9e3779b97f4a7c15ULL,
             a2 = 0x243f6a8885a308d3ULL, a3 = 0x13198a2e03707344ULL,
             a4 = 0xa4093822299f31d0ULL, a5 = 0x082efa98ec4e6c89ULL,
             a6 = 0x452821e638d01377ULL, a7 = 0xbe5466cf34e90c6cULL;
    for (i = 0; i < iters; i++) {
        const void *p = (const void *)((uintptr_t)g_b8 + o);
        __asm__ volatile(
            "addq 0(%8),%0\n\t"
            "addq 8(%8),%1\n\t"
            "addq 16(%8),%2\n\t"
            "addq 24(%8),%3\n\t"
            "addq 32(%8),%4\n\t"
            "addq 40(%8),%5\n\t"
            "addq 48(%8),%6\n\t"
            "addq 56(%8),%7"
            : "+r"(a0), "+r"(a1), "+r"(a2), "+r"(a3),
              "+r"(a4), "+r"(a5), "+r"(a6), "+r"(a7)
            : "r"(p)
            : "memory");
        o = (o + 8) & 1023u;  /* 1KB 内 8B 步进轮转, 终点确定(4096x8 mod 1024 = 0) */
    }
    return a0 ^ a1 ^ a2 ^ a3 ^ a4 ^ a5 ^ a6 ^ a7;
#else
    uint32_t a = 0x11223344u, b = 0x9e3779b9u, c = 0x243f6a88u, d = 0x13198a2eu;
    for (i = 0; i < iters; i++) {
        const void *p = (const void *)((uintptr_t)g_b8 + o);
        __asm__ volatile(
            "addl 0(%4),%0\n\t"
            "addl 8(%4),%1\n\t"
            "addl 16(%4),%2\n\t"
            "addl 24(%4),%3\n\t"
            "addl 32(%4),%0\n\t"
            "addl 40(%4),%1\n\t"
            "addl 48(%4),%2\n\t"
            "addl 56(%4),%3"
            : "+r"(a), "+r"(b), "+r"(c), "+r"(d)
            : "r"(p)
            : "memory");
        o = (o + 8) & 1023u;  /* 1KB 内 8B 步进轮转(i386 同 x64: 不越界) */
    }
    return (uint64_t)a ^ ((uint64_t)b << 16) ^ ((uint64_t)c << 32) ^ ((uint64_t)d << 48);
#endif
}

/* ---------------- mul_r64: 乘法延迟链(链不可闭式折叠) ---------------- */
static uint64_t k_mul_r64(ib_uw iters)
{
    uint64_t a = 0x1122334455667788ULL, k = 0x9e3779b97f4a7c15ULL;
    ib_uw i;
    for (i = 0; i < iters; i++)
        a *= k;
    return a;
}
static uint64_t k_mul_r64_tp(ib_uw iters)
{
    uint64_t a = 0x1122334455667788ULL, b = 0x9e3779b97f4a7c15ULL,
             c = 0x243f6a8885a308d3ULL, d = 0x13198a2e03707344ULL;
    ib_uw i;
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
static uint64_t k_crc32(ib_uw iters)
{
    uint32_t k = 0x12345678u;
    uint32_t a = 0xdeadbeefu;
    ib_uw i;
    for (i = 0; i < iters; i++) {
        k = k * 2654435761u + 1u;
        a = _mm_crc32_u32(a, k);
    }
    return a;
}
__attribute__((target("sse4.2")))
static uint64_t k_crc32_tp(ib_uw iters)
{
    uint32_t a = 0xdeadbeefu, b = 0x13579bdfu, c = 0xcafef00du, d = 0x0badf00du;
    uint32_t k1 = 0x12345678u, k2 = 0x23456789u, k3 = 0x3456789au, k4 = 0x456789abu;
    ib_uw i;
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

/* popcnt / lzcnt / bsr / bsf 已从本组删除(归 bits 组, 去重口径见 docs/设计/功能测试标准.md §5.2):
 * 位扫描/位操纵本就是 bits 的定位, 本组只留"标量整数基线"(add/mul) + crc32。 */

/* ---------------- KAT 探针(每词干一条) ----------------
 * 口径: 输入由词干哈希重导(甲=i0, 乙=i1), 只执行 1 次不进循环; 判定只比 o0..o3+outf。
 * 宽度固定取 32 位 —— 计时内核随 ABI 自适应宽度(x64 走 64 位, i386 走 32 位),
 * 但真值表两 ABI 共用, 故 KAT 用与 ABI 无关的定宽形式(同 cc 组), i386 与
 * x86_64 同表同值; 想审 64 位形态交给 alu 组的 add/mul 专条。
 * add: o0 = 和, outf = 全状态位;  mul: o0 = 积(截断), outf = CF/OF(其余未定义);
 * crc32: o0 = crc32(甲,乙), 架构上不碰 EFLAGS -> outf = 0。 */
static void k_add_r64_kat(int kk, ib_kv *g)
{
    IB_UL a = (IB_UL)IB_KIN8("add_r64", kk, 0, IB_UL),
          b = (IB_UL)IB_KIN8("add_r64", kk, 1, IB_UL);
    IB_UL ain = a;
    uintptr_t fv = (uintptr_t)IB_KFL("add_r64", kk), fl = 0;
    __asm__ volatile(IB_SETF "addl %[b],%[a]" IB_GETF
                    : [a] "+r"(a), [fl] "=&r"(fl)
                    : [b] "r"(b), [fv] "r"(fv) : "cc", "memory");
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b; g->inf = (uint64_t)fv;
    g->o0 = (uint64_t)a; g->o1 = 0; g->outf = (uint64_t)fl & IB_FLG_MASK;
}
static void k_mul_r64_kat(int kk, ib_kv *g)
{
    IB_UL a = (IB_UL)IB_KIN8("mul_r64", kk, 0, IB_UL),
          b = (IB_UL)IB_KIN8("mul_r64", kk, 1, IB_UL);
    IB_UL ain = a;
    uintptr_t fv = (uintptr_t)IB_KFL("mul_r64", kk), fl = 0;
    __asm__ volatile(IB_SETF "imull %[b],%[a]" IB_GETF
                    : [a] "+r"(a), [fl] "=&r"(fl)
                    : [b] "r"(b), [fv] "r"(fv) : "cc", "memory");
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b; g->inf = (uint64_t)fv;
    g->o0 = (uint64_t)a; g->o1 = 0; g->outf = (uint64_t)fl & (IB_FLG_MASK_CFOF);
}
__attribute__((target("sse4.2"))) static void k_crc32_kat(int kk, ib_kv *g)
{
    IB_UL a = (IB_UL)IB_KIN8("crc32", kk, 0, IB_UL),
          b = (IB_UL)IB_KIN8("crc32", kk, 1, IB_UL);
    IB_UL ain = a;
    __asm__ volatile("crc32l %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b; g->inf = 0;
    g->o0 = (uint64_t)a; g->o1 = 0; g->outf = 0;
}

static const ib_case g_cases[] = {
    { "x86_add_r64", NULL, k_add_r64, k_add_r64_tp, 0, NULL, 0, k_add_r64_b8, 0,
      k_add_r64_kat, IB_KAT_add_r64, "add_r64" },
    { "x86_mul_r64", NULL, k_mul_r64, k_mul_r64_tp, 0, NULL, 0, NULL, 0,
      k_mul_r64_kat, IB_KAT_mul_r64, "mul_r64" },
    { "sse42_crc32", "sse4.2", k_crc32, k_crc32_tp, 0, NULL, 0, NULL, 0,
      k_crc32_kat, IB_KAT_crc32, "crc32" },
};
#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

int main(int argc, char **argv)
{
    int i;
    volatile uint64_t *vb = g_b8;   /* volatile 写: 内容对编译器不可知, 防 0 传播/常数化 */
    for (i = 0; i < 144; i++)
        vb[i] = (uint64_t)(i * 13 + 7) * 0x9e3779b97f4a7c15ULL;
    __asm__ volatile("" : "+m"(g_b8[0]) : : "memory");
    ib_init(argc, argv);
    ib_hdr("scalar", NCASES);
    ib_run_cases("scalar", g_cases, NCASES);
    return 0;
}
