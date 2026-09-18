/* ib_buf.h —— isbench 可选公共层(需要缓冲区/种子/KAT输入推导时 include)
 *
 * 必须在 #include "ib_core.h" 之后引用。
 * 含: 宽度类型 + 种子宏 + 签名聚合 + 缓冲区 + 标志注入/取回 + IB_ROW 宏。
 */
#ifndef ISB_IB_BUF_H
#define ISB_IB_BUF_H

#include "ib_core.h"
#include "ib_gen.h"       /* 统一输入生成器(IB_G/IB_GB/IB_KIN/IB_KFL), 必须在 ib_core.h 之后 */

/* ==================== 宽度类型与立即数 ==================== */
#define IB_UQ unsigned long long
#define IB_UL unsigned int
#define IB_UW uint16_t
#define IB_UB uint8_t
#define IB_IMM "$5"
#ifdef __x86_64__
#define IB_WSUF "q"
#define IB_WTY  IB_UQ
#define IB_REG_SP "rsp"
#define IB_REG_BP "rbp"
#define IB_RG_A   "rax"
#define IB_RG_B   "rbx"
#define IB_RG_C   "rcx"
#define IB_RG_D   "rdx"
#define IB_RG_D16 "dx"
#define IB_RG_E   "rdx"
#define IB_SSTK   "q"
#else
#define IB_WSUF "l"
#define IB_WTY  IB_UL
#define IB_REG_SP "esp"
#define IB_REG_BP "ebp"
#define IB_RG_A   "eax"
#define IB_RG_B   "ebx"
#define IB_RG_C   "ecx"
#define IB_RG_D   "edx"
#define IB_RG_D16 "dx"
#define IB_RG_E   "edx"
#define IB_SSTK   "l"
#endif
#ifdef __x86_64__
#define IB_LBL_ADDR "8f(%%rip)"
#else
#define IB_LBL_ADDR "8f"
#endif
#define IB_TOPBIT(TY) ((TY)1 << (sizeof(TY) * 8 - 1))

/* ==================== 种子与签名聚合 ==================== */
#define IB_SEED(n) ((uint64_t)(0x9e3779b97f4a7c15ULL * (0x1122334455667788ULL + \
                        (unsigned long long)(n) * 0x100000001b3ULL) + \
                        (unsigned long long)(n) * 2654435761ull + 7ull))

#define IB_S1(x)       ((uint64_t)(x) * 0x9e3779b97f4a7c15ULL)
#define IB_S2(x, y)    (IB_S1(x) + (uint64_t)(y) * 0x85ebca6b96b5ee61ULL)
#define IB_S4(a, b, c, d) (IB_S1(a) + (uint64_t)(b) * 0x85ebca6b96b5ee61ULL + \
                           (uint64_t)(c) * 0xc2b2ae3d27d4eb4fULL + \
                           (uint64_t)(d) * 0x165667b19e3779f9ULL)

/* ==================== 缓冲区与寻址 ==================== */
static uint64_t g_rbuf[64] __attribute__((aligned(64)));
static uint64_t g_wbuf[64] __attribute__((aligned(64)));
#define IB_RBASE() ((uintptr_t)g_rbuf)
#define IB_WBASE() ((uintptr_t)g_wbuf)
#define IB_PROT_P(k) const void *p = (const void *)(IB_RBASE() + \
                     (((uintptr_t)(k) * 8) & 448))
#define IB_PROT_W(k) void *w = (void *)(IB_WBASE() + \
                     (((uintptr_t)(k) * 8) & 448))
#define IB_PROT_X(k) uintptr_t ix = (uintptr_t)((k) & 7)
#define IB_M_BASE    "8(%[p])"
#define IB_M_IDX     "(%[p],%[ix],8)"
#define IB_M_RIP     "g_rbuf+8(%%rip)"
#ifdef __x86_64__
#define IB_M_SP      "-64(%%rsp)"
#else
#define IB_M_SP      "-64(%%esp)"
#endif
#define IB_W_BASE    "8(%[w])"
#define IB_W_IDX     "(%[w],%[ix],8)"
#define IB_W_SLOT    "8(%[w])"

__attribute__((unused)) static void ib_abuf_init(void)
{
    int i;
    volatile uint64_t *r = g_rbuf, *w = g_wbuf;
    for (i = 0; i < 64; i++) {
        r[i] = IB_SEED(i);
        w[i] = 0;
    }
    __asm__ volatile("" :: "r"(g_rbuf), "r"(g_wbuf) : "memory");
}

/* KAT 专用缓冲区 */
static uint64_t g_kbuf[64] __attribute__((aligned(64)));
__attribute__((noinline, unused)) static void *ib_kbuf_fill(uint64_t v)
{
    int i;
    for (i = 0; i < 64; i++)
        g_kbuf[i] = v;
    __asm__ volatile("" ::: "memory");
    return (void *)g_kbuf;
}

/* ==================== 用例表行宏(声明式, 一行一 case) ==================== */
#define IB_ROW(nm, cap, sn)          { nm, cap, k_##sn, k_##sn##_tp, 0, NULL, 0, NULL, 0 }
#define IB_ROW_P(nm, cap, sn, bp)    { nm, cap, k_##sn, k_##sn##_tp, 0, NULL, bp, NULL, 0 }
#define IB_ROW_L(nm, cap, sn, li)    { nm, cap, k_##sn, k_##sn##_tp, 0, NULL, 0, NULL, li }
#define IB_ROW_PL(nm, cap, sn, bp, li) \
    { nm, cap, k_##sn, k_##sn##_tp, 0, NULL, bp, NULL, li }
#define IB_ROW_T(nm, cap, sn, bp)    { nm, cap, NULL, k_##sn##_tp, 0, NULL, bp, NULL, 0 }
#define IB_ROW_LAT(nm, cap, sn)      { nm, cap, k_##sn, NULL, 0, NULL, 0, NULL, 0 }
#define IB_ROW_K(nm, cap, sn, bp)    { nm, cap, k_##sn, k_##sn##_tp, 0, NULL, bp, \
                                       NULL, 0, k_##sn##_kat, IB_KAT_##sn, #sn }
#define IB_ROW_KT(nm, cap, sn, bp)   { nm, cap, NULL, k_##sn##_tp, 0, NULL, bp, \
                                       NULL, 0, k_##sn##_kat, IB_KAT_##sn, #sn }
#define IB_ROW_KPL(nm, cap, sn, bp, li) { nm, cap, k_##sn, k_##sn##_tp, 0, NULL, bp, \
                                       NULL, li, k_##sn##_kat, IB_KAT_##sn, #sn }

/* ==================== 标志注入/取回 ==================== */
#ifdef __x86_64__
#define IB_SETF        "pushq %[fv]\n\tpopfq\n\t"
#define IB_GETF        "\n\tpushfq\n\tpopq %[fl]"
#define IB_GETF2(v)    "\n\tpushfq\n\tpopq %[" v "]"
#else
#define IB_SETF        "pushl %[fv]\n\tpopfl\n\t"
#define IB_GETF        "\n\tpushfl\n\tpopl %[fl]"
#define IB_GETF2(v)    "\n\tpushfl\n\tpopl %[" v "]"
#endif

/* ==================== KAT 输入推导 ====================
 * 已上移到 ib_gen.h(统一输入生成器): ib_strhash/ib_mix/ib_kin + IB_G/IB_KIN/IB_KIN8/
 * IB_KFL/IB_GB。此处不再重复定义(重复定义 = 第二套实现, 早晚漂移)。 */

#endif /* ISB_IB_BUF_H */
