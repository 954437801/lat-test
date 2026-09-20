/* isb_special.c —— isbench「风险隔离」组: 原子 / 屏障 / 预取填充 / 串操作。
 *
 * x87 已整体迁出: 本文件原有第 6 节的 6 条(fld_fstp / fadd / fmul / fistp /
 * fcomip / fcw_rt)现在是 src/x87/isb_x87.c 的同名词干(内核逐字搬、词干与用例名不变,
 * 所以真值表里这 6 块的字段跨文件仍然同字), 另加 12 条高有效位整型往返。迁出的
 * 理由不是分类洁癖, 而是两件事必须分表存: 1) x87 只有 -m32 编译器会发射, 只能
 * 在 i386 在册(留在 special 就被迫跟着它的 x86_64 形态跑, 那是假覆盖);
 * 2) 入值口径根本不同 —— 本组其余各族的 KAT 表在 x86_64 采一份, 而 x87 新组要
 * 把入值抬到 >= 2^53 去抓 LATX 的 double 中转缺陷, 两套口径不能共表。
 *
 * 风格照 isb_scalar.c: 只依赖 ib.h 的运行框架, 不用任何形态模板宏 —— 一条指令
 * 一个单指令内核(k_*)、一个定时长内核(k_*_tp)、有架构结果的再加一个取值探针
 * (k_*_kat), 指令就是函数体里那行实际 asm。
 * 测的是**指令功能**, 不去对齐 实测 表里的形态(尺寸/寻址段/lock 前缀的组合):
 * 同一指令的各形态在 LATX 侧走同一条翻译路径, 分别登记只是把一份成本写四遍。
 * 宽度不穷举(一条指令只登记一个宽度, 不做形态档): 原子族钉 32 位、两 ABI 同宽,
 * 因为 KAT 表只在 x86_64 采一份 —— 内核宽度若跟着 ABI 变, i386 版的入值与结果
 * 高 32 位必然与表不符(实测见 A32 定义处)。串族逐字节、预取/屏障的地址宽度跟
 * ABI 走(I64/TW), 都不上表或不产宽度相关的值。
 *
 * 为什么这几族要单独成组(拆分维度 = LATX 成本结构 + 风险隔离): 原子要保原子序
 * (LLSC 开则 amxor/ll-sc, 关则全局自旋锁)、串要改 rsi/rdi/rcx、屏障/预取要么被删
 * 要么被扩, 三族互不相干且任一跑崩都不该带走别的族的数。
 *
 * lock 与不带 lock 的两形**必须分开登记**: 二者在 LATX 侧代价差是量级级的, 合成
 * 一条就把这个差异抹平了。同理 mfence/lfence/sfence 序强度不同, 各登一条。
 */
#include "ib_core.h"
#include "ib_buf.h"        /* KAT 输入推导(IB_KIN8/IB_KIN/IB_KFL)与标志注入(IB_SETF/IB_GETF) */
#include "isb_special_kat.h"     /* KAT 真值表(采集后生成; 未取数时全 UNSET) */

/* 自然宽度切换: 指令后缀 / C 类型 / 栈上槽位无需(本组一律用静态缓冲) */
#ifdef __x86_64__
#define I64 "q"
typedef uint64_t TW;
#else
#define I64 "l"
typedef uint32_t TW;
#endif

/* 原子族操作数宽度钉死 32 位(A32/AW): 与 ABI 无关 -> 一份 KAT 表两 ABI 通用。
 * 实测事实(i386-windows 复用 x86_64 采的表, 校验脚本): 用自然宽度 I64 时
 * 6 条原子全 KATFAIL(i0 高 32 位 e=0a7c9734 g=00000000 这类), 5 条串族全 OK
 * —— 差别就在串族本来就是字节宽。要 64 位宽形的数, 单独再登记一条(仅 x86_64
 * 在册、自己的词干、自己的表), 不要把这一族的宽度改回跟着 ABI 漂。 */
#define A32 "l"
typedef uint32_t AW;

/* 本组自用缓冲: 原子目的操作数、串的源/目的。全部静态分配 -> 不碰红区, 也不用
 * 把窗口指针传进 asm。main() 里经 volatile 指针填, 内容对编译器不可知(防常数折叠)。 */
static AW    g_mem[8] __attribute__((aligned(64)));
static uint64_t g_src[8] __attribute__((aligned(64)));
static uint64_t g_dst[8] __attribute__((aligned(64)));

/* 让 KAT 探针成为非叶子函数: 叶子函数里 pushf/popf 会落在红区, 被异步事件踩掉
 * 就会读到脏标志(参 ib.h 的 KAT 节注释)。这里顺手把内存槽预置成 m 再返回地址。 */
__attribute__((noinline)) static AW *kbuf(AW m)
{
    g_mem[1] = m;
    return &g_mem[1];
}

/* =====================================================================
 * 1) 原子: xchg(寄存器形与内存形) / cmpxchg / xadd —— 后两条各带一个 lock 形
 *    操作数角色由架构钉死: xchg 两 operand 都读写; cmpxchg 拿隐式累加器与目的比,
 *    等则目的<-src(累加器不变, ZF=1), 不等则累加器<-目的(ZF=0), src 只读;
 *    xadd 目的 <- src+old_dst, src <- old_dst。
 *    链主必须是累加器且不能进吸收态: cmpxchg 令 src = acc+2, 首轮(预置 mem=acc)
 *    走相等支、次轮走不等支把内存值回灌 acc, 每 2 轮 acc +2 单调增长, 两个分支
 *    各占一半轮次;xadd 零骨架自成链(acc 与内存互为斐波那契递推, 即
 *    mem(t+1)=mem(t)+mem(t-1) mod 2^64 -> 不会塌成常值);xchg 靠一条 add 推进。
 *    寄存器一律钉 "a"/"c"(累加器与 cmpxchg 的 src), 别的操作数走普通 "r"。
 *    实测事实(x86_64 参考机, 校验脚本): 零骨架的 xadd 内存 RMW 链报 0.33
 *    ns/轮、加一条 rol 骨架反而变 0.57 —— 同地址 store-to-load 转发比直觉快得多,
 *    且终值是富值(88d752ee1f743d6b)不是 0。所以这一行的 lat 偏低**不是**链被编译
 *    器折叠(反汇编核对过循环体只有一条 xadd), 不要为了“看着像个数”去改链形。
 * ===================================================================== */
/* ---------------- xchg 寄存器形 ---------------- */
static uint64_t k_xchg_r(unsigned long long iters)
{
    unsigned long long i;
    AW a = (AW)0x11223344u, b = (AW)0x9e3779b9u;

    for (i = 0; i < iters; i++)
        __asm__("add" A32 " $1,%[b]\n\txchg" A32 " %[b],%[a]"
                : [a] "+a"(a), [b] "+b"(b) : : "cc");
    return (uint64_t)a ^ ((uint64_t)b << 16);
}
static uint64_t k_xchg_r_tp(unsigned long long iters)
{
    unsigned long long i;
    AW a = (AW)0x11223344u, b = (AW)0x9e3779b9u;
    AW c = (AW)0x243f6a88u, d = (AW)0x13198a2eu;

    for (i = 0; i < iters; i++) {
        __asm__("add" A32 " $1,%[b]\n\txchg" A32 " %[b],%[a]"
                : [a] "+a"(a), [b] "+b"(b) : : "cc");
        __asm__("add" A32 " $1,%[d]\n\txchg" A32 " %[d],%[c]"
                : [c] "+c"(c), [d] "+d"(d) : : "cc");
    }
    return (uint64_t)a ^ ((uint64_t)b << 16) ^ ((uint64_t)c << 32) ^
           ((uint64_t)d << 48);
}
static void k_xchg_r_kat(int kk, ib_kv *g)
{
    AW a = (AW)IB_KIN8("xchg_r", kk, 0, AW), b = (AW)IB_KIN8("xchg_r", kk, 1, AW);
    AW in0 = a, in1 = b;
    AW *p = kbuf(0);                       /* 只为非叶子化 */
    uintptr_t fv = (uintptr_t)IB_KFL("xchg_r", kk), fl = 0;

    __asm__ volatile(IB_SETF "xchg" A32 " %[b],%[a]" IB_GETF
                     : [a] "+a"(a), [b] "+c"(b), [fl] "=&r"(fl)
                     : [p] "r"(p), [fv] "r"(fv) : "cc", "memory");
    g->i0 = in0;  g->i1 = in1;  g->inf = fv;
    g->o0 = a;    g->o1 = b;                 /* 期望: o0==i1 且 o1==i0, 标志不受影响 */
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

/* ---------------- xchg 内存形(隐式带锁) ---------------- */
static uint64_t k_xchg_m(unsigned long long iters)
{
    unsigned long long i;
    AW a = (AW)0x11223344u, x;
    AW *p = &g_mem[1];

    __asm__ volatile("mov" A32 " $0x77,(%[p])" : : [p] "r"(p) : "memory");
    for (i = 0; i < iters; i++)
        __asm__("add" A32 " $1,%[a]\n\txchg" A32 " %[a],(%[p])"
                : [a] "+a"(a) : [p] "r"(p) : "cc", "memory");
    __asm__ volatile("mov" A32 " (%[p]),%[x]" : [x] "=r"(x) : [p] "r"(p) : "memory");
    return (uint64_t)a ^ ((uint64_t)x << 16);
}
static uint64_t k_xchg_m_tp(unsigned long long iters)
{
    unsigned long long i;
    AW a = (AW)0x11223344u, x;
    AW *p = &g_mem[1];

    __asm__ volatile("mov" A32 " $0x77,(%[p])" : : [p] "r"(p) : "memory");
    for (i = 0; i < iters; i++) {
        __asm__("add" A32 " $1,%[a]\n\txchg" A32 " %[a],(%[p])"
                : [a] "+a"(a) : [p] "r"(p) : "cc", "memory");
        __asm__("add" A32 " $1,%[a]\n\txchg" A32 " %[a],(%[p])"
                : [a] "+a"(a) : [p] "r"(p) : "cc", "memory");
        __asm__("add" A32 " $1,%[a]\n\txchg" A32 " %[a],(%[p])"
                : [a] "+a"(a) : [p] "r"(p) : "cc", "memory");
        __asm__("add" A32 " $1,%[a]\n\txchg" A32 " %[a],(%[p])"
                : [a] "+a"(a) : [p] "r"(p) : "cc", "memory");
    }
    __asm__ volatile("mov" A32 " (%[p]),%[x]" : [x] "=r"(x) : [p] "r"(p) : "memory");
    return (uint64_t)a ^ ((uint64_t)x << 16);
}
static void k_xchg_m_kat(int kk, ib_kv *g)
{
    AW a = (AW)IB_KIN8("xchg_m", kk, 0, AW);
    AW m = (AW)IB_KIN8("xchg_m", kk, 1, AW);
    AW in0 = a, in1 = m, x;
    AW *p = kbuf(m);
    uintptr_t fv = (uintptr_t)IB_KFL("xchg_m", kk), fl = 0;

    __asm__ volatile(IB_SETF "mov" A32 " %[m],(%[p])\n\txchg" A32 " %[a],(%[p])\n\t"
                     "mov" A32 " (%[p]),%[x]" IB_GETF
                     : [a] "+a"(a), [x] "=&r"(x), [fl] "=&r"(fl)
                     : [m] "r"(in1), [p] "r"(p), [fv] "r"(fv) : "cc", "memory");
    g->i0 = in0;  g->i1 = in1;  g->inf = fv;
    g->o0 = a;    g->o1 = x;                /* 期望: o0==i1 且 o1==i0 */
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

/* ---------------- cmpxchg ---------------- */
static uint64_t k_cmpxchg(unsigned long long iters)
{
    unsigned long long i;
    AW a = (AW)0x11223344u, s, x;
    AW *p = &g_mem[1];

    /* 预置 mem = acc, 让首轮走相等支(x86 上累加器叫 %eax/%rax, 约束 "a") */
    __asm__ volatile("mov" A32 " %[a],(%[p])"
                     : : [a] "a"(a), [p] "r"(p) : "memory");
    for (i = 0; i < iters; i++)
        __asm__("mov" A32 " %[a],%[s]\n\tadd" A32 " $2,%[s]\n\tcmpxchg" A32 " %[s],(%[p])"
                : [a] "+a"(a), [s] "=&c"(s) : [p] "r"(p) : "cc", "memory");
    __asm__ volatile("mov" A32 " (%[p]),%[x]" : [x] "=r"(x) : [p] "r"(p) : "memory");
    return (uint64_t)a ^ ((uint64_t)x << 16);
}
static uint64_t k_cmpxchg_tp(unsigned long long iters)
{
    unsigned long long i;
    AW a = (AW)0x11223344u, s, x;
    AW *p = &g_mem[1];

    __asm__ volatile("mov" A32 " %[a],(%[p])"
                     : : [a] "a"(a), [p] "r"(p) : "memory");
    for (i = 0; i < iters; i++) {
        __asm__("mov" A32 " %[a],%[s]\n\tadd" A32 " $2,%[s]\n\tcmpxchg" A32 " %[s],(%[p])"
                : [a] "+a"(a), [s] "=&c"(s) : [p] "r"(p) : "cc", "memory");
        __asm__("mov" A32 " %[a],%[s]\n\tadd" A32 " $2,%[s]\n\tcmpxchg" A32 " %[s],(%[p])"
                : [a] "+a"(a), [s] "=&c"(s) : [p] "r"(p) : "cc", "memory");
        __asm__("mov" A32 " %[a],%[s]\n\tadd" A32 " $2,%[s]\n\tcmpxchg" A32 " %[s],(%[p])"
                : [a] "+a"(a), [s] "=&c"(s) : [p] "r"(p) : "cc", "memory");
        __asm__("mov" A32 " %[a],%[s]\n\tadd" A32 " $2,%[s]\n\tcmpxchg" A32 " %[s],(%[p])"
                : [a] "+a"(a), [s] "=&c"(s) : [p] "r"(p) : "cc", "memory");
    }
    __asm__ volatile("mov" A32 " (%[p]),%[x]" : [x] "=r"(x) : [p] "r"(p) : "memory");
    return (uint64_t)a ^ ((uint64_t)x << 16);
}
/* cmpxchg 的 src 不占入值槽(由 i0 反算 = i0+2), 不然六个字段不够用。
 * 探针里预选几组相等输入((kk & 3) == 0) -> 相等/不等两支都有样本。 */
static void k_cmpxchg_kat(int kk, ib_kv *g)
{
    AW a = (AW)IB_KIN8("cmpxchg", kk, 0, AW);
    AW m = (AW)IB_KIN8("cmpxchg", kk, 1, AW);
    AW in0 = a, s, x;
    AW *p;
    uintptr_t fv, fl = 0;

    if ((kk & 3) == 0)
        m = a;
    s = (AW)(a + 2);
    p = kbuf(m);
    fv = (uintptr_t)IB_KFL("cmpxchg", kk);
    __asm__ volatile(IB_SETF "mov" A32 " %[m],(%[p])\n\tcmpxchg" A32 " %[s],(%[p])\n\t"
                     "mov" A32 " (%[p]),%[x]" IB_GETF
                     : [a] "+a"(a), [x] "=&r"(x), [fl] "=&r"(fl)
                     : [m] "r"(m), [s] "c"(s), [p] "r"(p), [fv] "r"(fv)
                     : "cc", "memory");
    g->i0 = in0;  g->i1 = m;   g->inf = fv;
    g->o0 = a;    g->o1 = x;
    g->outf = (uint64_t)fl & IB_FLG_MASK;   /* 算术标志 = SUBTRACT(acc, mem入值) */
}

/* ---------------- lock cmpxchg(与上一形同真值, 差的只是原子序与代价) -------- */
static uint64_t k_lock_cmpxchg(unsigned long long iters)
{
    unsigned long long i;
    AW a = (AW)0x11223344u, s, x;
    AW *p = &g_mem[1];

    __asm__ volatile("mov" A32 " %[a],(%[p])"
                     : : [a] "a"(a), [p] "r"(p) : "memory");
    for (i = 0; i < iters; i++)
        __asm__("mov" A32 " %[a],%[s]\n\tadd" A32 " $2,%[s]\n\tlock cmpxchg" A32 " %[s],(%[p])"
                : [a] "+a"(a), [s] "=&c"(s) : [p] "r"(p) : "cc", "memory");
    __asm__ volatile("mov" A32 " (%[p]),%[x]" : [x] "=r"(x) : [p] "r"(p) : "memory");
    return (uint64_t)a ^ ((uint64_t)x << 16);
}
static uint64_t k_lock_cmpxchg_tp(unsigned long long iters)
{
    unsigned long long i;
    AW a = (AW)0x11223344u, s, x;
    AW *p = &g_mem[1];

    /* lock 形单条就贵两个量级, 定时长每轮只跑 1 条(不展开 4 份) */
    __asm__ volatile("mov" A32 " %[a],(%[p])"
                     : : [a] "a"(a), [p] "r"(p) : "memory");
    for (i = 0; i < iters; i++)
        __asm__("mov" A32 " %[a],%[s]\n\tadd" A32 " $2,%[s]\n\tlock cmpxchg" A32 " %[s],(%[p])"
                : [a] "+a"(a), [s] "=&c"(s) : [p] "r"(p) : "cc", "memory");
    __asm__ volatile("mov" A32 " (%[p]),%[x]" : [x] "=r"(x) : [p] "r"(p) : "memory");
    return (uint64_t)a ^ ((uint64_t)x << 16);
}
static void k_lock_cmpxchg_kat(int kk, ib_kv *g)
{
    AW a = (AW)IB_KIN8("lock_cmpxchg", kk, 0, AW);
    AW m = (AW)IB_KIN8("lock_cmpxchg", kk, 1, AW);
    AW in0 = a, s, x;
    AW *p;
    uintptr_t fv, fl = 0;

    if ((kk & 3) == 0)
        m = a;
    s = (AW)(a + 2);
    p = kbuf(m);
    fv = (uintptr_t)IB_KFL("lock_cmpxchg", kk);
    __asm__ volatile(IB_SETF "mov" A32 " %[m],(%[p])\n\tlock cmpxchg" A32 " %[s],(%[p])\n\t"
                     "mov" A32 " (%[p]),%[x]" IB_GETF
                     : [a] "+a"(a), [x] "=&r"(x), [fl] "=&r"(fl)
                     : [m] "r"(m), [s] "c"(s), [p] "r"(p), [fv] "r"(fv)
                     : "cc", "memory");
    g->i0 = in0;  g->i1 = m;   g->inf = fv;
    g->o0 = a;    g->o1 = x;
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

/* ---------------- xadd 与 lock xadd(零骨架: acc 与内存互为递推) -------------- */
static uint64_t k_xadd(unsigned long long iters)
{
    unsigned long long i;
    AW a = (AW)0x9e3779b9u, x;
    AW *p = &g_mem[1];

    __asm__ volatile("mov" A32 " $0x77,(%[p])" : : [p] "r"(p) : "memory");
    for (i = 0; i < iters; i++)
        __asm__("xadd" A32 " %[a],(%[p])"
                : [a] "+a"(a) : [p] "r"(p) : "cc", "memory");
    __asm__ volatile("mov" A32 " (%[p]),%[x]" : [x] "=r"(x) : [p] "r"(p) : "memory");
    return (uint64_t)a ^ ((uint64_t)x << 16);
}
static uint64_t k_xadd_tp(unsigned long long iters)
{
    unsigned long long i;
    AW a = (AW)0x9e3779b9u, c = (AW)0x243f6a88u, x;
    AW *p = &g_mem[1], *q = &g_mem[3];

    __asm__ volatile("mov" A32 " $0x77,(%[p])\n\tmov" A32 " $0x77,(%[q])"
                     : : [p] "r"(p), [q] "r"(q) : "memory");
    for (i = 0; i < iters; i++) {
        __asm__("xadd" A32 " %[a],(%[p])"
                : [a] "+a"(a) : [p] "r"(p) : "cc", "memory");
        __asm__("xadd" A32 " %[a],(%[p])"
                : [a] "+a"(a) : [p] "r"(p) : "cc", "memory");
        /* 第二条链用 %ecx 做累加器(x86 允许 xadd 的源是任意 GPR) -> 真并发 */
        __asm__("xadd" A32 " %[a],(%[q])"
                : [a] "+c"(c) : [q] "r"(q) : "cc", "memory");
        __asm__("xadd" A32 " %[a],(%[q])"
                : [a] "+c"(c) : [q] "r"(q) : "cc", "memory");
    }
    __asm__ volatile("mov" A32 " (%[p]),%[x]" : [x] "=r"(x) : [p] "r"(p) : "memory");
    return (uint64_t)a ^ ((uint64_t)c << 16) ^ ((uint64_t)x << 32);
}
static void k_xadd_kat(int kk, ib_kv *g)
{
    AW a = (AW)IB_KIN8("xadd", kk, 0, AW);
    AW m = (AW)IB_KIN8("xadd", kk, 1, AW);
    AW in0 = a, in1 = m, x;
    AW *p = kbuf(m);
    uintptr_t fv = (uintptr_t)IB_KFL("xadd", kk), fl = 0;

    __asm__ volatile(IB_SETF "mov" A32 " %[m],(%[p])\n\txadd" A32 " %[a],(%[p])\n\t"
                     "mov" A32 " (%[p]),%[x]" IB_GETF
                     : [a] "+a"(a), [x] "=&r"(x), [fl] "=&r"(fl)
                     : [m] "r"(in1), [p] "r"(p), [fv] "r"(fv) : "cc", "memory");
    g->i0 = in0;  g->i1 = in1;  g->inf = fv;
    g->o0 = a;    g->o1 = x;                /* 期望: o0==i1 且 o1==(i0+i1) */
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}
static uint64_t k_lock_xadd(unsigned long long iters)
{
    unsigned long long i;
    AW a = (AW)0x9e3779b9u, x;
    AW *p = &g_mem[1];

    __asm__ volatile("mov" A32 " $0x77,(%[p])" : : [p] "r"(p) : "memory");
    for (i = 0; i < iters; i++)
        __asm__("lock xadd" A32 " %[a],(%[p])"
                : [a] "+a"(a) : [p] "r"(p) : "cc", "memory");
    __asm__ volatile("mov" A32 " (%[p]),%[x]" : [x] "=r"(x) : [p] "r"(p) : "memory");
    return (uint64_t)a ^ ((uint64_t)x << 16);
}
static uint64_t k_lock_xadd_tp(unsigned long long iters)
{
    unsigned long long i;
    AW a = (AW)0x9e3779b9u, x;
    AW *p = &g_mem[1];

    __asm__ volatile("mov" A32 " $0x77,(%[p])" : : [p] "r"(p) : "memory");
    for (i = 0; i < iters; i++)
        __asm__("lock xadd" A32 " %[a],(%[p])"
                : [a] "+a"(a) : [p] "r"(p) : "cc", "memory");
    __asm__ volatile("mov" A32 " (%[p]),%[x]" : [x] "=r"(x) : [p] "r"(p) : "memory");
    return (uint64_t)a ^ ((uint64_t)x << 16);
}
static void k_lock_xadd_kat(int kk, ib_kv *g)
{
    AW a = (AW)IB_KIN8("lock_xadd", kk, 0, AW);
    AW m = (AW)IB_KIN8("lock_xadd", kk, 1, AW);
    AW in0 = a, in1 = m, x;
    AW *p = kbuf(m);
    uintptr_t fv = (uintptr_t)IB_KFL("lock_xadd", kk), fl = 0;

    __asm__ volatile(IB_SETF "mov" A32 " %[m],(%[p])\n\tlock xadd" A32 " %[a],(%[p])\n\t"
                     "mov" A32 " (%[p]),%[x]" IB_GETF
                     : [a] "+a"(a), [x] "=&r"(x), [fl] "=&r"(fl)
                     : [m] "r"(in1), [p] "r"(p), [fv] "r"(fv) : "cc", "memory");
    g->i0 = in0;  g->i1 = in1;  g->inf = fv;
    g->o0 = a;    g->o1 = x;
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

/* =====================================================================
 * 2) 屏障 mfence / lfence / sfence / pause 与 3) 预取 prefetcht0/t1/t2/nta:
 *    两类都**没有架构结果** -> 只登记定时长(没有可串起来的依赖链, 也不接 KAT;
 *    标志与内存都不变, 签名只能诚实记 0)。三条屏障不合并的理由见文件头注。
 *    预取每轮把地址在 64B 缓冲里按 8B 滑窗(而不是反复预取同一条已热行) ——
 *    后者测的是「prefetch 当空操作」的代价, 与真码里的滑窗预取不是一件事。
 * ===================================================================== */
static uint64_t k_mfence_tp(unsigned long long iters)
{
    unsigned long long i;

    for (i = 0; i < iters; i++)
        __asm__ volatile("mfence" ::: "memory");
    return 0;
}
static uint64_t k_lfence_tp(unsigned long long iters)
{
    unsigned long long i;

    for (i = 0; i < iters; i++)
        __asm__ volatile("lfence" ::: "memory");
    return 0;
}
static uint64_t k_sfence_tp(unsigned long long iters)
{
    unsigned long long i;

    for (i = 0; i < iters; i++)
        __asm__ volatile("sfence" ::: "memory");
    return 0;
}
static uint64_t k_pause_tp(unsigned long long iters)
{
    unsigned long long i;

    for (i = 0; i < iters; i++)
        __asm__ volatile("pause" ::: "memory");
    return 0;
}

static uint64_t k_prefetcht0_tp(unsigned long long iters)
{
    unsigned long long i;
    TW o = (TW)0;
    const void *b = (const void *)g_src;

    for (i = 0; i < iters; i++)
        __asm__ volatile("prefetcht0 (%[b],%[o],1)\n\tadd" I64 " $8,%[o]\n\t"
                         "and" I64 " $56,%[o]"
                         : [o] "+r"(o) : [b] "r"(b) : "memory");
    return (uint64_t)o;
}
static uint64_t k_prefetcht1_tp(unsigned long long iters)
{
    unsigned long long i;
    TW o = (TW)0;
    const void *b = (const void *)g_src;

    for (i = 0; i < iters; i++)
        __asm__ volatile("prefetcht1 (%[b],%[o],1)\n\tadd" I64 " $8,%[o]\n\t"
                         "and" I64 " $56,%[o]"
                         : [o] "+r"(o) : [b] "r"(b) : "memory");
    return (uint64_t)o;
}
static uint64_t k_prefetcht2_tp(unsigned long long iters)
{
    unsigned long long i;
    TW o = (TW)0;
    const void *b = (const void *)g_src;

    for (i = 0; i < iters; i++)
        __asm__ volatile("prefetcht2 (%[b],%[o],1)\n\tadd" I64 " $8,%[o]\n\t"
                         "and" I64 " $56,%[o]"
                         : [o] "+r"(o) : [b] "r"(b) : "memory");
    return (uint64_t)o;
}
static uint64_t k_prefetchnta_tp(unsigned long long iters)
{
    unsigned long long i;
    TW o = (TW)0;
    const void *b = (const void *)g_src;

    for (i = 0; i < iters; i++)
        __asm__ volatile("prefetchnta (%[b],%[o],1)\n\tadd" I64 " $8,%[o]\n\t"
                         "and" I64 " $56,%[o]"
                         : [o] "+r"(o) : [b] "r"(b) : "memory");
    return (uint64_t)o;
}

/* =====================================================================
 * 4) 填充类 nop / nopl 内存形: 有 lat —— 被测夹在「lea(乘 5) + 被测 + add」里,
 *    测解码与前端槽位成本(LATX 把 nop 译成 0 条 -> 这一列正是差异信号)。
 *    gas 事实(实测): AT&T 的 nopl 不收 Intel 那种「内存 + 假目的寄存器」两操作数,
 *    只收单内存操作数; 而 `nopl (%rax)` 生成 0f 1f 00 —— ModRM.reg = 000(正是那
 *    个假目的 %eax), 与反汇编到的多字节 NOP 同族。
 * ===================================================================== */
static uint64_t k_nop(unsigned long long iters)
{
    unsigned long long i;
    TW a = (TW)0x11223344u, b = (TW)0x9e3779b9u;

    for (i = 0; i < iters; i++)
        __asm__("lea (%[a],%[a],4),%[a]\n\tnop\n\tadd %[b],%[a]"
                : [a] "+a"(a) : [b] "r"(b) : "cc", "memory");
    return (uint64_t)a;
}
static uint64_t k_nop_tp(unsigned long long iters)
{
    unsigned long long i;
    TW a = (TW)0x11223344u, c = (TW)0x243f6a88u, b = (TW)0x9e3779b9u;

    for (i = 0; i < iters; i++) {
        __asm__("lea (%[a],%[a],4),%[a]\n\tnop\n\tadd %[b],%[a]"
                : [a] "+a"(a) : [b] "r"(b) : "cc", "memory");
        __asm__("lea (%[a],%[a],4),%[a]\n\tnop\n\tadd %[b],%[a]"
                : [a] "+c"(c) : [b] "r"(b) : "cc", "memory");
    }
    return (uint64_t)a ^ ((uint64_t)c << 16);
}
static uint64_t k_nopl_m(unsigned long long iters)
{
    unsigned long long i;
    TW a = (TW)0x11223344u, b = (TW)0x9e3779b9u;
    const void *p = (const void *)&g_mem[1];

    for (i = 0; i < iters; i++)
        __asm__("lea (%[a],%[a],4),%[a]\n\tnopl (%[p])\n\tadd %[b],%[a]"
                : [a] "+a"(a) : [b] "r"(b), [p] "r"(p) : "cc", "memory");
    return (uint64_t)a;
}
static uint64_t k_nopl_m_tp(unsigned long long iters)
{
    unsigned long long i;
    TW a = (TW)0x11223344u, c = (TW)0x243f6a88u, b = (TW)0x9e3779b9u;
    const void *p = (const void *)&g_mem[1];

    for (i = 0; i < iters; i++) {
        __asm__("lea (%[a],%[a],4),%[a]\n\tnopl (%[p])\n\tadd %[b],%[a]"
                : [a] "+a"(a) : [b] "r"(b), [p] "r"(p) : "cc", "memory");
        __asm__("lea (%[a],%[a],4),%[a]\n\tnopl (%[p])\n\tadd %[b],%[a]"
                : [a] "+c"(c) : [b] "r"(b), [p] "r"(p) : "cc", "memory");
    }
    return (uint64_t)a ^ ((uint64_t)c << 16);
}

/* =====================================================================
 * 5) 串操作 movsb / stosb / cmpsb(单字节三形)。宽度无关的写法靠三个固定寄存
 *    器约束: "S"=%esi/%rsi、"D"=%edi/%rdi -> 本族不需要 #ifdef。
 *    每轮重置指针(不重置就跑出缓冲) -> lat 含骨架 mov, 但「一次完整串 exec」的
 *    入口代价仍是 LATX 的串路径只能在真跑串指令时测到的那一段。DF 恒 0: SysV 与
 *    Windows ABI 都保证进入函数时 DF=0, 且本组没有指令会改 DF。
 *    上表字段语义(审计端按同一规则反算): i0 = 源侧 8 字节, i1 = 目的侧 8 字节
 *    (执行前), o0 = 目的侧 8 字节(执行后), o1 = 指针推进量(=1)。
 * ===================================================================== */
static uint64_t k_movsb(unsigned long long iters)
{
    unsigned long long i;

    for (i = 0; i < iters; i++) {
        const void *s = (const void *)&g_src[0];
        void *d = (void *)&g_dst[0];
        __asm__ volatile("movsb" : "+S"(s), "+D"(d) : : "memory");
    }
    return g_dst[0] & 0xffu;
}
static uint64_t k_movsb_tp(unsigned long long iters)
{
    unsigned long long i;
    const void *s;
    void *d;

    for (i = 0; i < iters; i++) {
        s = (const void *)&g_src[0];  d = (void *)&g_dst[0];
        __asm__ volatile("movsb" : "+S"(s), "+D"(d) : : "memory");
        __asm__ volatile("movsb" : "+S"(s), "+D"(d) : : "memory");
        __asm__ volatile("movsb" : "+S"(s), "+D"(d) : : "memory");
        __asm__ volatile("movsb" : "+S"(s), "+D"(d) : : "memory");
    }
    return (g_dst[0] >> 24) & 0xffu;
}
static void k_movsb_kat(int kk, ib_kv *g)
{
    uint64_t src, dst0;
    const void *s;
    void *d;
    uintptr_t fv = (uintptr_t)IB_KFL("movsb", kk), fl = 0;

    *(volatile uint64_t *)&g_src[0] = IB_KIN("movsb", kk, 0);
    *(volatile uint64_t *)&g_dst[0] = IB_KIN("movsb", kk, 1);
    src = g_src[0];  dst0 = g_dst[0];
    s = (const void *)&g_src[0];
    d = (void *)&g_dst[0];
    __asm__ volatile(IB_SETF "movsb" IB_GETF
                     : "+S"(s), "+D"(d), [fl] "=&r"(fl)
                     : [fv] "r"(fv) : "cc", "memory");
    g->i0 = src;  g->i1 = dst0;  g->inf = fv;
    g->o0 = g_dst[0];                       /* 期望: 低字节换成 i0 低字节, 高字节保持 */
    g->o1 = 1;
    g->outf = (uint64_t)fl & IB_FLG_MASK;   /* mov 类不改标志 -> outf == inf */
}

static uint64_t k_stosb(unsigned long long iters)
{
    unsigned long long i;
    unsigned char v = (unsigned char)0x5au;

    for (i = 0; i < iters; i++) {
        void *d = (void *)&g_dst[0];
        __asm__ volatile("stosb" : "+D"(d) : "a"(v) : "memory");
    }
    return g_dst[0] & 0xffu;
}
static uint64_t k_stosb_tp(unsigned long long iters)
{
    unsigned long long i;
    unsigned char v = (unsigned char)0x5au;
    void *d;

    for (i = 0; i < iters; i++) {
        d = (void *)&g_dst[0];
        __asm__ volatile("stosb" : "+D"(d) : "a"(v) : "memory");
        __asm__ volatile("stosb" : "+D"(d) : "a"(v) : "memory");
        __asm__ volatile("stosb" : "+D"(d) : "a"(v) : "memory");
        __asm__ volatile("stosb" : "+D"(d) : "a"(v) : "memory");
    }
    return (g_dst[0] >> 24) & 0xffu;
}
static void k_stosb_kat(int kk, ib_kv *g)
{
    uint64_t dst0;
    void *d;
    unsigned char v = (unsigned char)IB_KIN8("stosb", kk, 0, unsigned char);
    uintptr_t fv = (uintptr_t)IB_KFL("stosb", kk), fl = 0;

    *(volatile uint64_t *)&g_dst[0] = IB_KIN("stosb", kk, 1);
    dst0 = g_dst[0];
    d = (void *)&g_dst[0];
    __asm__ volatile(IB_SETF "stosb" IB_GETF
                     : "+D"(d), [fl] "=&r"(fl) : "a"(v), [fv] "r"(fv)
                     : "cc", "memory");
    g->i0 = v;      g->i1 = dst0;  g->inf = fv;
    g->o0 = g_dst[0];                       /* 期望: 低字节 == i0, 高字节保持 */
    g->o1 = 1;
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

static uint64_t k_cmpsb(unsigned long long iters)
{
    unsigned long long i;
    uintptr_t fl = 0;

    for (i = 0; i < iters; i++) {
        const void *s = (const void *)&g_src[0];
        void *d = (void *)&g_dst[0];
        __asm__ volatile("cmpsb" IB_GETF
                         : "+S"(s), "+D"(d), [fl] "=&r"(fl) : : "cc", "memory");
    }
    return (uint64_t)fl & IB_FLG_MASK;
}
static uint64_t k_cmpsb_tp(unsigned long long iters)
{
    unsigned long long i;
    uintptr_t fl = 0;

    for (i = 0; i < iters; i++) {
        const void *s = (const void *)&g_src[0];
        void *d = (void *)&g_dst[0];
        __asm__ volatile("cmpsb" IB_GETF
                         : "+S"(s), "+D"(d), [fl] "=&r"(fl) : : "cc", "memory");
        __asm__ volatile("cmpsb" IB_GETF
                         : "+S"(s), "+D"(d), [fl] "=&r"(fl) : : "cc", "memory");
        __asm__ volatile("cmpsb" IB_GETF
                         : "+S"(s), "+D"(d), [fl] "=&r"(fl) : : "cc", "memory");
        __asm__ volatile("cmpsb" IB_GETF
                         : "+S"(s), "+D"(d), [fl] "=&r"(fl) : : "cc", "memory");
    }
    return (uint64_t)fl & IB_FLG_MASK;
}
static void k_cmpsb_kat(int kk, ib_kv *g)
{
    uint64_t src, dst0;
    const void *s;
    void *d;
    uintptr_t fv = (uintptr_t)IB_KFL("cmpsb", kk), fl = 0;

    *(volatile uint64_t *)&g_src[0] = IB_KIN("cmpsb", kk, 0);
    *(volatile uint64_t *)&g_dst[0] = IB_KIN("cmpsb", kk, 1);
    src = g_src[0];  dst0 = g_dst[0];
    s = (const void *)&g_src[0];
    d = (void *)&g_dst[0];
    /* cmpsb 只产标志不写结果 -> 真值全在 outf(单字节无符号比较 = SUBTRACT 标志) */
    __asm__ volatile(IB_SETF "cmpsb" IB_GETF
                     : "+S"(s), "+D"(d), [fl] "=&r"(fl)
                     : [fv] "r"(fv) : "cc", "memory");
    g->i0 = src;  g->i1 = dst0;  g->inf = fv;
    g->o0 = 0;    g->o1 = 1;
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

/* ---------------- rep movsb / rep stosb(计数 8 字节) -------------------
 * 这一对才是 LATX 里真正的 REP 宏展开路径(单次 exec 要跑完 8 个字节), 也是
 * 整组里单条代价最高的两条 -> lat 含 3 条骨架 mov(重置 rsi/rdi/rcx)。
 * tput 用四个互不相干的内存槽(同一条 rep 挨个跑同一槽会串行)。 ------------- */
static uint64_t k_rep_movsb(unsigned long long iters)
{
    unsigned long long i;

    for (i = 0; i < iters; i++) {
        const void *s = (const void *)&g_src[0];
        void *d = (void *)&g_dst[0];
        unsigned long n = 8;
        __asm__ volatile("rep movsb" : "+S"(s), "+D"(d), "+c"(n) : : "memory");
    }
    return g_dst[0];
}
static uint64_t k_rep_movsb_tp(unsigned long long iters)
{
    unsigned long long i;

    for (i = 0; i < iters; i++) {
        const void *s = (const void *)&g_src[0];
        void *d = (void *)&g_dst[0];
        unsigned long n = 8;
        __asm__ volatile("rep movsb" : "+S"(s), "+D"(d), "+c"(n) : : "memory");
        d = (void *)&g_dst[1];
        __asm__ volatile("rep movsb" : "+S"(s), "+D"(d), "+c"(n) : : "memory");
        d = (void *)&g_dst[2];
        __asm__ volatile("rep movsb" : "+S"(s), "+D"(d), "+c"(n) : : "memory");
        d = (void *)&g_dst[3];
        __asm__ volatile("rep movsb" : "+S"(s), "+D"(d), "+c"(n) : : "memory");
    }
    return g_dst[0] ^ g_dst[3];
}
static void k_rep_movsb_kat(int kk, ib_kv *g)
{
    uint64_t src, dst0, left;
    const void *s;
    void *d;
    unsigned long n = 8;
    uintptr_t fv = (uintptr_t)IB_KFL("rep_movsb", kk), fl = 0;

    *(volatile uint64_t *)&g_src[0] = IB_KIN("rep_movsb", kk, 0);
    *(volatile uint64_t *)&g_dst[0] = IB_KIN("rep_movsb", kk, 1);
    src = g_src[0];  dst0 = g_dst[0];
    s = (const void *)&g_src[0];
    d = (void *)&g_dst[0];
    __asm__ volatile(IB_SETF "rep movsb" IB_GETF
                     : "+S"(s), "+D"(d), "+c"(n), [fl] "=&r"(fl)
                     : [fv] "r"(fv) : "cc", "memory");
    left = (uint64_t)n;
    g->i0 = src;  g->i1 = dst0;  g->inf = fv;
    g->o0 = g_dst[0];                       /* 期望: o0 == i0 且 o1 == 0 */
    g->o1 = left;
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

static uint64_t k_rep_stosb(unsigned long long iters)
{
    unsigned long long i;
    unsigned char v = (unsigned char)0x5au;

    for (i = 0; i < iters; i++) {
        void *d = (void *)&g_dst[0];
        unsigned long n = 8;
        __asm__ volatile("rep stosb" : "+D"(d), "+c"(n) : "a"(v) : "memory");
    }
    return g_dst[0];
}
static uint64_t k_rep_stosb_tp(unsigned long long iters)
{
    unsigned long long i;
    unsigned char v = (unsigned char)0x5au;

    for (i = 0; i < iters; i++) {
        void *d = (void *)&g_dst[0];
        unsigned long n = 8;
        __asm__ volatile("rep stosb" : "+D"(d), "+c"(n) : "a"(v) : "memory");
        d = (void *)&g_dst[1];
        __asm__ volatile("rep stosb" : "+D"(d), "+c"(n) : "a"(v) : "memory");
        d = (void *)&g_dst[2];
        __asm__ volatile("rep stosb" : "+D"(d), "+c"(n) : "a"(v) : "memory");
        d = (void *)&g_dst[3];
        __asm__ volatile("rep stosb" : "+D"(d), "+c"(n) : "a"(v) : "memory");
    }
    return g_dst[0] ^ g_dst[3];
}
static void k_rep_stosb_kat(int kk, ib_kv *g)
{
    uint64_t dst0, left;
    void *d;
    unsigned long n = 8;
    unsigned char v = (unsigned char)IB_KIN8("rep_stosb", kk, 0, unsigned char);
    uintptr_t fv = (uintptr_t)IB_KFL("rep_stosb", kk), fl = 0;

    *(volatile uint64_t *)&g_dst[0] = IB_KIN("rep_stosb", kk, 1);
    dst0 = g_dst[0];
    d = (void *)&g_dst[0];
    __asm__ volatile(IB_SETF "rep stosb" IB_GETF
                     : "+D"(d), "+c"(n), [fl] "=&r"(fl)
                     : "a"(v), [fv] "r"(fv) : "cc", "memory");
    left = (uint64_t)n;
    g->i0 = v;    g->i1 = dst0;  g->inf = fv;
    g->o0 = g_dst[0];                       /* 期望: o0 == i0 广播到 8 字节 */
    g->o1 = left;
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

/* ---------------- 用例表(声明式, 一行一 case; 字段序 = ib_case) ----------------
 * 预取/屏障无架构结果 -> lat 填 NULL、不接 KAT; 其余各形都接。bpop/b8 本次全空
 * (只做单指令 + 定时长)。lits = 0 = 不另设上限(rep 两形单 exec 只跑 8 字节,
 * 默认 2000 次迭代的窗口内能跑完; 将来把计数提到 KB 级要记得给小值)。 */
static const ib_case g_cases[] = {
    { "x86_xchg_r", NULL, k_xchg_r, k_xchg_r_tp, 0, NULL, 0, NULL, 0,
      k_xchg_r_kat, IB_KAT_xchg_r, "xchg_r" },
    { "x86_xchg_m", NULL, k_xchg_m, k_xchg_m_tp, 0, NULL, 0, NULL, 0,
      k_xchg_m_kat, IB_KAT_xchg_m, "xchg_m" },
    { "x86_cmpxchg", NULL, k_cmpxchg, k_cmpxchg_tp, 0, NULL, 0, NULL, 0,
      k_cmpxchg_kat, IB_KAT_cmpxchg, "cmpxchg" },
    { "x86_lock_cmpxchg", NULL, k_lock_cmpxchg, k_lock_cmpxchg_tp, 0, NULL, 0,
      NULL, 0, k_lock_cmpxchg_kat, IB_KAT_lock_cmpxchg, "lock_cmpxchg" },
    { "x86_xadd", NULL, k_xadd, k_xadd_tp, 0, NULL, 0, NULL, 0,
      k_xadd_kat, IB_KAT_xadd, "xadd" },
    { "x86_lock_xadd", NULL, k_lock_xadd, k_lock_xadd_tp, 0, NULL, 0, NULL, 0,
      k_lock_xadd_kat, IB_KAT_lock_xadd, "lock_xadd" },
    { "x86_movsb", NULL, k_movsb, k_movsb_tp, 0, NULL, 0, NULL, 0,
      k_movsb_kat, IB_KAT_movsb, "movsb" },
    { "x86_stosb", NULL, k_stosb, k_stosb_tp, 0, NULL, 0, NULL, 0,
      k_stosb_kat, IB_KAT_stosb, "stosb" },
    { "x86_cmpsb", NULL, k_cmpsb, k_cmpsb_tp, 0, NULL, 0, NULL, 0,
      k_cmpsb_kat, IB_KAT_cmpsb, "cmpsb" },
    { "x86_rep_movsb", NULL, k_rep_movsb, k_rep_movsb_tp, 0, NULL, 0, NULL, 0,
      k_rep_movsb_kat, IB_KAT_rep_movsb, "rep_movsb" },
    { "x86_rep_stosb", NULL, k_rep_stosb, k_rep_stosb_tp, 0, NULL, 0, NULL, 0,
      k_rep_stosb_kat, IB_KAT_rep_stosb, "rep_stosb" },
    { "x86_nop", NULL, k_nop, k_nop_tp, 0 },
    { "x86_nopl_m", NULL, k_nopl_m, k_nopl_m_tp, 0 },
    { "x86_mfence", NULL, NULL, k_mfence_tp, 0 },
    { "x86_lfence", NULL, NULL, k_lfence_tp, 0 },
    { "x86_sfence", NULL, NULL, k_sfence_tp, 0 },
    { "x86_pause", NULL, NULL, k_pause_tp, 0 },
    { "x86_prefetcht0", NULL, NULL, k_prefetcht0_tp, 0 },
    { "x86_prefetcht1", NULL, NULL, k_prefetcht1_tp, 0 },
    { "x86_prefetcht2", NULL, NULL, k_prefetcht2_tp, 0 },
    { "x86_prefetchnta", NULL, NULL, k_prefetchnta_tp, 0 },
};
#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

int main(int argc, char **argv)
{
    volatile uint64_t *vd = (volatile uint64_t *)g_dst;
    volatile uint64_t *vs = (volatile uint64_t *)g_src;
    volatile AW *vm = (volatile AW *)g_mem;
    int i;

    /* 经 volatile 指针填缓冲: 内容对编译器不可知, 不会把被测指令当常数折叠掉 */
    for (i = 0; i < 8; i++) {
        vm[i] = (AW)((uint64_t)(i * 13 + 7) * 0x9e3779b9u);
        vs[i] = (uint64_t)(i * 31 + 11) * 0x2545f491u;
        vd[i] = (uint64_t)(i * 17 + 3) * 0x85ebca6bu;
    }
    ib_init(argc, argv);
    ib_hdr("special", NCASES);
    /* 不回传 ib_run_cases 的返回值: 它返回的是「全绿用例数」(迁出 x87 后本组即
     * 21 = NCASES, 实机实测 x86_64-linux 与 i386 两侧均 ok=21/total=21), 而
     * isbench.py 与 gen_val.sh 都按 rc!=0 判整组失败并丢弃输出。口径与其余各组
     * 一致 —— 成败看 T 行的 status/kat_st/CRASH 列, 不看进程退出码。 */
    ib_run_cases("special", g_cases, NCASES);
    return 0;
}
