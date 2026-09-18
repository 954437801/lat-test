#include "ib_core.h"
#include "ib_buf.h"
#include "isb_x87_kat.h"
#include "isb_x87.h"

void k_fild_fistp_q_rt_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    const void *s = fput(0, xq(kk));
    void *d = fput(8, IB_POISON);
    uintptr_t fv = (uintptr_t)IB_KFL("fild_fistp_q_rt", kk), fl = 0;

    __asm__ volatile(IB_SETF
                     "fildll (%[s])\n\tfistpll (%[d])\n\tfnstsw (%[w])\n\t"
                     IB_GETF
                     : [fl] "=&r"(fl)
                     : [s] "r"(s), [d] "r"(d), [w] "r"(&g_sw[0]), [fv] "r"(fv)
                     : "cc", "memory");
    g->i0 = xq(kk);   g->i1 = 0;   g->inf = fv;
    g->o0 = fget(8);                        /* 期望 == i0(逐位) */
    g->o1 = swget();                          /* 期望 0: 无异常且 TOP 已回 0 */
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fild_fistp_d_rt_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    uint64_t raw;
    const void *s = fput(0, xd(kk));
    void *d = fput(8, IB_POISON);
    uintptr_t fv = (uintptr_t)IB_KFL("fild_fistp_d_rt", kk), fl = 0;

    __asm__ volatile(IB_SETF
                     "fildl (%[s])\n\tfistpl (%[d])\n\t"
                     IB_GETF
                     : [fl] "=&r"(fl)
                     : [s] "r"(s), [d] "r"(d), [fv] "r"(fv) : "cc", "memory");
    raw = fget(8);
    g->i0 = xd(kk);   g->i1 = 0;   g->inf = fv;
    g->o0 = (uint64_t)(int64_t)(int32_t)(uint32_t)raw;   /* 低 4 字节按 int32 读回 */
    g->o1 = ((raw & 0xffffffff00000000ULL) ==
             (IB_POISON & 0xffffffff00000000ULL)) ? 1 : 0;
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fild_fistp_w_rt_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    uint64_t raw;
    const void *s = fput(0, xw(kk));
    void *d = fput(8, IB_POISON);
    uintptr_t fv = (uintptr_t)IB_KFL("fild_fistp_w_rt", kk), fl = 0;

    __asm__ volatile(IB_SETF
                     "filds (%[s])\n\tfistps (%[d])\n\t"
                     IB_GETF
                     : [fl] "=&r"(fl)
                     : [s] "r"(s), [d] "r"(d), [fv] "r"(fv) : "cc", "memory");
    raw = fget(8);
    g->i0 = xw(kk);   g->i1 = 0;   g->inf = fv;
    g->o0 = (uint64_t)(int64_t)(int16_t)(uint16_t)raw;
    g->o1 = ((raw & 0xffffffffffff0000ULL) ==
             (IB_POISON & 0xffffffffffff0000ULL)) ? 1 : 0;
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fild_fistp_q_neg_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    uint64_t v = (uint64_t)0 - xq(kk);
    const void *s = fput(0, v);
    void *d = fput(8, IB_POISON);
    uintptr_t fv = (uintptr_t)IB_KFL("fild_fistp_q_neg", kk), fl = 0;

    __asm__ volatile(IB_SETF
                     "fildll (%[s])\n\tfistpll (%[d])\n\tfnstsw (%[w])\n\t"
                     IB_GETF
                     : [fl] "=&r"(fl)
                     : [s] "r"(s), [d] "r"(d), [w] "r"(&g_sw[0]), [fv] "r"(fv)
                     : "cc", "memory");
    g->i0 = v;   g->i1 = 0;   g->inf = fv;
    g->o0 = fget(8);
    g->o1 = swget();
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fild_q_odd_rt_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    uint64_t v = xq(kk) | 1ULL;
    const void *s = fput(0, v);
    void *d = fput(8, IB_POISON);
    uintptr_t fv = (uintptr_t)IB_KFL("fild_q_odd_rt", kk), fl = 0;

    __asm__ volatile(IB_SETF
                     "fildll (%[s])\n\tfistpll (%[d])\n\tfnstsw (%[w])\n\t"
                     IB_GETF
                     : [fl] "=&r"(fl)
                     : [s] "r"(s), [d] "r"(d), [w] "r"(&g_sw[0]), [fv] "r"(fv)
                     : "cc", "memory");
    g->i0 = v;   g->i1 = 0;   g->inf = fv;
    g->o0 = fget(8);
    g->o1 = swget();
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fild_fstp_q_dbl_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    const void *s = fput(0, xq(kk));
    void *d = fput(8, IB_POISON);
    uintptr_t fv = (uintptr_t)IB_KFL("fild_fstp_q_dbl", kk), fl = 0;

    __asm__ volatile(IB_SETF
                     "fildll (%[s])\n\tfstpl (%[d])\n\tfnstsw (%[w])\n\t"
                     IB_GETF
                     : [fl] "=&r"(fl)
                     : [s] "r"(s), [d] "r"(d), [w] "r"(&g_sw[0]), [fv] "r"(fv)
                     : "cc", "memory");
    g->i0 = xq(kk);   g->i1 = 0;   g->inf = fv;
    g->o0 = fget(8);                          /* 期望 dbl_rt(i0) */
    g->o1 = swget();
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fild_fstp_t_ext_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    void *d = tput80(0, 0, 0);
    const void *s = fput(0, xq(kk));
    uintptr_t fv = (uintptr_t)IB_KFL("fild_fstp_t_ext", kk), fl = 0;

    __asm__ volatile(IB_SETF
                     "fildll (%[s])\n\tfstpt (%[d])\n\t"
                     IB_GETF
                     : [fl] "=&r"(fl)
                     : [s] "r"(s), [d] "r"(d), [fv] "r"(fv) : "cc", "memory");
    g->i0 = xq(kk);   g->i1 = 0;   g->inf = fv;
    g->o0 = tget_m(0);   g->o1 = tget_s(0);   /* 期望 ext_form(i0) */
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fistp_q_indef_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    const void *s = fput(0, IVEC[kk]);
    void *d = fput(8, IB_POISON);
    uintptr_t fv = (uintptr_t)IB_KFL("fistp_q_indef", kk), fl = 0;

    __asm__ volatile(IB_SETF
                     "fldl (%[s])\n\tfistpll (%[d])\n\tfnstsw (%[w])\n\t"
                     IB_GETF
                     : [fl] "=&r"(fl)
                     : [s] "r"(s), [d] "r"(d), [w] "r"(&g_sw[0]), [fv] "r"(fv)
                     : "cc", "memory");
    g->i0 = IVEC[kk];   g->i1 = 0;   g->inf = fv;
    g->o0 = fget(8);   g->o1 = swget();
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fisttp_q_rt_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    const void *s = fput(0, xq(kk));
    void *d = fput(8, IB_POISON);
    uintptr_t fv = (uintptr_t)IB_KFL("fisttp_q_rt", kk), fl = 0;

    __asm__ volatile(IB_SETF
                     "fildll (%[s])\n\tfisttpll (%[d])\n\tfnstsw (%[w])\n\t"
                     IB_GETF
                     : [fl] "=&r"(fl)
                     : [s] "r"(s), [d] "r"(d), [w] "r"(&g_sw[0]), [fv] "r"(fv)
                     : "cc", "memory");
    g->i0 = xq(kk);   g->i1 = 0;   g->inf = fv;
    g->o0 = fget(8);
    g->o1 = swget();
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fld_t_fstp_t_rt_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    uint64_t m;
    uint16_t se;
    const void *s;
    void *d = tput80(1, 0, 0);
    uintptr_t fv = (uintptr_t)IB_KFL("fld_t_fstp_t_rt", kk), fl = 0;

    ext_form(xq(kk), &m, &se);
    s = tput80(0, m, se);
    __asm__ volatile(IB_SETF
                     "fldt (%[s])\n\tfstpt (%[d])\n\t"
                     IB_GETF
                     : [fl] "=&r"(fl)
                     : [s] "r"(s), [d] "r"(d), [fv] "r"(fv) : "cc", "memory");
    g->i0 = m;   g->i1 = se;   g->inf = fv;
    g->o0 = tget_m(1);   g->o1 = tget_s(1);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fbld_fistp_q_rt_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    int neg = (kk & 4) ? 1 : 0;
    uint64_t v = neg ? ((uint64_t)0 - BVEC[kk]) : BVEC[kk];
    const void *s = bput(BVEC[kk], neg);
    void *d = fput(8, IB_POISON);
    uintptr_t fv = (uintptr_t)IB_KFL("fbld_fistp_q_rt", kk), fl = 0;

    __asm__ volatile(IB_SETF
                     "fbld (%[s])\n\tfistpll (%[d])\n\tfnstsw (%[w])\n\t"
                     IB_GETF
                     : [fl] "=&r"(fl)
                     : [s] "r"(s), [d] "r"(d), [w] "r"(&g_sw[0]), [fv] "r"(fv)
                     : "cc", "memory");
    g->i0 = v;   g->i1 = (uint64_t)neg;   g->inf = fv;
    g->o0 = fget(8);
    g->o1 = swget();
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fild_fistp_q_x8_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    int j;
    uint64_t inv = 0, outv = 0, mask = 0;
    uintptr_t fv = (uintptr_t)IB_KFL("fild_fistp_q_x8", kk), fl = 0;

    for (j = 0; j < IB_KAT_N; j++) {
        fput(j, XVEC[j]);
        fput(8 + j, IB_POISON);
        inv ^= XVEC[j];
    }
    for (j = 0; j < IB_KAT_N; j++)
        __asm__ volatile(IB_SETF
                         "fildll (%[s])\n\tfistpll (%[d])\n\t"
                         IB_GETF
                         : [fl] "=&r"(fl)
                         : [s] "r"((const void *)&g_f[j]),
                           [d] "r"((void *)&g_f[8 + j]), [fv] "r"(fv)
                         : "cc", "memory");
    for (j = 0; j < IB_KAT_N; j++) {
        uint64_t r = fget(8 + j);

        outv ^= r;
        if (r == XVEC[j])
            mask |= 1ULL << j;
    }
    g->i0 = inv;   g->i1 = 0xff;   g->inf = fv;
    g->o0 = outv;   g->o1 = mask;                       /* 期望 o0==i0, o1==0xff */
    g->outf = (uint64_t)fl & IB_FLG_MASK;               /* 取最后一组的标志 */
}

void k_rc_fstcw_rt_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    unsigned enc_f = (unsigned)(kk & 3);
    /* enc_t 与 enc_f 恒不等, 且 kk 0-3 走 +1、kk 4-7 走 +2 -> 单 bit 变(0x400)与
     * 双 bit 变(0x800/0xC00)三种异或形状全覆盖(0..3 共 12 个有序对, 8 行取不到的
     * 4 对是同一形状的重复, 不补)。 */
    unsigned enc_t = (unsigned)((enc_f + 1 + (kk >> 2)) & 3);
    uintptr_t fv = (uintptr_t)IB_KFL("rc_fstcw_rt", kk), fl = 0;

    g_cw[2] = RC_CW(enc_f);
    __asm__ volatile(IB_SETF "fldcw (%[wt])\n\tfnstcw (%[sv])\n\t" IB_GETF
                     : [fl] "=&r"(fl)
                     : [wt] "r"(&g_cw[2]), [sv] "r"(&g_cw[0]), [fv] "r"(fv)
                     : "cc", "memory");
    /* 第二个控制字**从硬件读回的那个子改**(sv & ~0x0C00 | enc_t<<10), 不写常数:
     * 写常数就等于把"其余 14 位不许动"这条断言预先假设成事实。 */
    g_cw[2] = (uint16_t)((cwget(0) & (uint16_t)~0x0C00u) | (uint16_t)(enc_t << 10));
    __asm__ volatile(IB_SETF "fldcw (%[wt])\n\tfnstcw (%[rb])\n\t" IB_GETF
                     : [fl] "=&r"(fl)
                     : [wt] "r"(&g_cw[2]), [rb] "r"(&g_cw[1]), [fv] "r"(fv)
                     : "cc", "memory");
    g->i0 = enc_f;   g->i1 = enc_t;   g->inf = fv;
    g->o0 = (uint64_t)(cwget(0) ^ cwget(1));
    g->o1 = (uint64_t)cwget(1);
    g->outf = (uint64_t)fl & IB_FLG_MASK;     /* 取最后一段的标志(与 q_x8 同口径) */
}

void k_fld_fstp_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    const void *s = fput(0, qv("fld_fstp", kk, 0));
    void *d = (void *)&g_f[2];
    uintptr_t fv = (uintptr_t)IB_KFL("fld_fstp", kk), fl = 0;

    __asm__ volatile(IB_SETF "fldl (%[s])\n\tfstpl (%[d])" IB_GETF
                     : [fl] "=&r"(fl) : [s] "r"(s), [d] "r"(d), [fv] "r"(fv)
                     : "cc", "memory");
    g->i0 = x87n("fld_fstp", kk, 0);   g->i1 = 0;    g->inf = fv;
    g->o0 = fget(2);    g->o1 = 0;                  /* 期望: o0 == i0 的 n/4 位形 */
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fadd_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    const void *a = fput(0, qv("fadd", kk, 0));
    const void *b = fput(1, qv("fadd", kk, 1));
    void *r = (void *)&g_f[2];
    uintptr_t fv = (uintptr_t)IB_KFL("fadd", kk), fl = 0;

    __asm__ volatile(IB_SETF "fldl (%[a])\n\tfaddl (%[b])\n\tfstpl (%[r])" IB_GETF
                     : [fl] "=&r"(fl)
                     : [a] "r"(a), [b] "r"(b), [r] "r"(r), [fv] "r"(fv)
                     : "cc", "memory");
    g->i0 = x87n("fadd", kk, 0);   g->i1 = x87n("fadd", kk, 1);  g->inf = fv;
    g->o0 = fget(2);   g->o1 = 0;            /* 期望: o0 == 位形((i0+i1)/4) */
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fmul_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    const void *a = fput(0, qv("fmul", kk, 0));
    const void *b = fput(1, qv("fmul", kk, 1));
    void *r = (void *)&g_f[2];
    uintptr_t fv = (uintptr_t)IB_KFL("fmul", kk), fl = 0;

    __asm__ volatile(IB_SETF "fldl (%[a])\n\tfmull (%[b])\n\tfstpl (%[r])" IB_GETF
                     : [fl] "=&r"(fl)
                     : [a] "r"(a), [b] "r"(b), [r] "r"(r), [fv] "r"(fv)
                     : "cc", "memory");
    g->i0 = x87n("fmul", kk, 0);   g->i1 = x87n("fmul", kk, 1);  g->inf = fv;
    g->o0 = fget(2);   g->o1 = 0;            /* 期望: o0 == 位形((i0*i1)/16) */
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fistp_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    const void *s = fput(0, qv("fistp", kk, 0));
    void *d = (void *)&g_f[2];
    uintptr_t fv = (uintptr_t)IB_KFL("fistp", kk), fl = 0;

    __asm__ volatile(IB_SETF "fldl (%[s])\n\tfistpll (%[d])" IB_GETF
                     : [fl] "=&r"(fl) : [s] "r"(s), [d] "r"(d), [fv] "r"(fv)
                     : "cc", "memory");
    g->i0 = x87n("fistp", kk, 0);   g->i1 = 0;   g->inf = fv;
    g->o0 = (uint64_t)(int64_t)fget(2);   g->o1 = 0;   /* 期望: 就近取偶(i0/4) */
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fcomip_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    uint64_t n0 = x87n("fcomip", kk, 0), n1 = x87n("fcomip", kk, 1);
    const void *a;
    const void *b;
    void *d = (void *)&g_f[2];
    uintptr_t fv, fl = 0;

    if ((kk & 3) == 0)
        n1 = n0;                            /* 抽几组相等输入, 把 ZF=1 那支也采到 */
    a = fput(0, qbits(n0));
    b = fput(1, qbits(n1));
    fv = (uintptr_t)IB_KFL("fcomip", kk);
    __asm__ volatile(IB_SETF "fldl (%[a])\n\tfldl (%[b])\n\tfcomip %%st(1),%%st\n\t"
                     "fstpl (%[d])" IB_GETF
                     : [fl] "=&r"(fl)
                     : [a] "r"(a), [b] "r"(b), [d] "r"(d), [fv] "r"(fv)
                     : "cc", "memory");
    g->i0 = n0;   g->i1 = n1;   g->inf = fv;
    g->o0 = 0;    g->o1 = 0;
    g->outf = (uint64_t)fl & IB_FLG_MASK_FCOM;
}

void k_fcw_rt_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    /* save/back/want 一律走全局槽 g_cw[]: 本探针没有调用 -> 是叶子函数, GCC 会把
     * 按地址逃逸的局部量放进红区(-0x2..-0x8(%rsp)), 而 IB_SETF/IB_GETF 里的
     * pushq/pushfq 写的正好是 [rsp-8] —— 实测那三个局部量被整个踩成 push 进去的
     * 值, 表里 i0/o0 都是 0(反汇编 _tmp/x87n.sh, 复现 _tmp/x87o.sh)。全局槽不在
     * 栈上, 结构上免疫; 并且上表的顺序也改成「先写输入、 asm 后只读全局与寄存器
     * 输出」, 不在 asm 两边留任何必须存活却位于栈上的值。 */
    uint16_t *p_sv = &g_cw[0], *p_bk = &g_cw[2], *p_wt = &g_cw[4];
    /* 只动两个架构字段: RC 与 PC。位段按取证 g1/g2 的双机实测定(**不是** SDM 书里
     * 常被抄错的写法): RC = 位 10-11(四档全走), PC = 位 8-9(取 53/64 两档, 不碰
     * 保留编码 01b)。本条旧版这里写的是"RC(位 2-3)", 那是错的 —— 但当时它照样过,
     * 因为本条只断言"写下去的 16 位原样读回": 位 2-3 是异常屏蔽位、也可写可读,
     * 所以位序写错不会响。改到真位段之后, 这条才顺带把"RC 两位写下去存不存得住"
     * 钉住(P2 的 rc_fstcw_rt 靠这个前提才能只断言"仅 RC 两位变")。
     * 为什么不用 0x02ff/0x03ff 这种"低 8 位全 1"的方便值: 实测 `fldcw(0x02ff)` 后
     * `fnstcw` 读回的是 0x027f —— 位 7 是保留位, 硬件强制刷 0(另外位 6 恒 1、位
     * 13-15 恒 0, 见取证 g3)。拿被强制的字段做输入, "读回 == 写入"在任何 x87 上
     * 都不是可保证的期望, 表也就失去跨机可比的意义。 */
    uint16_t want = (uint16_t)(0x0073u | ((kk & 3) << 10) | ((kk & 4) ? 0x0300u : 0x0200u));
    uintptr_t fv = (uintptr_t)IB_KFL("fcw_rt", kk), fl = 0;

    *p_wt = want;
    *p_bk = 0;
    g->i0 = want;   g->i1 = 0;   g->inf = fv;   /* 输入先上表(全在栈外) */
    __asm__ volatile(IB_SETF
                     "fnstcw (%[sv])\n\t"
                     "fldcw (%[wt])\n\t"
                     "fnstcw (%[bk])\n\t"
                     "fldcw (%[sv])\n\t"
                     IB_GETF
                     : [fl] "=&r"(fl)
                     : [sv] "r"(p_sv), [wt] "r"(p_wt), [bk] "r"(p_bk), [fv] "r"(fv)
                     : "cc", "memory");
    g->o0 = *p_bk;  g->o1 = 0;   /* 期望: o0 == i0(写入的字段全合法, 应原样读回) */
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_stack_top_after_fild_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    int n = kk + 1;                     /* 压栈次数 1..8 */
    int j;
    uint16_t peak;
    uintptr_t fl = 0;
    const void *s = fput(0, xq(kk));
    void *d = fput(8, IB_POISON);
    uintptr_t fv = (uintptr_t)IB_KFL("stack_top_after_fild", kk);

    /* 每一次压栈/弹栈都单独包一轮 pushf/popf: 口径与 P1 的 fild_fistp_q_x8 一致
     * (那里就是逐轮注入、取最后一轮的 fl), 为的是"n 次压栈里只要有任一次被翻译成
     * 会踩标志的序列"都能被抓到, 而不是只验最后一步。 */
    for (j = 0; j < n; j++)
        __asm__ volatile(IB_SETF "fildll (%[s])\n\t" IB_GETF
                         : [fl] "=&r"(fl)
                         : [s] "r"(s), [fv] "r"(fv) : "cc", "memory");
    __asm__ volatile("fnstsw (%[w0])" : : [w0] "r"(&g_sw[0]) : "memory");
    peak = swget();
    for (j = 0; j + 1 < n; j++)
        __asm__ volatile(IB_SETF "fistpll (%[d])\n\t" IB_GETF
                         : [fl] "=&r"(fl)
                         : [d] "r"(d), [fv] "r"(fv) : "cc", "memory");
    __asm__ volatile(IB_SETF "fistpll (%[d])\n\tfnstsw (%[w1])\n\t" IB_GETF
                     : [fl] "=&r"(fl)
                     : [d] "r"(d), [w1] "r"(&g_sw[1]), [fv] "r"(fv)
                     : "cc", "memory");
    g->i0 = xq(kk);   g->i1 = (uint64_t)n;   g->inf = fv;
    g->o0 = (uint64_t)peak;   g->o1 = (uint64_t)swgetn(1);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_stack_fld8_st8_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    int j;
    uint16_t peak;
    uintptr_t fl = 0;
    uintptr_t fv = (uintptr_t)IB_KFL("stack_fld8_st8", kk);

    for (j = 0; j < 8; j++) {
        fput(j, XVEC[j]);
        fput(8 + j, IB_POISON);
    }
    for (j = 0; j < 8; j++)
        __asm__ volatile(IB_SETF "fildll (%[s])\n\t" IB_GETF
                         : [fl] "=&r"(fl)
                         : [s] "r"((const void *)&g_f[j]), [fv] "r"(fv)
                         : "cc", "memory");
    __asm__ volatile("fnstsw (%[w0])" : : [w0] "r"(&g_sw[0]) : "memory");
    peak = swget();
    for (j = 0; j < 8; j++)
        __asm__ volatile(IB_SETF "fistpll (%[d])\n\t" IB_GETF
                         : [fl] "=&r"(fl)
                         : [d] "r"((void *)&g_f[8 + j]), [fv] "r"(fv)
                         : "cc", "memory");
    __asm__ volatile("fnstsw (%[w1])" : : [w1] "r"(&g_sw[1]) : "memory");
    g->i0 = XVEC[kk];   g->i1 = (uint64_t)(7 - kk);   g->inf = fv;
    g->o0 = fget(8 + (7 - kk));
    g->o1 = (uint64_t)swgetn(1) | ((uint64_t)peak << 16);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fxch_st3_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    int j;
    uintptr_t fl = 0;
    uintptr_t fv = (uintptr_t)IB_KFL("fxch_st3", kk);

    /* 先把八个物理槽按想要的值填满, 再从槽 7 倒序压到槽 0: 第 1 次压栈落在物理格 7,
     * 于是"压栈序 j=7..0"正好让物理格 s 拿到 XVEC[(s+kk)&7](见上)。
     * ★ 必须倒序: 顺着压会把阶梯整个反过来, 那也是个自洽的置换、但期望式就得重写,
     *   而这里要的只是"同一个形、八组不同的值"。 */
    for (j = 0; j < 8; j++) {
        fput(j, XVEC[(j + kk) & 7]);
        fput(8 + j, IB_POISON);
    }
    for (j = 7; j >= 0; j--)
        __asm__ volatile(IB_SETF "fildll (%[s])\n\t" IB_GETF
                         : [fl] "=&r"(fl)
                         : [s] "r"((const void *)&g_f[j]), [fv] "r"(fv)
                         : "cc", "memory");
    __asm__ volatile(IB_SETF "fxch %%st(3)\n\t" IB_GETF
                     : [fl] "=&r"(fl) : [fv] "r"(fv) : "cc", "memory");
    for (j = 0; j < 8; j++)
        __asm__ volatile(IB_SETF "fistpll (%[d])\n\t" IB_GETF
                         : [fl] "=&r"(fl)
                         : [d] "r"((void *)&g_f[8 + j]), [fv] "r"(fv)
                         : "cc", "memory");
    g->i0 = XVEC[kk];   g->i1 = XVEC[(kk + 3) & 7];   g->inf = fv;
    g->o0 = fget(8);            /* 期望 == i1 */
    g->o1 = fget(8 + 3);        /* 期望 == i0 */
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fldst_st1_to_st0_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    uint64_t a = xq(kk), b = xq((kk + 1) & 7);
    uint64_t em;
    uint16_t es;
    uintptr_t fl = 0;
    const void *pa = fput(0, a);
    const void *pb = fput(1, b);
    uintptr_t fv = (uintptr_t)IB_KFL("fldst_st1_to_st0", kk);

    ext_form(a, &em, &es);
    __asm__ volatile(IB_SETF
                     "fildll (%[a])\n\t"
                     "fildll (%[b])\n\t"
                     "fld %%st(1)\n\t"
                     "fstpt (%[t0])\n\t"
                     IB_GETF
                     : [fl] "=&r"(fl)
                     : [a] "r"(pa), [b] "r"(pb), [t0] "r"(&g_t[0]), [fv] "r"(fv)
                     : "cc", "memory");
    /* 余下两格弹到同一个槽(值不上表), 弹完读 sw。单独一条 asm 的理由与 P3 的
     * pc_fmul_core 完全相同: i386 只有 7 个通用寄存器, 4 个 "r" 输入 + 1 个
     * early-clobber 输出 + 本函数的 g 指针已经吃满; 而这两条 asm 之间没有任何 C
     * 语句也没有调用 -> 中间没人能碰栈。 */
    __asm__ volatile("fstpt (%[t])\n\tfstpt (%[t])\n\tfnstsw (%[w])"
                     : : [t] "r"(&g_t[1]), [w] "r"(&g_sw[0]) : "memory");
    g->i0 = a;   g->i1 = b;   g->inf = fv;
    g->o0 = tget_m(0);
    g->o1 = (uint64_t)tget_s(0) | ((uint64_t)swget() << 16);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fincstp_fdecstp_rt_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    int n = kk + 1;
    int j;
    uintptr_t fl = 0;
    uintptr_t fv = (uintptr_t)IB_KFL("fincstp_fdecstp_rt", kk);

    for (j = 0; j < n; j++)
        __asm__ volatile(IB_SETF "fincstp\n\t" IB_GETF
                         : [fl] "=&r"(fl) : [fv] "r"(fv) : "cc", "memory");
    __asm__ volatile("fnstsw (%[w0])" : : [w0] "r"(&g_sw[0]) : "memory");
    for (j = 0; j < n; j++)
        __asm__ volatile(IB_SETF "fdecstp\n\t" IB_GETF
                         : [fl] "=&r"(fl) : [fv] "r"(fv) : "cc", "memory");
    __asm__ volatile("fnstsw (%[w1])" : : [w1] "r"(&g_sw[1]) : "memory");
    g->i0 = (uint64_t)n;   g->i1 = 0;   g->inf = fv;
    g->o0 = (uint64_t)swgetn(0);   g->o1 = (uint64_t)swgetn(1);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_ffree_tag_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    int j;
    uintptr_t fl = 0;
    const void *s = fput(0, xq(kk));
    uintptr_t fv = (uintptr_t)IB_KFL("ffree_tag", kk);

    for (j = 0; j < 8; j++)
        __asm__ volatile(IB_SETF "fildll (%[s])\n\t" IB_GETF
                         : [fl] "=&r"(fl)
                         : [s] "r"(s), [fv] "r"(fv) : "cc", "memory");
    for (j = 0; j < kk; j++)
        __asm__ volatile(IB_SETF "fincstp\n\t" IB_GETF
                         : [fl] "=&r"(fl) : [fv] "r"(fv) : "cc", "memory");
    __asm__ volatile(IB_SETF "ffree %%st(0)\n\t" IB_GETF
                     : [fl] "=&r"(fl) : [fv] "r"(fv) : "cc", "memory");
    __asm__ volatile("fnstenv (%[e])" : : [e] "r"(&g_env[0]) : "memory");
    g->i0 = (uint64_t)kk;   g->i1 = 8;   g->inf = fv;
    g->o0 = (uint64_t)envget16(4);                   /* tag 字 */
    g->o1 = (uint64_t)envget16(2);                   /* 环境里的 sw: TOP 未被 ffree 改动 */
    g->outf = (uint64_t)fl & IB_FLG_MASK;
    /* ★ 清栈再返回: 与 k_ffree_tag_tp 同因 —— 本条序列故意留满 8 格, 而满栈会让框架层
     * 紧随其后的 double 往返(ib_now 经 ST(0))与 libc 的 %f 转换溢出成 indefinite NaN。
     * 三个读数(o0/o1/outf)已取完, finit 不改判据。 */
    __asm__ volatile("finit" : : : "memory");
}

void k_fdiv_zero_ze_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    int asig = (kk >> 1) & 1, bsig = kk & 1;
    uint64_t a = (kk < 4 ? D_ONE : 0ULL) | ((uint64_t)asig << 63);
    uint64_t b = (uint64_t)bsig << 63;
    uintptr_t fl = 0;
    const void *pa = fput(0, a);
    const void *pb = fput(1, b);
    uintptr_t fv = (uintptr_t)IB_KFL("fdiv_zero_ze", kk);

    __asm__ volatile(IB_SETF
                     "fldl (%[a])\n\tfdivl (%[b])\n\tfnstsw (%[w])\n\t" IB_GETF
                     : [fl] "=&r"(fl)
                     : [a] "r"(pa), [b] "r"(pb), [w] "r"(&g_sw[0]), [fv] "r"(fv)
                     : "cc", "memory");
    __asm__ volatile("fstpt (%[t])" : : [t] "r"(&g_t[0]) : "memory");
    g->i0 = a;   g->i1 = b;   g->inf = fv;
    g->o0 = tget_m(0);
    g->o1 = (uint64_t)tget_s(0) | ((uint64_t)swget() << 16);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fsqrt_neg_ie_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    uintptr_t fl = 0;
    const void *pa = fput(0, SQRTA[kk]);
    uintptr_t fv = (uintptr_t)IB_KFL("fsqrt_neg_ie", kk);

    __asm__ volatile(IB_SETF
                     "fldl (%[a])\n\tfsqrt\n\tfnstsw (%[w])\n\t" IB_GETF
                     : [fl] "=&r"(fl)
                     : [a] "r"(pa), [w] "r"(&g_sw[0]), [fv] "r"(fv)
                     : "cc", "memory");
    __asm__ volatile("fstpt (%[t])" : : [t] "r"(&g_t[0]) : "memory");
    g->i0 = SQRTA[kk];   g->i1 = 0;   g->inf = fv;
    g->o0 = tget_m(0);
    g->o1 = (uint64_t)tget_s(0) | ((uint64_t)swget() << 16);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fistp_oe_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    int w16 = (kk >= 4);                       /* kk 0-3 = m32int, 4-7 = m16int */
    int ovf = (kk == 3 || kk == 7);            /* 远越界档: 2^40 / 2^20 */
    unsigned e = w16 ? (ovf ? 20u : 15u) : (ovf ? 40u : 31u);
    int sub = (kk == 1 || kk == 5);             /* 每宽度里“2^N-0.5”那一档(远越界档不取半) */
    uint64_t mant = sub ? (0ULL - (1ULL << (63 - e))) : X1;
    uint16_t se = (uint16_t)(((kk == 2 || kk == 6) ? M80_S : 0u) | M80_E(sub ? e - 1 : e));
    uint64_t raw;
    uintptr_t fl = 0;
    uintptr_t fv = (uint64_t)IB_KFL("fistp_oe", kk);

    tput80(0, mant, se);
    /* 目的槽**每个 kk 都要预置哨兵**: 只写 W 字节以外的部分得能看出来。不预置的话,
     * 高位残留的是**上一条 case 留在同一槽里的值**(本组就是 P5 的 fput(8, IB_POISON)
     * 与上一条 case 的存回结果) -> "未越写"会看错对象而假阳:x87_p6chk 的 F/G/H 三行
     * 实测 = 预置 0xaa 时判 1、不预置时判 0、先 fstpl 再 fistps 同槽也判 0。
     * ★ 本条旧形状里 m32 四档的"过"正是 H 那一行那种假阳性(欠的预置由前一条 case 补上)。
     * 两条 asm: 窄存回的助记符必须是字面量(fistpl / fistps), 而写宽哨兵要单独算。 */
    fput(8, IB_POISON);
    __asm__ volatile(IB_SETF "fldt (%[s])\n\t" IB_GETF
                     : [fl] "=&r"(fl)
                     : [s] "r"(&g_t[0]), [fv] "r"(fv) : "cc", "memory");
    if (w16)
        __asm__ volatile(IB_SETF "fistps (%[d])\n\tfnstsw (%[w])\n\t" IB_GETF
                         : [fl] "=&r"(fl)
                         : [d] "r"((void *)&g_f[8]), [w] "r"(&g_sw[0]), [fv] "r"(fv)
                         : "cc", "memory");
    else
        __asm__ volatile(IB_SETF "fistpl (%[d])\n\tfnstsw (%[w])\n\t" IB_GETF
                         : [fl] "=&r"(fl)
                         : [d] "r"((void *)&g_f[8]), [w] "r"(&g_sw[0]), [fv] "r"(fv)
                         : "cc", "memory");
    raw = fget(8);
    g->i0 = (uint64_t)mant;
    g->i1 = (uint64_t)se | ((uint64_t)(w16 ? 16 : 32) << 16);
    g->inf = fv;
    g->o0 = w16 ? (uint64_t)(int64_t)(int16_t)(uint16_t)raw
                : (uint64_t)(int64_t)(int32_t)(uint32_t)raw;
    /* 高半部分仍是哨兵 -> 没越写; 与 sw 打包进同一个字段(低位 sw、bit16 = 未越写) */
    g->o1 = (uint64_t)swget() |
            ((w16 ? (raw & 0xffffffffffff0000ULL) == (IB_POISON & 0xffffffffffff0000ULL)
                  : (raw & 0xffffffff00000000ULL) == (IB_POISON & 0xffffffff00000000ULL))
             ? (1ULL << 16) : 0ULL);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_stack_underflow_is_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    uintptr_t fv = (uintptr_t)IB_KFL("stack_underflow_is", kk), fl = 0;

    tput80(6, IB_POISON, IB_POISON >> 48);          /* drain 槽: 没写就看得见 */
    switch (kk) {
    case 0: SU_ACT("faddp %%st,%%st(1)\n\t"); break;    /* 以下三档: 弹栈类一次两格 */
    case 1: SU_ACT("fsubp %%st,%%st(1)\n\t"); break;
    case 2: SU_ACT("fmulp %%st,%%st(1)\n\t"); break;
    case 3: SU_ACT("fld %%st(0)\n\t"); break;           /* 空栈压栈 */
    case 4: SU_ACT("fxch %%st(1)\n\t"); break;          /* 空栈交换: TOP 不变 */
    case 5: SU_ACT("fstpt (%[s])\n\t"); break;          /* 空栈弹一格(G4 e1) */
    case 6: SU_ACT("fstpt (%[s])\n\tfstpt (%[s])\n\tfstpt (%[s])\n\t"); break;
    default:                                            /* 只有 1 项时弹两格(G7e) */
        SU_ACT("fld1\n\tfcompp\n\t");
        break;
    }
    __asm__ volatile("fstpt (%[t])" : : [t] "r"(&g_t[6]) : "memory");
    g->i0 = (uint64_t)kk;
    g->i1 = (kk == 7) ? 1u : 0u;      /* 动作前的栈深: 只有 fcompp 那档先 fld1 */
    g->inf = fv;
    g->o0 = (uint64_t)swget();
    g->o1 = tget_m(6);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_denormal_ue_kat(int kk, ib_kv *g)
{
    x87_bin80_core(kk, XBDEN, "denormal_ue", g);
}

void k_precision_pe_kat(int kk, ib_kv *g)
{
    x87_bin80_core(kk, XBPRC, "precision_pe", g);
}

void k_fnclex_clears_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    uintptr_t fv = (uintptr_t)IB_KFL("fnclex_clears", kk), fl = 0;

    switch (kk) {
    case 0:                                     /* 1/0 -> ZE */
        fput(0, D_ONE); fput(1, 0);
        __asm__ volatile("fldl (%[a])\n\tfdivl (%[b])"
                         : : [a] "r"(&g_f[0]), [b] "r"(&g_f[1]) : "memory");
        break;
    case 1:                                     /* sqrt(-1) -> IE */
        fput(0, D_ONE | D_NEG);
        __asm__ volatile("fldl (%[a])\n\tfsqrt"
                         : : [a] "r"(&g_f[0]) : "memory");
        break;
    case 2:                                     /* 1+1 -> 无异常对照(不误伤) */
        fput(0, D_ONE); fput(1, D_ONE);
        __asm__ volatile("fldl (%[a])\n\tfaddl (%[b])"
                         : : [a] "r"(&g_f[0]), [b] "r"(&g_f[1]) : "memory");
        break;
    case 3: {                                   /* 第 9 次压栈 -> 溢出 IE|SF|C1 */
        int j;

        for (j = 0; j < 9; j++)
            __asm__ volatile("fld1" : : : "memory");
        break;
    }
    case 4:                                     /* 空栈弹一格 -> IE|SF, TOP +1 */
        __asm__ volatile("fstpt (%[s])" : : [s] "r"(&g_t[5]) : "memory");
        break;
    case 5:                                     /* 空栈压栈 -> IE|SF, TOP 走到 7 */
        __asm__ volatile("fld %%st(0)" : : : "memory");
        break;
    case 6:                                     /* 空栈交换 -> IE|SF, TOP 不变 */
        __asm__ volatile("fxch %%st(1)" : : : "memory");
        break;
    default:                                    /* 只有 1 项时 fcompp -> IE|SF + CC */
        __asm__ volatile("fld1\n\tfcompp" : : : "memory");
        break;
    }
    __asm__ volatile(IB_SETF
                     "fnstsw (%[w0])\n\tfnclex\n\tfnstsw (%[w1])\n\t" IB_GETF
                     : [fl] "=&r"(fl)
                     : [w0] "r"(&g_sw[0]), [w1] "r"(&g_sw[1]), [fv] "r"(fv)
                     : "cc", "memory");
    g->i0 = (uint64_t)kk;
    g->i1 = FC_MASK[kk];
    g->inf = fv;
    g->o0 = (uint64_t)swgetn(0);
    g->o1 = (uint64_t)swgetn(1);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fcom_cc_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    uintptr_t fl = 0;
    const void *pa = fput(0, FCOP[kk][0]);
    const void *pb = fput(1, FCOP[kk][1]);
    uintptr_t fv = (uintptr_t)IB_KFL("fcom_cc", kk);

    __asm__ volatile(IB_SETF
                     "fldl (%[a])\n\tfcoml (%[b])\n\tfnstsw (%[w0])\n\t" IB_GETF
                     : [fl] "=&r"(fl)
                     : [a] "r"(pa), [b] "r"(pb), [w0] "r"(&g_sw[0]), [fv] "r"(fv)
                     : "cc", "memory");
    __asm__ volatile("fstpt (%[t])\n\tfnstsw (%[w1])"
                     : : [t] "r"(&g_t[0]), [w1] "r"(&g_sw[1]) : "memory");
    g->i0 = FCOP[kk][0];
    g->i1 = FCOP[kk][1];
    g->inf = fv;
    g->o0 = (uint64_t)swgetn(0);
    g->o1 = (uint64_t)swgetn(1);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fcompp_cc_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    uintptr_t fl = 0;
    const void *pa = fput(0, FCPP[kk][0]);
    const void *pb = fput(1, FCPP[kk][1]);
    uintptr_t fv = (uintptr_t)IB_KFL("fcompp_cc", kk);

    __asm__ volatile(IB_SETF
                     "fldl (%[a])\n\tfldl (%[b])\n\tfcompp\n\tfnstsw (%[w0])\n\t" IB_GETF
                     : [fl] "=&r"(fl)
                     : [a] "r"(pa), [b] "r"(pb), [w0] "r"(&g_sw[0]), [fv] "r"(fv)
                     : "cc", "memory");
    __asm__ volatile("fldl (%[a])\n\tfnstsw (%[w1])\n\tfstpt (%[t])"
                     : : [a] "r"(pa), [w1] "r"(&g_sw[1]), [t] "r"(&g_t[0]) : "memory");
    g->i0 = FCPP[kk][0];
    g->i1 = FCPP[kk][1];
    g->inf = fv;
    g->o0 = (uint64_t)swgetn(0);
    g->o1 = (uint64_t)swgetn(1);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fsubr_pair_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    const uint64_t a = FSUBAB[kk & 1][0], b = FSUBAB[kk & 1][1];
    const void *pa = fput(0, a);
    const void *pb = fput(1, b);
    uintptr_t fv = (uintptr_t)IB_KFL("fsubr_pair", kk), fl = 0;

    switch (kk >> 1) {
    case 0:                                            /* FSUBP: ST(1) <- ST(1)-ST(0) = a-b */
        FSP_ACT("fldl (%[a])\n\tfldl (%[b])\n\tfsubp %%st,%%st(1)\n\t");
        break;
    case 1:                                            /* FSUBRP: ST(1) <- ST(0)-ST(1) = b-a */
        FSP_ACT("fldl (%[a])\n\tfldl (%[b])\n\tfsubrp %%st,%%st(1)\n\t");
        break;
    case 2:                                            /* FSUB m64fp: ST(0) <- ST(0)-src = a-b */
        FSP_ACT("fldl (%[a])\n\tfsubl (%[b])\n\t");
        break;
    default:                                           /* FSUBR m64fp: ST(0) <- src-ST(0) = b-a */
        FSP_ACT("fldl (%[a])\n\tfsubrl (%[b])\n\t");
        break;
    }
    __asm__ volatile("fstpt (%[t])" : : [t] "r"(&g_t[0]) : "memory");
    g->i0 = a;   g->i1 = b;   g->inf = fv;
    g->o0 = tget_m(0);
    g->o1 = (uint64_t)tget_s(0) | ((uint64_t)swget() << 16);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fisubr_m64_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    const int m = kk >> 2;                           /* 0 = m32int 直接形, 1 = m64int 经 FILD */
    const void *pa = fput(0, FIA[m]);
    const void *pc = fput(2, FIC[kk]);
    uintptr_t fv = (uintptr_t)IB_KFL("fisubr_m64", kk), fl = 0;

    if (m == 0) {
        if (!(kk & 1))
            FIB_ACT("fldl (%[a])\n\tfisubl (%[c])\n\t");        /* DA/4: ST0 <- ST0 - m32 */
        else
            FIB_ACT("fldl (%[a])\n\tfisubrl (%[c])\n\t");       /* DA/5: ST0 <- m32 - ST0 */
    } else if (!(kk & 1)) {
        FIB_ACT("fldl (%[a])\n\tfildll (%[c])\n\tfsubp %%st,%%st(1)\n\t");
    } else {
        FIB_ACT("fldl (%[a])\n\tfildll (%[c])\n\tfsubrp %%st,%%st(1)\n\t");
    }
    __asm__ volatile("fstpt (%[t])" : : [t] "r"(&g_t[0]) : "memory");
    g->i0 = FIA[m];
    g->i1 = FIC[kk];
    g->inf = fv;
    g->o0 = tget_m(0);
    g->o1 = (uint64_t)tget_s(0) | ((uint64_t)swget() << 16);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fscale_int_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    const void *pn = fput(0, FSN[kk]);
    const void *pa = fput(1, FSA[kk]);
    uintptr_t fv = (uintptr_t)IB_KFL("fscale_int", kk), fl = 0;

    __asm__ volatile(IB_SETF
                     "fldl (%[n])\n\tfldl (%[a])\n\tfscale\n\tfnstsw (%[w])\n\t" IB_GETF
                     : [fl] "=&r"(fl)
                     : [n] "r"(pn), [a] "r"(pa), [w] "r"(&g_sw[0]), [fv] "r"(fv)
                     : "cc", "memory");
    /* 两次存回: 第一格 = 结果, 第二格 = 原 ST(1)。sw 已取在它们之前(节头那条读数位置
     * 约束), 弹栈后的 sw 这里不重复登记 —— "不弹栈"由 fscale 后那一个读数 = 0x3000 钉。 */
    __asm__ volatile("fstpt (%[t0])\n\tfstpt (%[t1])"
                     : : [t0] "r"(&g_t[0]), [t1] "r"(&g_t[1]) : "memory");
    g->i0 = FSA[kk];
    g->i1 = FSN[kk];
    g->inf = fv;
    g->o0 = tget_m(0);
    g->o1 = (uint64_t)tget_s(0) | ((uint64_t)swget() << 16) | ((uint64_t)tget_s(1) << 32);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fxam_kinds_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    const unsigned shape = FXA_SHAPE(kk);
    const void *pv = (shape == 2u) ? tput80(3, FXAV[7], 0x0000) : fput(0, FXAV[kk]);
    uintptr_t fv = (uintptr_t)IB_KFL("fxam_kinds", kk), fl = 0;

    switch (kk) {
    case 6:                                            /* 先压一项再标空: ST(0) 存在但无效 */
        FXA_ACT("fld1\n\tffree %%st(0)\n\t");
        break;
    case 7:                                            /* fldt 直接装一个伪非规格化 m80 */
        FXA_ACT("fldt (%[v])\n\t");
        break;
    default:
        FXA_ACT("fldl (%[v])\n\t");
        break;
    }
    __asm__ volatile("fstpt (%[t])" : : [t] "r"(&g_t[0]) : "memory");
    g->i0 = FXAV[kk];
    g->i1 = shape;
    g->inf = fv;
    g->o0 = tget_m(0);
    g->o1 = (uint64_t)tget_s(0) | ((uint64_t)swget() << 16);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fstsw_allbits_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    uint16_t ax1 = 0, ax2 = 0;
    uintptr_t fv = (uintptr_t)IB_KFL("fstsw_allbits", kk), fl = 0;

    x87_dirty(kk);
    __asm__ volatile(IB_SETF "fnstsw (%[m])\n\t" IB_GETF
                     : [fl] "=&r"(fl)
                     : [m] "r"(&g_sw[0]), [fv] "r"(fv) : "cc", "memory");
    /* 两个 AX 形各自一条 asm: 写 %%ax 必须用 "=a" 告知编译器(约束 = 占用 eax),
     * 否则会默认把 ax 当可分配寄存器。三条 asm 之间只有寄存器搬运、不会插浮点
     * 指令(本节内核里没有任何 C 浮点表达式), 所以状态字不会在中间变。 */
    __asm__ volatile("fnstsw %%ax" : "=a"(ax1));
    __asm__ volatile("fstsw %%ax" : "=a"(ax2));
    g->i0 = (uint64_t)kk;
    g->i1 = FDIRTY[kk];
    g->inf = fv;
    g->o0 = (uint64_t)swget();
    g->o1 = (uint64_t)(ax1 ^ swget()) | ((uint64_t)(ax2 ^ swget()) << 16);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}

void k_fninit_defaults_kat(int kk, ib_kv *g)
{
    X87_BEGIN();
    uintptr_t fv = (uintptr_t)IB_KFL("fninit_defaults", kk), fl = 0;

    x87_dirty(kk);
    __asm__ volatile(IB_SETF
                     "fnstcw (%[c0])\n\tfnstsw (%[w0])\n\t" IB_GETF
                     : [fl] "=&r"(fl)
                     : [c0] "r"(&g_cw[0]), [w0] "r"(&g_sw[0]), [fv] "r"(fv)
                     : "cc", "memory");
    __asm__ volatile("fnstenv (%[e])" : : [e] "r"(&g_env[0]) : "memory");
    __asm__ volatile("fninit" : : : "memory");
    __asm__ volatile("fnstcw (%[c1])\n\tfnstsw (%[w1])\n\tfnstenv (%[e2])"
                     : : [c1] "r"(&g_cw[1]), [w1] "r"(&g_sw[1]), [e2] "r"(&g_env[16])
                     : "memory");
    g->i0 = (uint64_t)kk;
    g->i1 = FDIRTY[kk];
    g->inf = fv;
    g->o0 = (uint64_t)swgetn(0) | ((uint64_t)cwget(0) << 16);
    g->o1 = (uint64_t)cwget(1) | ((uint64_t)swgetn(1) << 16)
            | ((uint64_t)envget16(16 + 4) << 32);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}


/* =====================================================================
 * 8) P8 超越函数/除法精度边界(26 条)的 KAT 内核。
 *    入值口径与 lat/tp 完全同形(同指令序列、同槽位分配), 唯一差别 = 主尾数
 *    取 op_mant(stem,kk,base) 的 8 组扰动(高 52 位锁 base, 低 12 位哈希选图案)
 *    —— 被测机若把 m80 归一到 double 再算, p80 档丢的低 11 格必落进 o0 低格;
 *    p64 档同扰动但值在 double 内, 作对照组把"精度不足"与"实现不同"分开。
 *    判定字段: o0=结果 mant, o1=结果 se | (sw<<16), outf=EFLAGS(IB_FLG_MASK 后);
 *    fsincos 的 cos 占 o2/o3, fptan 的哨兵 1.0 也登记进 o2(mant 非 X1 即假实现)。
 *    sw 取在任何存回/弹栈之前(P6 纪律); 唯一例外是五形态里的弹栈结果已在 ST0,
 *    fnstsw 落在被测指令后、fstpt 前 —— TOP 读数才能把"弹了几格"一并钉住。
 *    结果/哨兵槽预置 IB_POISON(假阳性教训见本文件 pc24 一族): 没写回必以
 *    o0 != gold 报出, 不靠"碰巧是 0"自洽。
 *    五种形态的汇编模板与 lat/tp 一一对应(改一边必改另一边, 槽位表见 tp 头注)。
 * ===================================================================== */
/* 固定缓存: 本组不能用 `g_t+n` 绝对内联 —— xb80 因 8 字节对齐 stride=16(非 10),
 * g_t+20 会落进 g_t[1] 尾部只盖 mant 低 6 字、se/高位残留哨兵。改用专用 byte 缓存
 * p8buf(无结构体对齐), 各 10 字 m80 槽按字节位移定死(下面模板里的 0/16/32/48/64/80),
 * 单基址寄存器 %[b] + 常量位移寻址 —— 既修正地址又把 i386 6 个通用寄存器的压力
 * 降到 base+fv+fl 三个(旧写法 s1/s0/r/d/w/fv/fl 超 6 个会 "impossible constraints")。
 * 布局: S0=0(mant0-7/se8-9) S1=16 R=32(结果) D=48(哨兵) C=64(双结果补读) SW=80(状态字)。 */
static unsigned char p8buf[96];

#define P8_K_S1(op)  "fldt 16(%[b])\n\tfldt 0(%[b])\n\t" op "\n\tfnstsw 80(%[b])\n\tfstpt 32(%[b])\n\tfstpt 48(%[b])"
#define P8_K_D1(op)  "fldt 16(%[b])\n\tfldt 0(%[b])\n\t" op "\n\tfnstsw 80(%[b])\n\tfstpt 32(%[b])"
#define P8_K_D2(op)  "fldt 16(%[b])\n\tfldt 0(%[b])\n\t" op "\n\tfnstsw 80(%[b])\n\tfstpt 32(%[b])\n\tfstpt 48(%[b])"
#define P8_K_SC      "fldt 0(%[b])\n\tfsincos\n\tfnstsw 80(%[b])\n\tfstpt 32(%[b])\n\tfstpt 64(%[b])"
#define P8_K_PT      "fldt 16(%[b])\n\tfldt 0(%[b])\n\tfptan\n\tfnstsw 80(%[b])\n\tfstpt 48(%[b])\n\tfstpt 32(%[b])"

/* 结果/补读槽回读(x86 小端, 非对齐读合法): mant 在槽基址, se 在基址+8 */
#define P8_RM(off)   (*(volatile uint64_t *)(p8buf + (off)))
#define P8_RS(off)   (*(volatile uint16_t *)(p8buf + (off) + 8))

/* sn: 指令前缀; i: g_opinfo 下标; sfx: "p64"/"p80"; ASM: 拼好的模板 */
#define P8_KAT(sn, i, sfx, base, ASM)                                       \
    void k_##sn##_##sfx##_kat(int kk, ib_kv *g)                             \
    {                                                                       \
        X87_BEGIN();                                                        \
        const struct ib_opinfo *e = &g_opinfo[i];                           \
        char fs[24] = { 0 };                                                \
        uint64_t m;                                                         \
        uintptr_t fv, fl = 0;                                               \
                                                                            \
        strcat(strcpy(fs, e->stem), "_" #sfx);                              \
        m = op_mant(fs, kk, (base));                                        \
        fv = (uintptr_t)IB_KFL(fs, kk);                                     \
        *(uint64_t *)(p8buf + 0)  = m;            /* S0: 主(边界)尾数 */   \
        *(uint16_t *)(p8buf + 8)  = M80_E(e->ise);                          \
        *(uint64_t *)(p8buf + 16) = e->smant;     /* S1: 副/哨兵 */        \
        *(uint16_t *)(p8buf + 24) = e->sse;                                 \
        *(uint64_t *)(p8buf + 32) = IB_POISON;    /* 结果/哨兵/补读槽预置 */ \
        *(uint64_t *)(p8buf + 48) = IB_POISON;                              \
        *(uint64_t *)(p8buf + 64) = IB_POISON;                              \
        __asm__ volatile(IB_SETF ASM IB_GETF                                \
                         : [fl] "=&r"(fl)                                   \
                         : [b] "r"(p8buf), [fv] "r"(fv)                     \
                         : "cc", "memory");                                 \
        g->i0 = m;                g->i1 = e->smant;                          \
        g->i2 = M80_E(e->ise);    g->i3 = e->sse;                            \
        g->inf = fv;                                                          \
        g->o0 = P8_RM(32);                                                   \
        g->o1 = (uint64_t)P8_RS(32) | ((uint64_t)*(volatile uint16_t *)(p8buf + 80) << 16); \
        g->o2 = 0;                                                           \
        g->o3 = 0;                                                           \
        g->outf = (uint64_t)fl & IB_FLG_MASK;                                \
    }

/* fsincos/fptan 的双结果补读: cos/哨兵存进 C=64 槽, 其余字段与通用形同。 */
#define P8_KAT2(sn, i, sfx, base, ASM)                                      \
    void k_##sn##_##sfx##_kat(int kk, ib_kv *g)                             \
    {                                                                       \
        X87_BEGIN();                                                        \
        const struct ib_opinfo *e = &g_opinfo[i];                           \
        char fs[24] = { 0 };                                                \
        uint64_t m;                                                         \
        uintptr_t fv, fl = 0;                                               \
                                                                            \
        strcat(strcpy(fs, e->stem), "_" #sfx);                              \
        m = op_mant(fs, kk, (base));                                        \
        fv = (uintptr_t)IB_KFL(fs, kk);                                     \
        *(uint64_t *)(p8buf + 0)  = m;                                      \
        *(uint16_t *)(p8buf + 8)  = M80_E(e->ise);                          \
        *(uint64_t *)(p8buf + 16) = e->smant;                               \
        *(uint16_t *)(p8buf + 24) = e->sse;                                 \
        *(uint64_t *)(p8buf + 32) = IB_POISON;                              \
        *(uint64_t *)(p8buf + 48) = IB_POISON;                              \
        *(uint64_t *)(p8buf + 64) = IB_POISON;                              \
        __asm__ volatile(IB_SETF ASM IB_GETF                                \
                         : [fl] "=&r"(fl)                                   \
                         : [b] "r"(p8buf), [fv] "r"(fv)                     \
                         : "cc", "memory");                                 \
        g->i0 = m;                g->i1 = e->smant;                          \
        g->i2 = M80_E(e->ise);    g->i3 = e->sse;                            \
        g->inf = fv;                                                          \
        g->o0 = P8_RM(32);                                                   \
        g->o1 = (uint64_t)P8_RS(32) | ((uint64_t)*(volatile uint16_t *)(p8buf + 80) << 16); \
        g->o2 = P8_RM(64);                                                   \
        g->o3 = (uint64_t)P8_RS(64);                                         \
        g->outf = (uint64_t)fl & IB_FLG_MASK;                                \
    }


/* ---- 13 条指令 x 2 档(表序与 g_opinfo 一致; 模板与 lat/tp 同形) ---- */
#define P8_KATPAIR(sn, i, ASM)                              \
    P8_KAT(sn, i, p64, MANT_P64, ASM)                       \
    P8_KAT(sn, i, p80, MANT_P80, ASM)

P8_KATPAIR(fsin,    0, P8_K_S1("fsin"));
P8_KATPAIR(fcos,    1, P8_K_S1("fcos"));
P8_KATPAIR(fsqrt,   2, P8_K_S1("fsqrt"));
P8_KATPAIR(f2xm1,   3, P8_K_S1("f2xm1"));
P8_KAT2(fsincos, 4, p64, MANT_P64, P8_K_SC)
P8_KAT2(fsincos, 4, p80, MANT_P80, P8_K_SC)
P8_KAT2(fptan,   5, p64, MANT_P64, P8_K_PT)
P8_KAT2(fptan,   5, p80, MANT_P80, P8_K_PT)
P8_KATPAIR(fpatan,  6, P8_K_D1("fpatan"));
P8_KATPAIR(fyl2x,   7, P8_K_D1("fyl2x"));
P8_KATPAIR(fyl2xp1, 8, P8_K_D1("fyl2xp1"));
P8_KATPAIR(fprem,   9, P8_K_D2("fprem"));
P8_KATPAIR(fprem1, 10, P8_K_D2("fprem1"));
/* fdiv/fdivr 显式弹栈形(同 tp 文件: 裸形会被汇编器静默翻译成 f*xp) */
P8_KATPAIR(fdiv,   11, P8_K_D2("fdivp %%st,%%st(1)"));
P8_KATPAIR(fdivr,  12, P8_K_D2("fdivrp %%st,%%st(1)"));
