#include "ib_core.h"
#include "ib_buf.h"
#include "isb_x87_kat.h"
#include "isb_x87.h"


/* ---------------- fadd m64: ST0 <- ST0 + m64(唯一能自串的 x87 内核) -------- */
uint64_t k_fadd(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *p = fput(0, qv("fadd", 0, 1));
    void *q = (void *)&g_f[2];

    __asm__ volatile("fldl (%[p])" : : [p] "r"(p) : "memory");      /* 种栈 */
    for (i = 0; i < iters; i++)
        __asm__ volatile("faddl (%[p])" : : [p] "r"(p) : "memory"); /* ST0 自串 */
    __asm__ volatile("fstpl (%[q])" : : [q] "r"(q) : "memory");     /* 还栈 */
    return fget(2);
}


/* ---------------- fmul m64: ST0 <- ST0 * m64 ----------------
 * 链上的乘数钉 1.0: 任何 |b|!=1 的乘数都会把递推跑成指数式增长, 几百轮就溢出。
 * 实测事实(乘数用随机值时): lat 从 0.85 ns 跳到 79.85 ns(溢出/助跑路径的代价,
 * 与指令吞吐无关), 并且带着一个挂起的 x87 异常往下跑 -> 两个 case 之后的
 * x87_fcomip 直接没行、整组没有 DONE 行(_tmp/g5b.sh 的输出)。乘数取 1.0 不改变
 * 依赖链的性质(ST0 仍读写自己), 只是把值钉在有界区; 定时长每组只乘一次
 * (fld->fmul->fstp), 本来就不会累乘, 所以它不需要这个限制。 */
uint64_t k_fmul(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *one = fput(0, 0x3ff0000000000000ULL);   /* 1.0 */
    const void *seed = fput(1, qv("fmul", 0, 1));
    void *q = (void *)&g_f[2];

    __asm__ volatile("fldl (%[s])" : : [s] "r"(seed) : "memory");
    for (i = 0; i < iters; i++)
        __asm__ volatile("fmull (%[o])" : : [o] "r"(one) : "memory");
    __asm__ volatile("fstpl (%[q])" : : [q] "r"(q) : "memory");
    return fget(2);
}


/* =====================================================================
 * 通用延迟测试函数: 重复执行 N 次同一条指令(不依赖链, 测吞吐型延迟)
 * 用于 lat=NULL 的用例, 让它们也能测出延迟(虽然是吞吐延迟而非依赖链延迟)
 * ===================================================================== */
uint64_t k_x87_generic_lat(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *p = fput(0, 0x3ff0000000000000ULL);  /* 1.0 as double */
    void *q = (void *)&g_f[2];
    
    for (i = 0; i < iters; i++)
        __asm__ volatile("fldl (%[p])\n\tfstpl (%[q])"
                         : : [p] "r"(p), [q] "r"(q) : "memory");
    return fget(2);
}


/* =====================================================================
 * P1 精度类(12 条)专用延迟函数。
 * 口径: 每条用**它自己的指令序列**做同槽往返(装载 -> 存回写回同一槽 -> 下一轮
 * 再装载), 相邻两轮形成串行依赖, 测的是“这对指令”的往返延迟; 无法写回同槽的
 * (如 fild+fstpt 的 8/10 字节跨槽)退回“专用指令序列的重复”, 但仍不是通用 fld/fst。
 * ===================================================================== */

uint64_t k_fild_fistp_q_rt_lat(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    void *p = fput(0, XVEC[0]);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fildll (%[p])\n\tfistpll (%[p])"
                         : : [p] "r"(p) : "memory");
    return fget(0);
}

uint64_t k_fild_fistp_d_rt_lat(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    void *p = fput(0, xd(0));

    for (i = 0; i < iters; i++)
        __asm__ volatile("fildl (%[p])\n\tfistpl (%[p])"
                         : : [p] "r"(p) : "memory");
    return fget(0);
}

uint64_t k_fild_fistp_w_rt_lat(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    void *p = fput(0, xw(0));

    for (i = 0; i < iters; i++)
        __asm__ volatile("filds (%[p])\n\tfistps (%[p])"
                         : : [p] "r"(p) : "memory");
    return fget(0);
}

uint64_t k_fild_fistp_q_neg_lat(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    void *p = fput(0, (uint64_t)0 - XVEC[5]);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fildll (%[p])\n\tfistpll (%[p])"
                         : : [p] "r"(p) : "memory");
    return fget(0);
}

uint64_t k_fild_q_odd_rt_lat(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    void *p = fput(0, XVEC[1] | 1ULL);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fildll (%[p])\n\tfistpll (%[p])"
                         : : [p] "r"(p) : "memory");
    return fget(0);
}

uint64_t k_fild_fstp_q_dbl_lat(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    void *p = fput(0, XVEC[1]);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fildll (%[p])\n\tfstpl (%[p])"
                         : : [p] "r"(p) : "memory");
    return fget(0);
}

uint64_t k_fild_fstp_t_ext_lat(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *s = fput(0, XVEC[1]);
    void *d = tput80(0, 0, 0);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fildll (%[s])\n\tfstpt (%[d])"
                         : : [s] "r"(s), [d] "r"(d) : "memory");
    return tget_m(0);
}

uint64_t k_fistp_q_indef_lat(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *s = fput(0, IVEC[0]);
    void *d = fput(8, IB_POISON);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fldl (%[s])\n\tfistpll (%[d])"
                         : : [s] "r"(s), [d] "r"(d) : "memory");
    return fget(8);
}

uint64_t k_fisttp_q_rt_lat(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    void *p = fput(0, XVEC[1]);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fildll (%[p])\n\tfisttpll (%[p])"
                         : : [p] "r"(p) : "memory");
    return fget(0);
}

uint64_t k_fld_t_fstp_t_rt_lat(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    uint64_t m;
    uint16_t se;
    void *p;

    ext_form(XVEC[1], &m, &se);
    p = tput80(0, m, se);
    for (i = 0; i < iters; i++)
        __asm__ volatile("fldt (%[p])\n\tfstpt (%[p])"
                         : : [p] "r"(p) : "memory");
    return tget_m(0);
}

uint64_t k_fbld_fistp_q_rt_lat(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    void *p = (void *)bput(BVEC[1], 0);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fbld (%[p])\n\tfistpll (%[p])"
                         : : [p] "r"(p) : "memory");
    return fget(0);
}

uint64_t k_fild_fistp_q_x8_lat(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    int j;
    uint64_t x = 0;

    for (j = 0; j < IB_KAT_N; j++)
        fput(j, XVEC[j]);
    for (i = 0; i < iters; i++)
        for (j = 0; j < IB_KAT_N; j++)
            __asm__ volatile("fildll (%[s])\n\tfistpll (%[s])"
                             : : [s] "r"((void *)&g_f[j]) : "memory");
    for (j = 0; j < IB_KAT_N; j++)
        x ^= fget(j);
    return x;
}


/* =====================================================================
 * P2 舍入模式(5) + P3 精度控制(3) 专用延迟: rc_fistp 四档用同槽往返(RC 只设一次),
 * rc_fstcw_rt 用 fldcw/fnstcw 往返, P3 三条用 fldl+运算+fstpt 往返。
 * ===================================================================== */
static uint64_t rc_fistp_lat(unsigned long long iters, unsigned enc)
{
    X87_BEGIN();
    unsigned long long i;
    void *p = fput(0, q4bits(RVQ[0]));

    g_cw[0] = RC_CW(enc);
    __asm__ volatile("fldcw (%[cw])" : : [cw] "r"(&g_cw[0]) : "memory");
    for (i = 0; i < iters; i++)
        __asm__ volatile("fldl (%[p])\n\tfistpll (%[p])"
                         : : [p] "r"(p) : "memory");
    return fget(0);
}

uint64_t k_rc_fistp_q_rn_lat(unsigned long long iters) { return rc_fistp_lat(iters, 0); }
uint64_t k_rc_fistp_q_rd_lat(unsigned long long iters) { return rc_fistp_lat(iters, 1); }
uint64_t k_rc_fistp_q_ru_lat(unsigned long long iters) { return rc_fistp_lat(iters, 2); }
uint64_t k_rc_fistp_q_rz_lat(unsigned long long iters) { return rc_fistp_lat(iters, 3); }

uint64_t k_rc_fstcw_rt_lat(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;

    g_cw[0] = RC_CW(0);
    g_cw[1] = RC_CW(1);
    for (i = 0; i < iters; i++)
        __asm__ volatile("fldcw (%[a])\n\tfnstcw (%[b])\n\t"
                         "fldcw (%[c])\n\tfnstcw (%[d])"
                         : : [a] "r"(&g_cw[0]), [b] "r"(&g_cw[2]),
                           [c] "r"(&g_cw[1]), [d] "r"(&g_cw[3]) : "memory");
    return (uint64_t)cwget(2) ^ (uint64_t)cwget(3);
}

static uint64_t pc_fadd_lat(unsigned long long iters, unsigned enc)
{
    X87_BEGIN();
    unsigned long long i;
    const void *a = fput(0, FAVEC[0]);
    const void *b = fput(1, FBVEC[0]);
    void *t = &g_t[0];

    g_cw[0] = PC_CW(enc);
    __asm__ volatile("fldcw (%[cw])" : : [cw] "r"(&g_cw[0]) : "memory");
    for (i = 0; i < iters; i++)
        __asm__ volatile("fldl (%[a])\n\tfaddl (%[b])\n\tfstpt (%[t])"
                         : : [a] "r"(a), [b] "r"(b), [t] "r"(t) : "memory");
    return tget_m(0) ^ (uint64_t)tget_s(0);
}

uint64_t k_pc24_fadd_lat(unsigned long long iters) { return pc_fadd_lat(iters, 0); }
uint64_t k_pc53_fadd_lat(unsigned long long iters) { return pc_fadd_lat(iters, 2); }

uint64_t k_pc64_fmul_lat(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *a = fput(0, FMVEC[0]);
    void *t = &g_t[0];

    g_cw[0] = PC_CW(3);
    __asm__ volatile("fldcw (%[cw])" : : [cw] "r"(&g_cw[0]) : "memory");
    for (i = 0; i < iters; i++)
        __asm__ volatile("fldl (%[a])\n\tfmull (%[a])\n\tfstpt (%[t])"
                         : : [a] "r"(a), [t] "r"(t) : "memory");
    return tget_m(0) ^ (uint64_t)tget_s(0);
}


/* =====================================================================
 * 迁入 / 栈操作 / 异常 / 特殊类(25 条)专用延迟。
 * 这些指令(内存搬运、栈走位、控制字、异常触发、比较)无法自串 ST0 依赖链, 其“专用”
 * 口径 = 各自用例自身的指令序列(即该条定时长体同形), 区别于通用 fld/fst。
 * ===================================================================== */
uint64_t k_fld_fstp_lat(unsigned long long iters) { return k_fld_fstp_tp(iters); }
uint64_t k_fistp_m64_lat(unsigned long long iters) { return k_fistp_tp(iters); }
uint64_t k_fcomip_lat(unsigned long long iters) { return k_fcomip_tp(iters); }
uint64_t k_fcw_rt_lat(unsigned long long iters) { return k_fcw_rt_tp(iters); }
uint64_t k_stack_top_after_fild_lat(unsigned long long iters) { return k_stack_top_after_fild_tp(iters); }
uint64_t k_stack_fld8_st8_lat(unsigned long long iters) { return k_stack_fld8_st8_tp(iters); }
uint64_t k_fxch_st3_lat(unsigned long long iters) { return k_fxch_st3_tp(iters); }
uint64_t k_fldst_st1_to_st0_lat(unsigned long long iters) { return k_fldst_st1_to_st0_tp(iters); }
uint64_t k_fincstp_fdecstp_rt_lat(unsigned long long iters) { return k_fincstp_fdecstp_rt_tp(iters); }
uint64_t k_ffree_tag_lat(unsigned long long iters) { return k_ffree_tag_tp(iters); }
uint64_t k_fdiv_zero_ze_lat(unsigned long long iters) { return k_fdiv_zero_ze_tp(iters); }
uint64_t k_fsqrt_neg_ie_lat(unsigned long long iters) { return k_fsqrt_neg_ie_tp(iters); }
uint64_t k_fistp_oe_lat(unsigned long long iters) { return k_fistp_oe_tp(iters); }
uint64_t k_stack_underflow_is_lat(unsigned long long iters) { return k_stack_underflow_is_tp(iters); }
uint64_t k_denormal_ue_lat(unsigned long long iters) { return k_denormal_ue_tp(iters); }
uint64_t k_precision_pe_lat(unsigned long long iters) { return k_precision_pe_tp(iters); }
uint64_t k_fnclex_clears_lat(unsigned long long iters) { return k_fnclex_clears_tp(iters); }
uint64_t k_fcom_cc_lat(unsigned long long iters) { return k_fcom_cc_tp(iters); }
uint64_t k_fcompp_cc_lat(unsigned long long iters) { return k_fcompp_cc_tp(iters); }
uint64_t k_fsubr_pair_lat(unsigned long long iters) { return k_fsubr_pair_tp(iters); }
uint64_t k_fisubr_m64_lat(unsigned long long iters) { return k_fisubr_m64_tp(iters); }
uint64_t k_fscale_int_lat(unsigned long long iters) { return k_fscale_int_tp(iters); }
uint64_t k_fxam_kinds_lat(unsigned long long iters) { return k_fxam_kinds_tp(iters); }
uint64_t k_fstsw_allbits_lat(unsigned long long iters) { return k_fstsw_allbits_tp(iters); }
uint64_t k_fninit_defaults_lat(unsigned long long iters) { return k_fninit_defaults_tp(iters); }


/* =====================================================================
 * P8 超越函数/除法精度边界(26 条)专用延迟: 口径与迁入类同一 —— 无法自串 ST0
 * 依赖链(超越指令的值每轮变号/收敛), "专用" = 各自定时长体同形(固定源槽每轮
 * 重灌, 输入恒为边界档常量)。lat/tp 同形还有一个好处: lat 跑的就是接 KAT 的
 * 那条指令序列, 慢路径(denormal/越界)不会只在某一侧看得见。
 * ===================================================================== */
uint64_t k_fsin_f64_lat(unsigned long long iters)     { return k_fsin_f64_tp(iters); }
uint64_t k_fsin_f80_lat(unsigned long long iters)     { return k_fsin_f80_tp(iters); }
uint64_t k_fcos_f64_lat(unsigned long long iters)     { return k_fcos_f64_tp(iters); }
uint64_t k_fcos_f80_lat(unsigned long long iters)     { return k_fcos_f80_tp(iters); }
uint64_t k_fsqrt_f64_lat(unsigned long long iters)    { return k_fsqrt_f64_tp(iters); }
uint64_t k_fsqrt_f80_lat(unsigned long long iters)    { return k_fsqrt_f80_tp(iters); }
uint64_t k_f2xm1_f64_lat(unsigned long long iters)    { return k_f2xm1_f64_tp(iters); }
uint64_t k_f2xm1_f80_lat(unsigned long long iters)    { return k_f2xm1_f80_tp(iters); }
uint64_t k_fsincos_f64_lat(unsigned long long iters)  { return k_fsincos_f64_tp(iters); }
uint64_t k_fsincos_f80_lat(unsigned long long iters)  { return k_fsincos_f80_tp(iters); }
uint64_t k_fptan_f64_lat(unsigned long long iters)    { return k_fptan_f64_tp(iters); }
uint64_t k_fptan_f80_lat(unsigned long long iters)    { return k_fptan_f80_tp(iters); }
uint64_t k_fpatan_f64_lat(unsigned long long iters)   { return k_fpatan_f64_tp(iters); }
uint64_t k_fpatan_f80_lat(unsigned long long iters)   { return k_fpatan_f80_tp(iters); }
uint64_t k_fyl2x_f64_lat(unsigned long long iters)    { return k_fyl2x_f64_tp(iters); }
uint64_t k_fyl2x_f80_lat(unsigned long long iters)    { return k_fyl2x_f80_tp(iters); }
uint64_t k_fyl2xp1_f64_lat(unsigned long long iters)  { return k_fyl2xp1_f64_tp(iters); }
uint64_t k_fyl2xp1_f80_lat(unsigned long long iters)  { return k_fyl2xp1_f80_tp(iters); }
uint64_t k_fprem_f64_lat(unsigned long long iters)    { return k_fprem_f64_tp(iters); }
uint64_t k_fprem_f80_lat(unsigned long long iters)    { return k_fprem_f80_tp(iters); }
uint64_t k_fprem1_f64_lat(unsigned long long iters)   { return k_fprem1_f64_tp(iters); }
uint64_t k_fprem1_f80_lat(unsigned long long iters)   { return k_fprem1_f80_tp(iters); }
uint64_t k_fdiv_f64_lat(unsigned long long iters)     { return k_fdiv_f64_tp(iters); }
uint64_t k_fdiv_f80_lat(unsigned long long iters)     { return k_fdiv_f80_tp(iters); }
uint64_t k_fdivr_f64_lat(unsigned long long iters)    { return k_fdivr_f64_tp(iters); }
uint64_t k_fdivr_f80_lat(unsigned long long iters)    { return k_fdivr_f80_tp(iters); }
