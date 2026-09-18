#include "ib_core.h"
#include "ib_buf.h"
#include "isb_x87_kat.h"
#include "isb_x87.h"


/* =====================================================================
 * 1) P1 精度(12 条): 整型 <-> x87 寄存器 <-> 内存的往返, 入值全在高有效位。
 *    本节的 12 条**全是 [解析]**: 每条的期望都写在它自己的注释里, 并标出它
 *    能否抓到缺陷本体(抓不到的也登记, 它们是"缺陷只在这条路径上"这条论断的
 *    证据行 —— 出问题时用来定位是装载丢位还是存回丢位)。
 *    本节的验证通道(口径与 P7 同: 验 x87 要写"各种常用 / 不常用的 C 调用组合",
 *    不是只按助记符直调): 探针 = _tmp/x87_p1chk.c 的 A-H 八节, 一条 asm 都不写,
 *    双机 139 行可比 / 差异 0 / 一列都不必剥(P1、P2 的形状没有 P7 那种 fenv 分家)。
 *    通道脚本已泛化(_tmp/pchk_{build,pe,box31,two_diff,dis}.sh + x87_p1chk.strip 边车,
 *    剥列规则必须带实测出处 —— 本探针的边车里一条 S 规则都没有, 因为两机逐字可比),
 *    逐函数指令归因看 _tmp/_x87_p1chk_dis_{exe,elf}.txt(每节都坐实到具体助记符:
 *    sec_a=fildll+fistpll+fldt/fstpt、sec_b=fildl/filds/fistpl/fistps、sec_h 只调
 *    __fesetround(体内是 fnstcw+fldcw)与 __llrint(体内是一条裸 fistpll))。
 *    词干 -> 探针行(锚点 = 同一件事的另一条实现路径, 不是同一串指令):
 *      fild_fistp_q_rt -> A1   fild_fistp_q_neg -> A2   fild_q_odd_rt -> A3
 *      fild_fistp_q_x8 -> A5   fild_fistp_d_rt -> B1 前  fild_fistp_w_rt -> B1 后
 *      fild_fstp_t_ext -> C1/C2(与 ext_expect 逐位)   fild_fstp_q_dbl -> D1(dblok)
 *      fistp_q_indef   -> E1   fld_t_fstp_t_rt -> G1   (A4 是"过 double 必丢位"的对照行)
 *    本节覆盖不到的三处(实测划出来的边界, 不是"应该也能"):
 *      ① fisttp_q_rt: 两形态反汇编里 `fisttp` 命中 **0 次** —— gcc 为满足 C99"强转
 *         恒向零"发的是 fnstcw/fldcw(RC=11b)/fistpll/fldcw(还原) 的控制字舞, 存回本身
 *         仍受 RC 影响。所以 C 的强转**不是** FISTTP 的对应物, 这条继续只有内核一路。
 *      ② 写宽断言(各条 o1 的"高字节仍是哨兵"): C 写进 int 对象必然只写 4 字节,
 *         构造不出"给 8 字节槽只写 4 字节"这个形状。
 *      ③ fbld_fistp_q_rt: packed BCD 没有 C 类型(strtod 走十进制文本, 与 9+1 字节
 *         编码不是一回事) —— 不拿它作证。
 * ===================================================================== */

/* ---- fild_fistp_q_rt: fildll -> fistpll, int64 原值往返 ---- [解析]
 * 期望 o0 == i0(SDM: FILD m64int "loaded without rounding errors"; FISTP m64int
 * 对量程内整数值精确存回), o1 == 0(无异常: 状态字 IE..ES/Cx/TOP 全 0, 弹栈后 TOP
 * 回 0)。这条是缺陷本体的**主探针**: LATX 按 double 中转时 XVEC[1](2^53+1)必丢。 */
uint64_t k_fild_fistp_q_rt_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *s = fput(0, XVEC[0]);
    void *d = fput(8, IB_POISON);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fildll (%[s])\n\tfistpll (%[d])"
                         : : [s] "r"(s), [d] "r"(d) : "memory");
    return fget(8);
}


/* ---- fild_fistp_d_rt: fildl -> fistpl(m32int 形态的往返 + 写宽断言) ---- [解析]
 * 期望 o0 == i0(32 位整数在 80 位与 double 里都精确, 故本条**抓不到缺陷**, 它是
 * "缺陷需要 >=2^53 入值"的边界证据); o1 == 1: 目的槽高 4 字节仍是 0xAA 哨兵 =>
 * 实际写宽是 4 字节(h 项实测), 抓"把 m32 形按 8 字节写"的翻译越界。 */
uint64_t k_fild_fistp_d_rt_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *s = fput(0, xd(0));
    void *d = fput(8, IB_POISON);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fildl (%[s])\n\tfistpl (%[d])"
                         : : [s] "r"(s), [d] "r"(d) : "memory");
    return fget(8);
}


/* ---- fild_fistp_w_rt: filds -> fistps(m16int 形态) ---- [解析]
 * m16int 装载形助记符是 filds = DF/0(被 as 拒的是 fildw), 存回形 fistps = DF/3,
 * 实测 2 字节写宽 + 弹栈。期望同 d_rt, o1 == 1: 高 6 字节仍是哨兵。 */
uint64_t k_fild_fistp_w_rt_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *s = fput(0, xw(0));
    void *d = fput(8, IB_POISON);

    for (i = 0; i < iters; i++)
        __asm__ volatile("filds (%[s])\n\tfistps (%[d])"
                         : : [s] "r"(s), [d] "r"(d) : "memory");
    return fget(8);
}


/* ---- fild_fistp_q_neg: 负侧往返(0 - XVEC, 无符号回绕取补, 避开 -INT64_MIN 的 UB)
 * 期望 o0 == i0 且 o1 == 0。抓的是"按无符号搬进 double 再补符号"这类实现: 负数
 * 侧的量程判据与正数侧不同(INT64_MIN 的幅值 2^63 只有负侧能表示)。 */
uint64_t k_fild_fistp_q_neg_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *s = fput(0, (uint64_t)0 - XVEC[5]);
    void *d = fput(8, IB_POISON);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fildll (%[s])\n\tfistpll (%[d])"
                         : : [s] "r"(s), [d] "r"(d) : "memory");
    return fget(8);
}


/* ---- fild_q_odd_rt: 强制最低位为 1 的往返(把入值全变成奇数) ---- [解析]
 * 2^53 以上任何奇数都无法用 double 表示, 所以 |v|>=2^53 的 8 组里每一组的奇偶性
 * 都是一次"有没有被舍过"的检票; XVEC[0]/[1] 这一对(2^53 / 2^53+1)在原始向量里
 * 只有一个奇数, 这里补齐。期望 o0 == i0(|v|<=2^63-1, 量程内), o1 == 0。 */
uint64_t k_fild_q_odd_rt_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *s = fput(0, XVEC[1] | 1ULL);
    void *d = fput(8, IB_POISON);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fildll (%[s])\n\tfistpll (%[d])"
                         : : [s] "r"(s), [d] "r"(d) : "memory");
    return fget(8);
}


/* ---- fild_fstp_q_dbl: fildll -> fstpl(存成 double) ---- [解析] **对照行**
 * 期望 o0 == 把整数**一次**舍到 double 的 RN 结果(算式见文件顶部注与 kat_audit.py
 * 的 p1_fild_fstp_q_dbl() 与 p1_fild_fstp_q_dbl_sw()), o1 = fnstsw 读回的状态字:
 * 只要真舍过位就置 PE(bit5), 量级变大再置 C1(bit9) —— 双机 8 组实测恰好是 0x000/0x020/0x220
 * 三种(取证 i)。注意这条**结构上抓不到本体的缺陷**: 缺陷是
 * "中途按 double 舍了一次", 而终点本来就是 double, 一次舍与两次舍在这里同值
 * —— 所以它是对照行: 若将来某台机器上 #1 挂了而这条没挂, 就说明丢位发生在
 * **整数存回**那一段而不是装载那一段。 */
uint64_t k_fild_fstp_q_dbl_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *s = fput(0, XVEC[1]);
    void *d = fput(8, IB_POISON);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fildll (%[s])\n\tfstpl (%[d])"
                         : : [s] "r"(s), [d] "r"(d) : "memory");
    return fget(8);
}


/* ---- fild_fstp_t_ext: fildll -> fstpt(存成 m80real, 直接看装载进寄存器的位形) ----
 * [解析] **单点定位装载精度的探针**: o0 = 尾数、o1 = 指数+符号, 期望 ext_form(i0)。
 * 80 位的 64 位尾数足以精确表示任意 int64, 所以期望与入值一一对应、与舍入档无关;
 * 只要翻译器在 FILD 里过了一次 double, o0 的低 11 位就会出现舍入痕迹。 */
uint64_t k_fild_fstp_t_ext_tp(unsigned long long iters)
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


/* ---- fistp_q_indef: FISTP m64int 的量程外行为 ---- [解析]
 * 期望 o0 == 0x8000000000000000(integer indefinite)且 o1 == 0x0001(**只有 IE**)。
 * 取证 c 的落点: 越界是 #IA/IE **不是 OE**, 且 masked 异常**不置 ES**(bit7=0);
 * 2^63 刚好在界外一格, 所以它是"按有符号还是按无符号判量程"的分水岭。 */
uint64_t k_fistp_q_indef_tp(unsigned long long iters)
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


/* ---- fisttp_q_rt: fildll -> fisttpll(SSE3 的截断存回) ---- [解析]
 * 期望 o0 == i0(输入本来就是整数, 截断无损), o1 == 0。FISTTP 按架构不受 RC 影响,
 * 这条钉住它的"i386 + SSE3 编码路径"(实测 fisttpll = DD/1, 弹栈、8 字节写宽);
 * RC 的影响面归 P2, PC 的忽略面归 P3, 不在这里混。 */
uint64_t k_fisttp_q_rt_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *s = fput(0, XVEC[1]);
    void *d = fput(8, IB_POISON);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fildll (%[s])\n\tfisttpll (%[d])"
                         : : [s] "r"(s), [d] "r"(d) : "memory");
    return fget(8);
}


/* ---- fld_t_fstp_t_rt: fldt -> fstpt(m80real 内存格式原样往返) ---- [解析]
 * 输入位形由 ext_form(i0) 造(正规格化、显式整数位=1, 不踩 pseudo-denormal 那条
 * 会置 DE 的路), 期望输出逐位等于输入: 10 字节操作数 + 80 位显式整数位格式都必须
 * 被原样搬运。SDM 把 FLD/FST m80real 标为 64-Bit Mode Invalid, 但**本机实测不成立**
 * (见文件头第 2 条与 _tmp/x87_abi_cmp.sh: x86_64 下照样执行且与 i386 同字), 所以
 * 这条登记成 i386 的理由是"没有编译器会发射", 不是"别的模式跑不出来"。
 * i1/o1 里的 se 只用低 16 位。 */
uint64_t k_fld_t_fstp_t_rt_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    uint64_t m;
    uint16_t se;
    const void *s;
    void *d = tput80(1, 0, 0);

    ext_form(XVEC[1], &m, &se);
    s = tput80(0, m, se);
    for (i = 0; i < iters; i++)
        __asm__ volatile("fldt (%[s])\n\tfstpt (%[d])"
                         : : [s] "r"(s), [d] "r"(d) : "memory");
    return tget_m(1);
}


/* ---- fbld_fistp_q_rt: fbld -> fistpll(BCD 十进制通路的整型往返) ---- [解析]
 * 期望 o0 == i0(18 位内的 BCD 整数在 80 位里精确; 取回又是精确整数存回)且
 * o1 == 0。符号由 kk&4 定(正 4 组 + 负 4 组, 取证 4f 两侧都量过)。入值全 < 1e18
 * —— FBLD 只有 18 位十进制量程, 19 位必被截(取证 4f 反例), 那不是缺陷是架构。 */
uint64_t k_fbld_fistp_q_rt_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *s = bput(BVEC[1], 0);
    void *d = fput(8, IB_POISON);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fbld (%[s])\n\tfistpll (%[d])"
                         : : [s] "r"(s), [d] "r"(d) : "memory");
    return fget(8);
}


/* ---- fild_fistp_q_x8: 一次探针跑 8 组**独立槽**的往返(源 0-7 / 目的 8-15) ----
 * [解析] 抓的是"复用同一个临时寄存器/同一个转换缓冲"这类翻译器实现: 八组各自
 * 独立往返, 任何一组串了别组都会反映在掩码上。
 * i0 = 八组入值异或, i1 = 0xff(入值侧的"应有全等"位掩码), o0 = 八组结果异或,
 * o1 = 逐组相等位掩码(第 j 组结果 == 入值则置位), 期望 0xff。
 * 注: 本条的 i0/o0 与 kk **无关**(异或对固定八元组是常数) —— 这是刻意的: 它的
 * 看点是 o1 与 outf(注入标志必须原样穿过 8 组), 8 行之间只有 inf/outf 不同。 */
uint64_t k_fild_fistp_q_x8_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    int j;
    uint64_t x = 0;

    for (j = 0; j < IB_KAT_N; j++) {
        fput(j, XVEC[j]);
        fput(8 + j, IB_POISON);
    }
    for (i = 0; i < iters; i++)
        for (j = 0; j < IB_KAT_N; j++)
            __asm__ volatile("fildll (%[s])\n\tfistpll (%[d])"
                             : : [s] "r"((const void *)&g_f[j]),
                               [d] "r"((void *)&g_f[8 + j]) : "memory");
    for (j = 0; j < IB_KAT_N; j++)
        x ^= fget(8 + j);
    return x;
}


/* ---- rc_fstcw_rt: fnstcw 读 -> 只改 RC 两位 -> fldcw -> 再读 ---- [解析]
 * 断言两件事, 而三个读回值只有一个独立来源(表里不留"没人核过"的字段):
 *   o0 = sv ^ rb 必须是 (enc_from ^ enc_to) << 10 —— "除 RC 两位之外没动过任一位"
 *   o1 = rb 必须是 0x037f | enc_to << 10 —— 绝对锚点
 * 由 o0 ^ o1 可反推 sv = 0x037f | enc_from << 10, 所以第一次 fldcw 也没漏检。
 * 与 fcw_rt 的分工: 那条只证"16 位原样存得住"(不掺算术、不依赖位段含义), 本条证
 * "改档只动这两位"(依赖取证 g1 的位段 + g3 的可写位档)。P2 那四条的 fldcw 全靠
 * 这个前提才能把"签名不同"归因到舍入模式而不是"根本没写进去"。 */
uint64_t k_rc_fstcw_rt_tp(unsigned long long iters)
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


/* ---------------- fld + fstp: 浮点载入/存回对(数据通路) ---------------- */
uint64_t k_fld_fstp_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *s = fput(0, qv("fld_fstp", 0, 0));
    void *d = (void *)&g_f[2];

    for (i = 0; i < iters; i++)
        __asm__ volatile("fldl (%[s])\n\tfstpl (%[d])"
                         : : [s] "r"(s), [d] "r"(d) : "memory");
    return fget(2);
}

uint64_t k_fadd_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *p = fput(0, qv("fadd", 0, 1));
    const void *p2 = fput(1, qv("fadd", 0, 2));

    for (i = 0; i < iters; i++) {
        __asm__ volatile("fldl (%[p])\n\tfaddl (%[p])\n\tfstpl (%[d])"
                         : : [p] "r"(p), [d] "r"((void *)&g_f[2]) : "memory");
        __asm__ volatile("fldl (%[p])\n\tfaddl (%[p2])\n\tfstpl (%[d])"
                         : : [p] "r"(p), [p2] "r"(p2),
                           [d] "r"((void *)&g_f[3]) : "memory");
        __asm__ volatile("fldl (%[p2])\n\tfaddl (%[p])\n\tfstpl (%[d])"
                         : : [p] "r"(p), [p2] "r"(p2),
                           [d] "r"((void *)&g_f[4]) : "memory");
        __asm__ volatile("fldl (%[p2])\n\tfaddl (%[p2])\n\tfstpl (%[d])"
                         : : [p2] "r"(p2), [d] "r"((void *)&g_f[5]) : "memory");
    }
    return fget(2) ^ fget(3) ^ fget(4) ^ fget(5);
}

uint64_t k_fmul_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *p = fput(0, qv("fmul", 0, 1));
    const void *p2 = fput(1, qv("fmul", 0, 2));

    for (i = 0; i < iters; i++) {
        __asm__ volatile("fldl (%[p])\n\tfmull (%[p])\n\tfstpl (%[d])"
                         : : [p] "r"(p), [d] "r"((void *)&g_f[2]) : "memory");
        __asm__ volatile("fldl (%[p])\n\tfmull (%[p2])\n\tfstpl (%[d])"
                         : : [p] "r"(p), [p2] "r"(p2),
                           [d] "r"((void *)&g_f[3]) : "memory");
        __asm__ volatile("fldl (%[p2])\n\tfmull (%[p])\n\tfstpl (%[d])"
                         : : [p] "r"(p), [p2] "r"(p2),
                           [d] "r"((void *)&g_f[4]) : "memory");
        __asm__ volatile("fldl (%[p2])\n\tfmull (%[p2])\n\tfstpl (%[d])"
                         : : [p2] "r"(p2), [d] "r"((void *)&g_f[5]) : "memory");
    }
    return fget(2) ^ fget(3) ^ fget(4) ^ fget(5);
}


/* ---------------- fistp m64: 浮点->整数存回(软浮点舍入路径) -------------
 * 循环体写成「fldl + fistpll」看上去像欠了一次弹栈, 但本机弹不弹都不是事: 入口
 * X87_BEGIN()(finit) 已经把栈位归零, 不依赖上一个内核留什么状态。
 * (special 原注在此处写过两条"实测与文档不一致"的事实, 现已由取证 1/2 订正:
 *  `fistpll` 的反汇编是 DF reg=7 = SDM 的 FISTP m64int, 本来就弹栈; 当初读成
 *  "DF reg=3 = FIST 不弹"是把 modrm 0x3c 的首位 hex 当成了 reg 号。行为与文档
 *  一致, 所以"别拆成循环外种一次"的写法照旧保留 —— 它同时是 lat 无关的自平衡体。)
 * 入值口径: 与 P1 相反, 这里的被乘数是 n/4(小数只可能 .00/.25/.50/.75) ->
 * 期望是**就近取偶后的整数**, 抓的是软浮点舍入模式而不是位精度。 */
uint64_t k_fistp_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *s = fput(0, qv("fistp", 0, 0));
    void *d = (void *)&g_f[2];

    for (i = 0; i < iters; i++)
        __asm__ volatile("fldl (%[s])\n\tfistpll (%[d])"
                         : : [s] "r"(s), [d] "r"(d) : "memory");
    return fget(2);
}


/* ---------------- fcomip: 比较并把结果写成 EFLAGS ---------------- */
uint64_t k_fcomip_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *s = fput(0, qv("fcomip", 0, 0));
    const void *s2 = fput(1, qv("fcomip", 0, 1));
    void *d = (void *)&g_f[2];

    for (i = 0; i < iters; i++)
        __asm__ volatile("fldl (%[s])\n\tfldl (%[s2])\n\tfcomip %%st(1),%%st\n\t"
                         "fstpl (%[d])"
                         : : [s] "r"(s), [s2] "r"(s2), [d] "r"(d)
                         : "cc", "memory");
    return fget(2);
}


/* ---------------- fldcw / fnstcw: 控制字状态往返 ----------------
 * 只往返控制字本身、中间不做任何浮点运算: 本条要钉的是"写进去的 16 位原样读回", 掺
 * 进算术就把档的行为(PC 影响位宽, 取证 g2)混了进来 —— 一条 case 同时回答两个问题,
 * 出错时分不清是 fldcw 没存住还是运算舍了位。"设档之后真算一次"由 P3 单独上表。
 * (这一节的旧注写的是"把精度设成 24 位后再算一次乘法, 在'硬件忽略 PC'与'软浮点
 *  honor PC'两台机器上会得到不同结果 -> 那是状态语义差异不是翻译错误, 不该上表", 那
 *  个前提来自伪取证(见文件头 g0), 已被两台真机实测否掉: 三档位形互异且与 SDM 一致,
 *  所以"设档再算"是可推导的架构行为, 现由 P3 正式上表并给[解析]期望。)
 * 定时长内核的入值恒 0x037f(finit 同值): 保留位照文档写, 不赌硬件怎么刷 —— 保留位
 * 实测档见取证 g3(位 6 恒 1、位 7 与 13-15 恒 0), 取值内核因此只能用可写位段。 */
uint64_t k_fcw_rt_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    *(volatile uint16_t *)&g_cw[0] = 0x037fu;   /* finit 同值: 保留位照文档写, 不赌硬件怎么刷 */
    for (i = 0; i < iters; i++)
        __asm__ volatile("fldcw (%[s])\n\tfnstcw (%[d])"
                         : : [s] "r"((const void *)&g_cw[0]),
                           [d] "r"((void *)&g_cw[2]) : "memory");
    return g_cw[2];
}


/* =====================================================================
 * 5) P5 栈操作(6 条): 判据是 **TOP 走位 / tag 字 / 弹栈值序**, 不是算术结果。
 *    位段一律按取证 2/6 的真机读回: **TOP = bits 11-13(LSB=bit11)** —— 计划 99 行
 *    写的"TOP=bits 8-10、C1=bit11"是错的(订正见文件头 h) ①)。
 *    本节所有压弹都走 fildll/fistpll 或 fstpt 这一对**无损**形(P1 已双机证过整数往返
 *    不置任何异常位): 换成 fstpl 会在 >=2^53 的入值上置 PE, 那等于把"栈没走错"与
 *    "舍入没丢位"混进同一个 sw 读数。
 *    sw 读数的位置: 一律落在**任何存回/弹栈之前**(取证 7 e) 末段: 存回类指令会把 C1
 *    写掉)。本节只有三处刻意取在弹完之后(stack_top_after_fild 的 o1、
 *    stack_fld8_st8/fldst_st1_to_st0 的末 sw), 那几处本组入值全程无舍入、C1 无从
 *    产生, 且读数形状与 G2 的"弹 8 步逐次 sw ... 0000"同位。
 *    一条贯穿全节的硬件事实(取证 6 c)/G3): ST(k) = 物理格 (TOP+k)&7、压栈 TOP-1、
 *    弹栈 TOP+1、第 9 次压栈才报 IE|SF —— 八条期望式全都只用到这四句话。
 *    验证通道边界: 栈深、TOP 走位、tag 字、WAIT 前缀在 C 里**没有对应物** ——
 *    编译器自己管 8 格栈, 源码层构造不出"压到第 9 格"的确定形状(fenv.h 的
 *    fenv_t 能读到 fnstenv 镜像里的 tag 字, 但 C 语义不会去 ffree 某个寄存器),
 *    所以 _tmp/x87_p1chk.c 不接 P5; 本节六条仍只有内核一路, 判据靠取证 7 的双基准。
 * ===================================================================== */

/* ---- stack_top_after_fild: 压 n 次(n=kk+1)读峰值 TOP, 再弹 n 次读回归零 ---- [解析]
 * 期望 o0 == ((8-n)&7)<<11: 取证 6 c) 实测 finit 后 TOP=0、每次压栈 -1、第 1 次读回
 *   0x3800(TOP=7)。★ 第 8 次压栈之后 TOP 又回到 **0**, 所以"栈满"这一档的峰值 sw 是
 *   0x0000 而不是 0x3800×8 的某种进位; 只有第 9 次才报 0x3a41 —— 那是 P6 的
 *   stack_underflow_is 那一档, 本条**不造溢出**(连续溢出的 C1 交替未解释, 文件头 c))。
 * 期望 o1 == 0(弹 n 次之后 TOP 回 0, IE/SF/C1 全 0: 整数装载精确故无舍入方向)。
 * i0 = 压栈用的值, i1 = 压栈次数 n(审计端据此重算 TOP, 不抄表)。 */
uint64_t k_stack_top_after_fild_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    int j;
    const void *s = fput(0, XVEC[2]);
    void *d = fput(8, IB_POISON);

    for (i = 0; i < iters; i++) {
        for (j = 0; j < 8; j++)
            __asm__ volatile("fildll (%[s])" : : [s] "r"(s) : "memory");
        __asm__ volatile("fnstsw (%[w])" : : [w] "r"(&g_sw[0]) : "memory");
        for (j = 0; j < 8; j++)
            __asm__ volatile("fistpll (%[d])" : : [d] "r"(d) : "memory");
    }
    return fget(8) ^ (uint64_t)swget();
}


/* ---- stack_fld8_st8: 压满 8 格再弹 8 格, 逐值核 LIFO 反序 + TOP 归零 ---- [解析]
 * 就是取证 6 的 G2 上表: 8 压之后 sw=0x0000(TOP 走完一圈回 0 且**无溢出** —— 第 9 次
 * 压栈才报 0x3a41), 弹栈序是入栈序的反序(逐值核过)。
 * 期望 o0 == i0(第 i1 = 7-kk 次弹出的值, 0 基),
 *      o1 == 弹完 sw(低 16 位)| 峰值 sw(高 16 位)== 0x00000000。
 * 两个 sw 打包进一个字段而不是分两处: 它们本来就是同一次实测的两半("压满不溢出"
 * 与"弹空回原点"), 任一非 0 即本条 FAIL —— 拆成两条只会多占一个词干。 */
uint64_t k_stack_fld8_st8_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    int j;
    uint64_t x = 0;

    for (j = 0; j < 8; j++) {
        fput(j, XVEC[j]);
        fput(8 + j, IB_POISON);
    }
    for (i = 0; i < iters; i++) {
        for (j = 0; j < 8; j++)
            __asm__ volatile("fildll (%[s])"
                             : : [s] "r"((const void *)&g_f[j]) : "memory");
        for (j = 0; j < 8; j++)
            __asm__ volatile("fistpll (%[d])"
                             : : [d] "r"((void *)&g_f[8 + j]) : "memory");
    }
    for (j = 0; j < 8; j++)
        x ^= fget(8 + j);
    return x;
}


/* ---- fxch_st3: 满栈上 FXCH %st(3) —— 只换 ST0 与 ST(3)、其余六格不动 ---- [解析]
 * 取证 6 d)/G3 的形状: ST0 <-> ST(3) 互换而 TOP 不变。八行换的是**栈上的值**(整条
 * 阶梯按 kk 轮转), 下标恒为 3 与词干名一致 —— 词干名写的是被钉住的那个形, 八行走
 * 同一个形(P1 的 fild_fistp_d_rt 同一条纪律)。
 * 物理槽 s 装 XVEC[(s+kk)&7] => 换前 ST0 = XVEC[kk] = i0、ST(3) = XVEC[(kk+3)&7] = i1。
 * 期望 o0(换后第 1 个弹出值 == slot0)== i1, o1(换后第 4 个弹出值 == slot3)== i0
 * —— 两半合起来就是"互换", 而且是纯置换、不含任何舍入模型。
 * TOP 不变不在字段里, 但它是这个等式成立的前提: TOP 一旦被改动, 整个弹栈阶梯整体
 * 平移, o0/o1 同时错(stack_top_after_fild 与 fincstp_fdecstp_rt 另外直接钉 TOP)。 */
uint64_t k_fxch_st3_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    int j;
    uint64_t x = 0;

    for (j = 0; j < 8; j++) {
        fput(j, XVEC[j]);
        fput(8 + j, IB_POISON);
    }
    for (i = 0; i < iters; i++) {
        for (j = 7; j >= 0; j--)
            __asm__ volatile("fildll (%[s])"
                             : : [s] "r"((const void *)&g_f[j]) : "memory");
        __asm__ volatile("fxch %%st(3)" : : : "cc");
        for (j = 0; j < 8; j++)
            __asm__ volatile("fistpll (%[d])"
                             : : [d] "r"((void *)&g_f[8 + j]) : "memory");
    }
    for (j = 0; j < 8; j++)
        x ^= fget(8 + j);
    return x;
}


/* ---- fldst_st1_to_st0: FLD %st(1) 把原 ST(1) 的副本压成新 ST(0) ---- [解析]
 * 计划 99 行的括注写的是 FSTP、词干名写的是 fldst: 取证 6 d)/G3c 里这两个动作是
 * 一件事的两半(压一份 ST(1) 的副本 -> 立刻弹掉它, 剩下的新 ST(0) 就正是原 ST(1))。
 * 本条把两步都发出去, 判据取**弹回来的第一格**: 它必须正是压栈前的 ST(1)。
 * 序列: fildll A -> fildll B -> fld %st(1) -> fstpt(第一格); 余下两格弹掉但不上表。
 * 期望 o0 == ext_form(i0).mant, o1 == ext_form(i0).se(低 16)| 弹完 sw(高 16),
 *   弹完 sw 期望 0(三格弹完 TOP 回 0、无 IE|SF)。
 * "TOP 退了一格"是通过值序钉住的: 若 FLD 没压栈, 第一格弹回来的是 B 而不是 A,
 * o0 当场错 —— 不需要第三个字段(与 fxch_st3 同一处置)。 */
uint64_t k_fldst_st1_to_st0_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *a = fput(0, XVEC[2]);
    const void *b = fput(1, XVEC[3]);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fildll (%[a])\n\tfildll (%[b])\n\t"
                         "fld %%st(1)\n\tfstpt (%[t])\n\tfstpt (%[t])\n\tfstpt (%[t])"
                         : : [a] "r"(a), [b] "r"(b), [t] "r"(&g_t[0]) : "memory");
    return tget_m(0) ^ (uint64_t)tget_s(0);
}


/* ---- fincstp_fdecstp_rt: TOP 只加/只减的走位往返 ---- [解析]
 * 取证 6 c): fincstp 每步 +0x0800 且 8 步回环, fdecstp 反向、从 0 退到 7。本条**不发
 * 一条浮点指令**(栈上一格都没有), 于是它是全组唯一一条"TOP 与 tag/值彻底解耦"的
 * 判据: 把 fincstp 实现成"多压一格"或"连 tag 一起动"的翻译器在这里必错, 而其它五
 * 条都有值序当掩护。
 * 期望 o0 == (n&7)<<11(n=kk+1 次 fincstp), o1 == 0(再 n 次 fdecstp 回到起点)。
 * ★ 方向与压栈相反: finit 后 TOP=0, 压栈是 -1、fincstp 是 +1 —— 两条都在本节上表,
 *   拿同一条走位规则混过去就会正好错一档。 */
uint64_t k_fincstp_fdecstp_rt_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    int j;

    for (i = 0; i < iters; i++) {
        for (j = 0; j < 8; j++)
            __asm__ volatile("fincstp" : : : "memory");
        for (j = 0; j < 8; j++)
            __asm__ volatile("fdecstp" : : : "memory");
    }
    /* 循环是自平衡的 -> 末态恒为 TOP=0, 签名会退化成 0; 因此循环外再走 3 步读 sw:
     * 既不随 iters 变(每次进循环都是整周期), 又不是全零。 */
    for (j = 0; j < 3; j++)
        __asm__ volatile("fincstp" : : : "memory");
    __asm__ volatile("fnstsw (%[w])" : : [w] "r"(&g_sw[0]) : "memory");
    return (uint64_t)swget();
}


/* ---- ffree_tag: FFREE 之后 tag 字里那两位变 11、TOP 不动 ---- [解析]
 * 取证 6 c) 实测: 每寄存器两位、物理格 p 在 bit 2p、置 11 = 空; 而这件事在**状态字
 * 里一位都不反映**, 只能从 fnstenv 的 tag 字看(环境头三字段 cw/sw/tw, b13 核过)。
 * 八行走 k = 0..7, 但没有 switch: 先把 TOP 用 fincstp 挪到 k(只动 TOP、不动值),
 * 再发字面量 `ffree %st(0)` —— ST(0) 就是物理格 (TOP+0)&7 = k。这样"下标八档"与
 * "助记符必须是字面量"两件事同时成立(取证 6 c) 用 4 项栈反证过这个映射:
 * TOP=4 时 ffree st0 清的是 bit8-9)。
 * 序列: 压满 8 格(tag 全 valid = 0x0000) -> fincstp ×kk -> ffree %st(0) -> fnstenv。
 * 期望 o0 == 3u<<(2*kk)(tag 字), o1 == 环境里的 sw == (kk&7)<<11 —— 后者钉的是
 *   "ffree 不动 TOP", 而 TOP 这一档**不是** 0, 所以不会被"反正回绕到 0"蒙过去。
 * ★ 本条**不把栈弹空**就返回(8 格留在上面): 弹一个被 ffree 掉的格子会碰上
 *   "向无效格存回"这个未实测形状, 而那不属于本条要钉的事; 隔离靠下一内核入口的
 *   X87_BEGIN()(文件头"内核纪律"第一条就是不指望进出平衡)。 */
uint64_t k_ffree_tag_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    int j;
    const void *s = fput(0, XVEC[2]);

    for (j = 0; j < 8; j++)
        __asm__ volatile("fildll (%[s])" : : [s] "r"(s) : "memory");
    /* 反复 ffree 同一格是幂等的: 既不会溢出(没有任何压栈), 末态 tag 也恒为 0x0003
     * —— 定时长体要的是"被测指令在圈里", 不是把整条 P5 序列重跑一遍。 */
    for (i = 0; i < iters; i++)
        __asm__ volatile("ffree %%st(0)" : : : "cc");
    __asm__ volatile("fnstenv (%[e])" : : [e] "r"(&g_env[0]) : "memory");
    /* ★ 清栈再返回: 上面的序列故意留满 8 格(见注), 但"满栈"一旦漏到框架层, 就会让
     * ib_now() 的 double 往返(返回值经 ST(0))与 libc 的 %f 转换一起溢出成 indefinite
     * NaN —— 实测表现是本用例 lat/tput 测不出(报警 el=0)且 window 列打成 -nan。
     * 隔离不能只靠"下一内核入口的 finit": 框架的 ib_now/printf 就在本函数返回后立即调用。
     * finit 直接重置 FPU(不走"向无效格存回"那条未实测路), 且判据读数已取完, 不影响结果。 */
    {
        uint64_t r = (uint64_t)envget16(4) ^ ((uint64_t)envget16(2) << 16);
        __asm__ volatile("finit" : : : "memory");
        return r;
    }
}


/* ---- fdiv_zero_ze: 除零与 0/0 的符号组合 ---- [解析]
 * 取证 7 e) 前半 + G5 实测(masked、ES 永远为 0):
 *   非零/±0 -> 只置 ZE(0x0004) + 结果 ±Inf, 符号 = 两操作数符号亦或;
 *   0/0 的四档符号组合**全部**给同一个 -QNaN indefinite(c000….ffff) 且只置 IE。
 * 入值八档就是那两组符号: kk<4 为 ±1 / ±0(asig=(kk>>1)&1、bsig=kk&1),
 *               kk>=4 为 ±0 / ±0(同公式)。
 * 期望 o0 == 结果 mant, o1 == 结果 se | (sw<<16):
 *   kk<4:  0x8000…. / 0x7fff|亦或<<15 / sw=0x3804
 *   kk>=4: c000….    / 0xffff              / sw=0x3801
 * TOP=7 是因为序列取 fldl+fdivl(不弹栈), 与 G5 的读数同形 —— 用 fdivp 就变成 TOP=7
 * 但少一项, 两者不可混读(这就是文件头说的"省掉操作数次序的名字就是下一个错读")。 */
uint64_t k_fdiv_zero_ze_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *a = fput(0, D_ONE);
    const void *b = fput(1, 0);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fldl (%[a])\n\tfdivl (%[b])\n\tfstpt (%[t])"
                         : : [a] "r"(a), [b] "r"(b), [t] "r"(&g_t[0]) : "memory");
    return tget_m(0) ^ (uint64_t)tget_s(0);
}

/* fsqrt_neg_ie 的定时长体与 kat 共用同一张入值表(取 SQRTA[0]): 本条要量的是
 * fsqrt 自己, 序列形与取值体一致 —— 否则定时长数字与判据不同形(其余各条同此)。 */
uint64_t k_fsqrt_neg_ie_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *a = fput(0, SQRTA[0]);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fldl (%[a])\n\tfsqrt\n\tfstpt (%[t])"
                         : : [a] "r"(a), [t] "r"(&g_t[0]) : "memory");
    return tget_m(0) ^ (uint64_t)tget_s(0);
}


/* ---- fistp_oe: 浮点->窄整型存回越界 ---- [解析]
 * ★ 词干名里的 "oe" 是计划 103 行写的, **实测不是 OE**: G7b 三档同形 = 只置
 *   IE(0x0001) 且写**该宽度的整数最小值**(m32=0x80000000 / m16=0x8000), 且越界档
 *   连 2^N-0.5 那行(先按 RC=RNE 舍、ties 取偶 -> 正好撞上上限)**也不置 PE**。
 *   名字不改(口径与 P3 同: 计划词干名原样、判据按实测), 差异记进过程报告。
 * 八档 = m32/m16 各四: 2^N / 2^N-0.5 / -2^N(在范围内!) / 远越界。
 *   m32: 2^31、2^31-0.5、-2^31、2^40      m16: 2^15、2^15-0.5、-2^15、2^20
 * 期望 o0 == 按该行宽度符号扩展的写回值, o1 == sw(低 16)| 未越写标志(1=>只写了 W 字节):
 *   越界档 sw=0x0001 且值=该宽度最小值; -2^N 档 sw=0x0000 且值同样=最小值。
 *   ★ 这两档的 o0 **字面相同时**, 只靠 sw 分开 —— 那正是本节最有信息量的一行:
 *     "整数最小值"既是合法结果又是错值填充, 拿写回值当唯一判据会把越界读成正常。
 * 序列的 sw 取在 fistp 之后(见本节头三个例外的说明)。 */
uint64_t k_fistp_oe_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    void *d = fput(8, IB_POISON);

    for (i = 0; i < iters; i++) {
        tput80(0, X1, M80_E(3));                      /* 8: 在 m32/m16 都量程内 */
        __asm__ volatile("fldt (%[s])\n\tfistpl (%[d])"
                         : : [s] "r"(&g_t[0]), [d] "r"(d) : "memory");
    }
    return fget(8);
}

uint64_t k_stack_underflow_is_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;

    /* finit 必须在循环里: 本条量的是"空栈弹一次", 不弹回去第二圈就不是空栈了 */
    for (i = 0; i < iters; i++)
        __asm__ volatile("finit\n\tfstpt (%[s])\n\tfnstsw (%[w])"
                         : : [s] "r"(&g_t[5]), [w] "r"(&g_sw[0]) : "memory");
    return tget_m(5) ^ (uint64_t)swget();
}


uint64_t k_denormal_ue_tp(unsigned long long iters)
{
    return x87_bin80_tp(iters, XBDEN);
}

uint64_t k_precision_pe_tp(unsigned long long iters)
{
    return x87_bin80_tp(iters, XBPRC);
}

uint64_t k_fnclex_clears_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *a = fput(0, D_ONE), *b = fput(1, 0);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fldl (%[a])\n\tfdivl (%[b])\n\tfnstsw (%[w])\n\tfnclex\n\tfstp %%st(0)"
                         : : [a] "r"(a), [b] "r"(b), [w] "r"(&g_sw[0]) : "memory");
    return (uint64_t)swget();
}


uint64_t k_fcom_cc_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *pa = fput(0, FCOP[0][0]);
    const void *pb = fput(1, FCOP[0][1]);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fldl (%[a])\n\tfcoml (%[b])\n\tfstpt (%[t])"
                         : : [a] "r"(pa), [b] "r"(pb), [t] "r"(&g_t[0]) : "memory");
    return (uint64_t)swget() ^ tget_m(0);
}


uint64_t k_fcompp_cc_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *pa = fput(0, FCPP[0][0]);
    const void *pb = fput(1, FCPP[0][1]);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fldl (%[a])\n\tfldl (%[b])\n\tfcompp"
                         : : [a] "r"(pa), [b] "r"(pb) : "memory");
    return (uint64_t)swget();
}


uint64_t k_fsubr_pair_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *pa = fput(0, FSUBAB[0][0]);
    const void *pb = fput(1, FSUBAB[0][1]);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fldl (%[a])\n\tfldl (%[b])\n\tfsubp %%st,%%st(1)\n\tfstpt (%[t])"
                         : : [a] "r"(pa), [b] "r"(pb), [t] "r"(&g_t[0]) : "memory");
    return tget_m(0) ^ (uint64_t)tget_s(0);
}


uint64_t k_fisubr_m64_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *pa = fput(0, FIA[1]);
    const void *pc = fput(2, FIC[4]);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fldl (%[a])\n\tfildll (%[c])\n\tfsubrp %%st,%%st(1)\n\tfstpt (%[t])"
                         : : [a] "r"(pa), [c] "r"(pc), [t] "r"(&g_t[0]) : "memory");
    return tget_m(0) ^ (uint64_t)tget_s(0);
}


uint64_t k_fscale_int_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *pn = fput(0, FSN[0]);
    const void *pa = fput(1, FSA[0]);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fldl (%[n])\n\tfldl (%[a])\n\tfscale\n\tfstpt (%[t])\n\tfstpt (%[t])"
                         : : [n] "r"(pn), [a] "r"(pa), [t] "r"(&g_t[0]) : "memory");
    return tget_m(0) ^ (uint64_t)tget_s(0) ^ ((uint64_t)swget() << 32);
}


uint64_t k_fxam_kinds_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    const void *pv = fput(0, FXAV[5]);

    for (i = 0; i < iters; i++)
        __asm__ volatile("fldl (%[v])\n\tfxam\n\tfnstsw (%[w])\n\tfstpt (%[t])"
                         : : [v] "r"(pv), [w] "r"(&g_sw[0]), [t] "r"(&g_t[0]) : "memory");
    return (uint64_t)swget() ^ tget_m(0) ^ (uint64_t)tget_s(0);
}


/* ---- fstsw_allbits: 同一个状态字的三种读法逐位相等 ---- [解析]
 * 三种读法是三条不同的编码: `fnstsw m16`(DD /6)、`fnstsw ax`(DF /4 无等待)、
 *   `fstsw ax`(9B + DF /4, 带等待形) —— 操作码不同、写回目标不同(内存 16 位 vs AX),
 *   所以"三种读法同字"不是一句空话: 把 m16 形按 32 位写、或者把 AX 形只按低 8 位
 *   补零, 都只会在某一种读法上错(取证 a) 里"fnstsw m2byte 与 fnstsw ax 两路同字"
 *   就是本条的两个锚点, 它同时钉住了状态字的**位序**(写错位序则三路会一起错、但
 *   与 o0 的期望对不上)。
 * 期望: o1 == 0(两个 XOR 都是 0), 而 o0 == 本档的期望 sw(表在 x87_dirty 注里)。
 * C 侧锚点 = _tmp/x87_p7chk.c 的 G0/G0b/G1 三行(入口默认值、归零后同字、同一脏态
 *   重复读同字 + fnstenv 镜像与 fnstsw 掩码两条路径在低 6 位同字); AX 形那两路无对应物,
 *   见节头 ②。
 * ★ 16 位里有两位在本组结不到非零值: bit7(ES) 与 bit15(B)。取证 a) 实测 masked 路径
 *   不置 ES, 而 B 需要 unmasked 挂起异常 —— 同一实测里 unmasked 会在**下一条** x87 指令
 *   处交付 #MF、进程直接带走, 所以这两位的"三读法一致"无法在内核里证, 写在
 *   这里而不是悄悄少测(与 a)/c) 那两处同一处置)。 */
uint64_t k_fstsw_allbits_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;
    uint16_t ax1 = 0, ax2 = 0;      /* 必须起零: iters=0 时循环不转, 不初始化就是读垃圾
                                     * (-Wall 的 maybe-uninitialized 就是抬这一条) */

    x87_dirty(0);
    for (i = 0; i < iters; i++) {
        __asm__ volatile("fnstsw (%[m])" : : [m] "r"(&g_sw[0]) : "memory");
        __asm__ volatile("fnstsw %%ax" : "=a"(ax1));
        __asm__ volatile("fstsw %%ax" : "=a"(ax2));
    }
    return (uint64_t)swget() ^ ((uint64_t)ax1 << 16) ^ ((uint64_t)ax2 << 32);
}


/* ---- fninit_defaults: 任意一个脏态, fninit 之后必回默认 ---- [解析]
 * 计划 109 行写的是"CW=0x037f、SW=0x4020、tag 全空"; 其中的 SW=0x4020 已被实测撤回
 * (取证 h ③: finit 与 fninit 之后都是 cw=0x037f / sw=0x0000 / tag=0xffff, b1/b11 双机同
 * 值), 所以本条的期望 o1 是一个**常量**、八档全同:
 *   o1 == cw_after | (sw_after<<16) | (tag_after<<32) == 0x0000ffff0000037f。
 * 脏态由 x87_dirty 造(与上一条共用), o0 == sw_before | (cw_before<<16) 逐档不同,
 * 用它验证"归零前确实脏": 七档的 sw 带标志或 CC 位、档 3 的 cw 是 0x007f —— 没有 o0
 * 这一列, 一个"什么都不做的 fninit"也能过 o1。
 * ★ 读序不能倒: tag 只能从 fnstenv 拿(环境头三字段 cw/sw/tw, 取证 b13), 而 fnstenv 存完
 *   **顺手把所有异常屏蔽**(把活动控制字改成全屏蔽形) —— 先取 tag 就把 cw_before 那个
 *   读数洗掉了, 所以档 3 必须 fnstcw 在前、fnstenv 在末尾且不参与 o0。
 * ★ 只登记归零**后**的 tag: 归零前的 tag 要按"哪几个物理格被写过"建模(取证 c) 里
 *   ffree/溢出都影响它), 而判据 o1 只需要"归零后 = 全空"; 档 3 造了八个 valid 格,
 *   翻译器若只刷 TOP 不刷 tag, 它的 tag_after 就不是 0xffff -> 本条能抓到。
 * C 侧锚点 = _tmp/x87_p7chk.c 的 G0(入口 sw=0000/cw=037f) 与 G3(脏态归零后 cw 回入口、
 *   sw 归零) 两行; tag 与 TOP 的归零只有本条的 fninit+fnstenv 能证, 见节头 ③。 */
uint64_t k_fninit_defaults_tp(unsigned long long iters)
{
    X87_BEGIN();
    unsigned long long i;

    for (i = 0; i < iters; i++) {
        x87_dirty(3);
        __asm__ volatile("fnstcw (%[c])\n\tfnstsw (%[w])\n\tfninit\n\t"
                         "fnstcw (%[c])\n\tfnstsw (%[w])"
                         : : [c] "r"(&g_cw[5]), [w] "r"(&g_sw[5]) : "memory");
    }
    /* 循环外不再补读数: 循环体末态恒为归零后的 cw=0x037f/sw=0x0000 -> 签名 = 0x037f,
     * 不随 iters 变也不是全零(定时长签名要的就是这两条)。 */
    return (uint64_t)cwget(5) ^ ((uint64_t)swgetn(5) << 16);
}
