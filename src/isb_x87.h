/* isb_x87.h -- x87 组跨文件共享声明(由 tmp/x87_split/split_x87.py 生成) */
#ifndef ISB_X87_H
#define ISB_X87_H

#include "ib_core.h"
#include "ib_buf.h"
#include "isb_x87_kat.h"
#include <stdint.h>

typedef struct { uint64_t mant; uint16_t se; } xb80;   /* m80real: 恰 10 字节 */


#define IB_POISON 0xaaaaaaaaaaaaaaaaULL                 /* 写宽哨兵的预置值 */


/* 整数值 -> double 位形(RN, 就近取偶)的推导式**不在本文件里实现**: 它是[解析]期望,
 * 而本框架的 kat 契约是"探针只填实测值、由框架跟表比", C 侧再无别的引用点 ->
 * 留一份看死的参考实现会破"工具干净纯净"。算式落在 kat_audit.py 的
 * p1_fild_fstp_q_dbl()(B1-f), 文字版(手工校对过的三个锚点):
 *   hi = |v| 的位长 - 1; shift = hi - 52; shift <= 0 则精确可表示; 否则把
 *   keep = u >> shift(53 位, 含隐含 1)按 ties-to-even 进位, 撑到 54 位则
 *   keep >>= 1 且 hi++ -> bits = sign<<63 | (hi+1023)<<52 | keep 的低 52 位
 *   2^53+1 -> 0x4340000000000000;  INT64_MAX -> 0x43e0000000000000;
 *   -2^63  -> 0xc3e0000000000000   (三个锚点均与本机 PE 实测同字)
 *   INT64_MAX 那条要格外小心: 2^63-1 距 2^63 仅 1、距上一档 2^63-1024 有 1023,
 *   故 RN 是**舍上到 2^63**(0x43e0...), 不是向零舍的 0x43dfffffffffffff —— 后者是
 *   "不大于 INT64_MAX 的最大 double", 拿它当期望会把正确实现判成违约。 */

/* 每个 x87 内核/探针入口先把 FPU 归零: TOP=0、标记全空、挂起异常清零、控制字回默认
 * 0x037f(PC=64 位扩展档)。理由与代价见文件头; special 原注里那句"fistpll 编出来是
 * df /3, 按 SDM 是 FIST m64int 不弹"已被取证 1/2 订正(见文件头 h 项): DF/7 就是弹栈
 * 形, 入口 finit 依然要留 —— 因为它同时钉住控制字与状态字, 不只是清栈。 */
#define X87_BEGIN()  __asm__ volatile("finit" : : : "memory")


/* =====================================================================
 * 2) P2 舍入模式(5 条): fldcw 置 RC 之后做浮点->整数存回, 四档各一词干, 加一条
 *    "只改 RC 两位"的往返。位段按取证 g1 的双机实测: **RC = 控制字位 10-11**
 *    (00 就近取偶 / 01 向 -inf / 10 向 +inf / 11 向零), 不是常被抄成的位 2-3(那
 *    是异常屏蔽位)。旧 special 的 fistp 只测默认的 RN 档, 四档全走是本节的增量。
 *    入值口径: 一律 q/4(q 为带符号小整数, 见 RVQ) -> 结果恒为"整数 + r/4", 于是
 *    平局(r==2)、要进位(r==3)、舍去(r==1)、无舍入(r==0)四种情形纯整数就能判, 且
 *    四档在本向量上的结果签名两两互异(单档不可能同时等于四种签名) => [解析]。
 *    计划里"源值 -3.75/+2.5/-2.5/+3.5/边界整数" = RVQ 前四项 + 两个平局(±0.5) +
 *    两个精确整数(3.0/-4.0); 计划里"fistp m64int、fistp m32int"两个存回宽度在同
 *    一内核里共用同一次 fldcw(o0 = m64int 结果, o1 = m32int 结果) —— 这也是 P2
 *    恰好 5 条(4 档 + rc_fstcw_rt)而不是 8 条的原因。
 *    ★ 表里不放状态字(SW): 取证 i 只坐实了**正侧**的 C1 读法("量级变大置 1"), 负
 *      侧"向 -inf 舍 => 量级变大"(如 -3.75 在 RD 档)双机都没实测过。拿没验过的方向
 *      约定当[解析]期望, 正是本组最该防的那类错(取证 g0 的成因就是"我以为硬件是这个
 *      意思")。RC 的效应已由 o0 的四档互异签名钉死, 标志一侧留给 P6 连同补取证做。
 *    例外声明: q4bits() 是本文件第二处让 C 的浮点参与取值, 与 qbits() 同式 —— 只做
 *      一次 |q| < 2^24 的整数->double **精确转换**, 不做任何浮点算术, 函数自平衡。
 *    本节的验证通道: _tmp/x87_p1chk.c 的 H 节(fesetround 四档 x llrint(q/4) 共 32 行,
 *    期望由 rc_expect() 纯整数现算) + F 节(同一批 long double 上 cast 与 llrint 的
 *    分家)。两形态反汇编: glibc 的 __fesetround 体内就是 fnstcw/fldcw, __llrint 体内
 *    是一条裸 fistpll, 而 C 的强转是"临时把 RC 拧到 11b 再 fistpll" —— 于是
 *    "RC 真的占控制字两位、真的影响 FISTP 存回"在 C 侧被独立复现了一遍。
 *    ★ 本轮在这一节抓到的是**自己的期望算错**: rc_expect 初版拿带符号余数 q%4 分档,
 *      负侧两个平局(-2.5 / -0.5)被判成向 -inf 舍, 两台机器同时 rcok=0(30/32)。改法
 *      是小数部分一律取非负余数 m=((q%4)+4)%4。Python 侧 kat_audit.rc_int() 用的是
 *      floor-divmod, 本来就是对的 —— 两份实现要抓的正是这一类错。
 * ===================================================================== */

/* RC 编码 -> 控制字: finit 默认值 0x037f 之上只改位 10-11, 其余位一律保持默认。
 * 为什么不让屏蔽位也跟着飘: 四档之间唯一的自变量就该是 RC(取证 b: masked 与
 * unmasked 是两条路径, 谁都不该在本节的差异里出现)。
 * 写成"先清后置"而不是直接 OR(与 PC_CW 同形): 默认值 0x037f 的位 10-11 恰好是 0,
 * 直接 OR 也能对, 但"对不对"就取决于一个没写在式子里的事实 —— 而同一个事实的 PC
 * 位段却是 11b(见 PC_CW 的注), 两处不同形迟早会把这里也带错。 */
#define RC_CW(enc)  ((uint16_t)((0x037fu & (uint16_t)~0x0C00u) | \
                                ((uint16_t)(((enc) & 3u)) << 10)))


#define RC_ARM(sn, enc)                                                        \
    static uint64_t k_##sn##_tp(unsigned long long iters)                      \
    {                                                                          \
        return rc_fistp_tp_core(iters, (enc));                                 \
    }                                                                          \
    static void k_##sn##_kat(int kk, ib_kv *g)                                 \
    {                                                                          \
        rc_fistp_core(kk, (enc), #sn, g);                                      \
    }


/* =====================================================================
 * 3) P3 精度控制(3 条): fldcw(PC) -> fadd/fmul m64real -> fstp m80real -> fnstcw。
 *    序列与三个词干名按计划原样, 但**判据换了**: 计划把 P3 划给[档间]("三档结果
 *    逐位相同 + 控制字回读一致"), 依据是"现代 Intel(含 box31 i3-4150)忽略 PC";
 *    取证 g0/g2 的重做实测否掉了这个前提 —— 同一算式三档给出三个互异位形, 于是
 *    "三档逐位相同"在两台真机上都是 FAIL。现在每条各钉自己档位的[解析]期望:
 *      o0 = 精确结果舍到本档位宽(w = 24/53/64, RC 保持默认 00b)后的 m80 尾数;
 *      o1 = 该 m80 的指数域 | (fnstcw 读回的控制字 << 16) —— 把"档真设进去了且
 *           原样读回"与"结果位形"落在同一个字段里(表只有两个输出字段)。
 *    为什么还要留一道档间关系(kat_audit.py 的 pc_arm_relation): 每档的解析期望共用
 *    同一个舍入器 rnd_sig(w), 如果 w 在某处被写死, 三条会同时"自洽地全过"; 而
 *    pc24_fadd 与 pc53_fadd 用的是**同一个入值向量**, "两档结果必须按模型预测的那
 *    几行不同"是一条不受这个共因影响的独立断言(计划要的档间对照还在, 只是从唯一
 *    判据降为第二道)。
 *    PC=01b 是保留编码(实测与 64 档同值), 不取 —— 保留区是实现自便, 拿它当期望
 *    等于赌微架构。finit 后本就是 64 档, 所以 pc64_fmul 不写 fldcw 也能过, 但三条
 *    序列同形(仍显式 fldcw), 顺带让"设 64 档"这条路自己上表。
 *    本节不碰异常屏蔽位(恒 0x037f 的低 8 位), 所以 PC 是三档之间唯一的自变量。
 *    验证通道边界: **C 里没有 PC 的对应物** —— fenv.h 只暴露舍入方向(fesetround),
 *    不暴露尾数位数, 所以 _tmp/x87_p1chk.c 不接 P3(P7 节头那句"库函数不等于指令"
 *    在这里反过来成立: 库没有提供的语义, 就不能假装有第二条路)。
 * ===================================================================== */

/* PC 编码 -> 控制字(位 8-9)。00=24 位、10=53 位、11=64 位(与取证 g2 的实测档位一致)
 * ★ 必须先清后置再 OR: finit 默认控制字 0x037f 的位 8-9 **本来就是 11b**(64 位档),
 *   只 OR 永远清不掉那两位 —— 结果是 PC_CW(0) 静默地就是 64 档、三档里的"24 档"
 *   根本不存在(而 pc53 因为要设 10b 反而正常)。这个坑与 RC 相反(那里默认位是 0),
 *   所以两个宏都写成同一种形式: 先把档位域清成 0 再置进去。 */
#define PC_CW(enc)  ((uint16_t)((0x037fu & (uint16_t)~0x0300u) | \
                                ((uint16_t)(((enc) & 3u)) << 8)))


/* double 位形的纯整数式: D_POW2(k) = 2^k, D_2PN1(n) = 2^n + 1(0 <= n <= 52)。
 * 为什么用式子而不是抄 hex: 本节的期望全落在"最低那一位在不在"上, 一个抄错的
 * 指数字段会让两档得到同一个结果、看起来却像"硬件没 honor PC"—— 正是取证 g0 的
 * 形状。两个式子都能用取证 g2 的实测常数反验(2^27+1 = 0x41A0000002000000)。 */
#define D_POW2(k)   ((uint64_t)((int64_t)1023 + (int64_t)(k)) << 52)

#define D_ONE       D_POW2(0)

#define D_2PN1(n)   (D_POW2(n) | (1ULL << (52 - (n))))


/* 三条共用一个包裹宏: tp/core 的函数名都是参数, 于是"两条共用加法内核、第三条换
 * 乘法内核"这件事在表里就是一行一行看得见的; 词干串由 #sn 从同一个 token 推出
 * (理由同 RC_ARM)。 */
#define PC_ARM(sn, enc, tp_fn, core_fn)                                        \
    static uint64_t k_##sn##_tp(unsigned long long iters)                      \
    {                                                                          \
        return tp_fn(iters, (enc));                                            \
    }                                                                          \
    static void k_##sn##_kat(int kk, ib_kv *g)                                 \
    {                                                                          \
        core_fn(kk, (enc), #sn, g);                                            \
    }


/* =====================================================================
 * 6) P6 异常(masked 路径, 7 条): 每类异常置哪几位 + 同时结果是什么位形。
 *    入值口径全取自取证 7 e) 的两张实测表(G5/G7a-G7d), 一行为一档、逐行可追溯到
 *    _tmp/x87_c_pe.txt 里的那一行 —— 本节的期望不包任何未实测档(计划 103 行的
 *    "ES=1"、sqrt(+dmin) 的无理尾数那两处已按实测换掉, 见文件头 h) ②)。
 *    三条全节约束:
 *      - 全程 CW=0x037f 全屏蔽(X87_BEGIN 的 finit 已钉), 因为取证 7 a) 实测 unmasked
 *        路径上 #MF 会在**下一条** x87 指令处交付、进程直接带走 —— 计划 105 行的
 *        "每条出口 fnclex"在这条路径上无事可做(ES 恒 0、挂起异常取不到), 而
 *        fnclex_clears 本身就是量 fnclex 的那一条。
 *      - sw 读数一律取在任何存回/弹栈之前(取证 7 e) 末段); **两个例外**是
 *        fistp_oe 与 fnclex_clears: 那里的 IE/SF 就是存回/栈操作自己置的, 取早了
 *        读不到那一位(两处的实测行里都没 C1, 所以不掩盖任何位)。
 *      - 字段不够用的时候按 P3 的打包惯例: o1 = 结果 se(低 16) | sw(高 16)。
 *    m80 入值不再手抄十六进制, 全走下面三个式子(每个都能在取证 7 的实测行里反验):
 *      M80_E(k)   = 16383+k  -> 1.xxx x 2^k 的指数域(偏置 16383)
 *      X1         = 显式整数位=1、其余全 0 的尾数 -> 1.0 x 2^k
 *      M80_P2MH(N)= 2^N-0.5 的尾数: (2-2^-N) x 2^(N-1) 的 mant = -2^(63-N)(回绕)
 *        反验: N=31 -> 0xffffffff00000000 / 指数 M80_E(30) = 2^31-0.5(与探针
 *        E_2P31M 同字), N=15 -> 0xffff000000000000 / M80_E(14) ✓
 *
 *    C 调用组合交叉验证通道(与内联指令那条完全另一条路): _tmp/x87_p6cchk.c ——
 *    **一条 asm 都不写**, 除法/开方/乘加/llrint 全交编译器挑指令, 状态字经
 *    fegetenv 读回。双机各 63 行、各自 bad=0, 剥掉工具链列后 diff=0(边车
 *    _tmp/x87_p6cchk.strip, 每条剥列规则都带"是哪一拍哪一行让它进来"的出处);
 *    指令归因取 _tmp/_x87_p6cchk_dis_{exe,elf}.txt(objdump -d 逐函数计数)。
 *    ★ 判据只能走硬件字: 两机实测 fegetenv 状态字的**低 6 位**与内核 fnstsw 读到的
 *      逐字相同(所以下面 16 档的 sw 低字节 0x32/0x28/0x22/0x02/0x00 可直接当期望),
 *      而 fetestexcept 在 glibc 上永远报不出 DE —— V 节两类数据把这条钉住:
 *      五行 xorTC=0000(两家的 FE_* 位位置都等于 SW 位序, 不存在"位序分家") +
 *      FE-enums 行 box31 allTC=3d deTC=0 vs PE allTC=3f deTC=2(glibc 的 FE_ALL_EXCEPT
 *      里没有 bit1) -> 差的是库的可见性, 不是 x87 的行为。
 *    逐词干锚点(格式: 词干 <- C 形状 | 双机读数 | objdump 坐实):
 *      fdiv_zero_ze  <- P1..P7(d/f/L 三形除法 + 符号亦或两档 + 0/0 四符号) |
 *                        hw=04/04/04/04/01/01/00 两机逐字等 |
 *                        sec_p 里 fdivrp **7 次**(= 七行各一条, PE 与 glibc 同数) +
 *                        fldl/flds/fldt/fstpt/fucomi/fabs —— 编译器挑的是 fdivr 反除,
 *                        与内核的 fldl+fdivl 是不同指令形、同一件事
 *      fsqrt_neg_ie  <- Q1..Q8(+1/-1/-4/-0/-Inf/-QNaN/+4/-dmin) | hxA(= hw & ~IE)
 *                        两机同字, 只有 Q8 含 DE(=02) -> 取证 7 那条"DE 跟着操作数需要
 *                        格式转换走"在纯 C 路径上复现; ieTC 分家(PE 0 / box31 1)
 *                        -> 边界④
 *      fistp_oe      <- R1..R6(llrint 在 int64 量程内外, 含 -2^63 那行同字不同义) |
 *                        fIe 两机同(1/0/0/1/1/0) | 指令**在 libm 里**: PE 的 _llrint =
 *                        fldl+fistpll, glibc 的 __llrint = fldl+fistpll+fwait, 两侧都
 *                        **没有 fldcw** -> 用的是当前 RC, 与内核 fistp m64 同一条指令
 *                        (不是 fisttp 截断); m32/m16 两半见边界③
 *      denormal_ue   <- S 节 B 行 8 档(mk80 位级构造, 与内核 XBDEN 逐位同入值) |
 *                        flgOk=1 全 8 档、hw=32/32/32/02/02/00/32/22 两机同字 |
 *                        指令在 run_brow(S/T 两节都只是循环调它; PE 计数: fldt 8 +
 *                        fstpt 7 + fmulp/faddp/fdivrp 各 1, glibc 同构但 10/9) ——
 *                        正是内核那三条乘/加/除, 但由编译器排
 *      precision_pe  <- T 节 B 行 8 档(内核 XBPRC 同入值) | hw=20/20/20/20/20/00/00/28
 *                        两机同字, 最后一档 2^16383*2 是全组唯一真 OE |
 *      stack_underflow_is <- C 里构造不出未配对弹栈 -> 边界①(内核独路)
 *      fnclex_clears <- 不进 C 通道 -> 边界②: PE 的 _feclearexcept 反汇编是
 *                        fldenv+fnstenv(整环境覆盖)+fnclex 1 次, glibc 是 fnstenv+fldenv
 *                        —— 两者都连 C0-C3/TOP 一起动, 与 fnclex "只清 Px"不同形
 *    顺带把"为什么 C1 只能记录不能断言"也归到指令级: PE 侧的 _cls_d/_cls_l(mingw 的
 *    fpclassify)发的是 fldl/fldt+**fxam**+fstsw, 每分类一次就重写 C0/C2/C3; glibc 侧的
 *    cls_* 一个 x87 都没有(纯位运算) —— 所以 fegetenv 原字的高 10 位必然两机不同形
 *    (PE 读到 0132/4032/4402, box31 全 0032/0002/0022), 低 6 位不受影响(fxam 不动
 *    异常位)。本节四处边界的完整措辞在 _tmp/x87_p6cchk.c 文件头。 */

#define X1       0x8000000000000000ULL               /* m80: 1.0 x 2^k 的尾数形 */

#define M80_E(k) ((uint16_t)(16383 + (int)(k)))      /* m80 指数域(偏置 16383) */

#define M80_S    0x8000u                             /* m80 的 se 符号位 */

#define INDEF_M  0xc000000000000000ULL               /* integer-indefinite / -QNaN 的尾数 */

#define INDEF_S  0xffffu                              /* 指数全 1 + 符号 1 */

#define D_NEG    0x8000000000000000ULL               /* double 位形的符号位 */


/* ---- stack_underflow_is: 空栈上的弹栈/压栈/交换/比较 ---- [解析]
 * 八档 = G4(e1/e5) + G7e 的实测行, 三条只在这里成立的读数:
 *   弹栈类一次消耗两格 -> IE|SF 且 TOP **+1**(0x0841);
 *   空栈 `fld %st(0)` 是压栈方向(TOP 走到 7), 但仍报 IE|SF -> 0x3841;
 *   空栈 `fxch %st(1)` **也报**(0x0041 = IE|SF 而 TOP 不变) —— 这一档是本轮按 SDM 推
 *     "fxch 不压不弹故不报栈错"被实测推翻的(文件头 d) 末段)。
 * 期望 o0 == sw(取在任何 drain 之前), o1 == INDEF_M: 空档被弹时写回内存的恒是
 *   -QNaN indefinite —— G4 的 e1/e5 与 G7e 每一行的 drain 都是这个位形。八行同值是
 *   刻意的: 它把"栈错的代价只体现在状态字上、内存侧一律同一个填充"钉成一条不变式。
 *   drain 槽预置成哨兵位形, 所以"根本没写"也会以 o1 != INDEF_M 报出来(不靠 sw 兜)。 */
#define SU_ACT(BODY)                                                            \
    __asm__ volatile(IB_SETF BODY "fnstsw (%[w])\n\t" IB_GETF                    \
                     : [fl] "=&r"(fl)                                           \
                     : [w] "r"(&g_sw[0]), [s] "r"(&g_t[5]), [fv] "r"(fv)         \
                     : "cc", "memory")


/* M80_F(N) = 尾数里 2^-N 那一格 -> 1+2^-N 写成 (X1 | M80_F(N))。
 * 逐个可在探针的 E_* 宏里反验: M80_1PN(1)=E_1P5/E_THREE 的尾数、M80_E(-64)=0x3fbf、
 * M80_E(-16382)=0x0001=E_MINNORM、M80_E(16383)=0x7ffe=E_2P16383。 */
#define M80_F(N)     (1ULL << (63 - (N)))

#define M80_1PN(N)   (X1 | M80_F(N))


#define XB_ACT(BODY)                                                            \
    __asm__ volatile(IB_SETF                                                    \
                     "fldt (%[rh])\n\tfldt (%[lh])\n\t" BODY                     \
                     "fnstsw (%[w])\n\t" IB_GETF                                \
                     : [fl] "=&r"(fl)                                           \
                     : [rh] "r"(pr), [lh] "r"(pl), [w] "r"(&g_sw[0]), [fv] "r"(fv) \
                     : "cc", "memory")


/* =====================================================================
 * 7) P7 特殊指令与组合(8 条): 比较码 / 方向对 / FSCALE / FXAM / 状态字全位 /
 *    fninit 归零。与 P6 的分工: P6 量"异常置哪几位", 本节量"不置异常时状态字
 *    里剩下的那 10 位(CC 与 TOP)"以及两条归零/换序指令。
 *    八条**全是 [解析]**, 且期望式只做整数运算 —— 本节的入值要么是 2 的幂、
 *    要么是小整数, 结果全部落在 m80 的 64 位有效位内(唯一占满是 fisubr_m64 的
 *    2^62+2^63 = 1.5x2^63, 它正好用足 64 位而不需要舍), 所以不必套 P6 那套一般化
 *    m80 舍入模型(那是给 1/3、dmin*dmin 这类真不精确结果准备的)。
 *    两条与文档相反的事实按文件头 g) 写死在本节(取证 7 的 G1/G1b: 十四档 n x 两个
 *    a x RC 四档, 双机一致): FSCALE **不弹栈**(sw 恒 0x3000 = TOP6, 与 SDM 结尾那句
 *    FPOP ST(1) 相反), 且 ST1 的取整是**向零截断**不是 floor(只有负小数能分清这两者;
 *    n=+1.5 -> 2^1 同时排除"按当前 RC 舍", 因为默认 RNE 会把 1.5 舍成 2)。
 *    sw 读数位置仍同 P5/P6: 一律取在任何存回/弹栈之前。全节唯一的例外是
 *    fstsw_allbits —— 它要量的就是"读"这个动作本身, 而三种读法都不改状态。
 *    装载侧的标志位(P6 的 fsqrt_neg_ie 已吃过一次亏)在本节同样要算: a13 实测
 *    `fldl SNaN` 当场置 IE 并把寄存器收成 QNaN(e000….7fff), 所以 fxam 那一档的
 *    IE 归装载、不归 fxam —— 两者的读数一样, 但归因不一样, 写在注释里才不至于
 *    下一轮又去"复测 fxam 会不会置 IE"。
 *
 * 本节的验证通道(口径: 验 x87 要写"各种常用 / 不常用的 C 调用组合", 不是只按指令直调):
 *   探针 _tmp/x87_p7chk.c 的 A-G 七节一条 asm 都不写, 由 gcc -m32 -mno-sse -mfpmath=387
 *   自己发 x87; 双基准逐行一致(93 行可比 / 差异 0, 剥列理由写在 _tmp/p7_two_diff.sh)。
 *   每条内核都在自己注里标明对应的 C 侧锚点行。覆盖不到的地方写成边界、不假装覆盖 ——
 *   本轮实测到三处分界(都是先看到读数不对、再反汇编归因的):
 *     ① CC 位序在 C 侧**没有对应物**: gcc 的比较发的是 fcomip/fucomip(反汇编见
 *        _tmp/p7_cc_dis.sh), 两机读到的 sw 里 C3C2C0 恒为 0(无序列只多一个 IE) ——
 *        与本节 fcom_cc 用的非 COMI 族 `fcoml` 不矛盾(取证 g) 的 b9 里 CC 真在状态字里),
 *        是**两条不同的指令**。C 侧能锚的是判定表(八对数各自的 lt/gt/eq)与"无序置 IE"。
 *     ② "写进 AX"与"WAIT 前缀"没有 C 侧对应物(用哪条由编译器选) —— fstsw_allbits 的
 *        C 侧锚点只覆盖"重复读同字"与"fnstenv 镜像 vs fnstsw 掩码两条路径低 6 位同字"。
 *     ③ tag 字节没有 C 语义可读, 且库函数的"归零"范围不如 fninit(glibc 的
 *        fesetenv(FE_DFL_ENV) 不清 CC、mingw 的连 CC 一起清 —— 两机不同字, 那一列已标成
 *        库属性不进比对) —— fninit_defaults 的 tag/TOP 断言只有内核侧能证。
 * ===================================================================== */

/* double 位形的补齐(P6 只用 2 的幂; 本节要 ±Inf/NaN/±0/DBL_MAX 与 1.5/2.5)。
 * 每一个都能用 a13/G1 的实测行反验: D_QNAN 装出来 = c000….7fff、D_SNAN 装出来 =
 * e000000000000800.7fff(bit62 被 quiet 掉、bit50 的载荷还在)、D_MAXDBL = XFEF…. */
#define D_ZERO    0ULL                                  /* +0 */

#define D_MZERO   D_NEG                                 /* -0 */

#define D_TWO     D_POW2(1)

#define D_FOUR    D_POW2(2)

#define D_HALF    D_POW2(-1)

#define D_1P5     (D_POW2(0) | (1ULL << 51))            /* 1.5 */

#define D_2P5     (D_POW2(1) | (1ULL << 51))            /* 2.5 */

#define D_PINF    0x7ff0000000000000ULL                 /* 指数域全 1、尾数 0 */

#define D_MINF    (D_PINF | D_NEG)

#define D_QNAN    0x7ff8000000000000ULL                 /* 指数全 1 + quiet 位 */

#define D_SNAN    0x7ff4000000000001ULL                 /* 指数全 1、bit51=0、尾数非 0 */

#define D_MAXDBL  0x7fefffffffffffffULL                 /* (2-2^-52) x 2^1023 */

/* 本节另加的七个位形(式子与上面同形, 每个都能用 _tmp/x87_p7chk.c 的自检行反验:
 * "自检: DB_FOUR=4 DB_2P5=2.5 DB_M100=-100 往返一致=1" 那行就是防抄错指数域 ——
 * D_FOUR 曾被写成 0x4004...(那是 2.5), 两档会得同一结果而看不出来)。 */
#define D_THREE   (D_POW2(1) | D_POW2(0))              /* 3 = 1.5 x 2^1 */

#define D_M1P5    (D_1P5  | D_NEG)                     /* -1.5 */

#define D_M2P5    (D_2P5  | D_NEG)                     /* -2.5 */

#define D_MHALF   (D_HALF | D_NEG)                     /* -0.5 */

#define D_M100    0xc059000000000000ULL                /* -100 = -1.5625 x 2^6 */

#define D_2P62    D_POW2(62)                           /* 2^62 */

#define D_DMIN    1ULL                                 /* double 最小非规格化 = 2^-1074 */


/* BODY 必须是**编译期字面量**: IB_SETF/IB_GETF 靠串接拼窗, 而窗口里只允许被测指令
 * (掺进编译器自己发的 mov/cmp 就把 outf 这个 EFLAGS 读数洗掉了) —— 同 XB_ACT 的处置。 */
#define FSP_ACT(BODY)                                                             \
    __asm__ volatile(IB_SETF BODY "fnstsw (%[w])\n\t" IB_GETF                      \
                     : [fl] "=&r"(fl)                                             \
                     : [a] "r"(pa), [b] "r"(pb), [w] "r"(&g_sw[0]), [fv] "r"(fv)    \
                     : "cc", "memory")


#define FIB_ACT(BODY)                                                             \
    __asm__ volatile(IB_SETF BODY "fnstsw (%[w])\n\t" IB_GETF                      \
                     : [fl] "=&r"(fl)                                             \
                     : [a] "r"(pa), [c] "r"(pc), [w] "r"(&g_sw[0]), [fv] "r"(fv)    \
                     : "cc", "memory")

#define FXA_SHAPE(kk)  ((kk) <= 5 ? 0u : ((kk) == 6 ? 1u : 2u))   /* 0=fldl 1=ffree 2=fldt */


#define FXA_ACT(BODY)                                                             \
    __asm__ volatile(IB_SETF BODY "fxam\n\tfnstsw (%[w])\n\t" IB_GETF               \
                     : [fl] "=&r"(fl)                                             \
                     : [v] "r"(pv), [w] "r"(&g_sw[0]), [fv] "r"(fv)                 \
                     : "cc", "memory")

#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))


/* RVQ: 被舍数的**分子**(值 = q/4, 带符号, |q| < 2^24)。逐位的看点:
 *   -15(-3.75)  计划点名的入值: r=1 舍去; 负号让 RD/RN 与 RU/RZ 分家
 *    10( 2.5)   平局且下档偶 -> RN 与 RU 分家
 *   -10(-2.5)   平局且下档奇(负侧) -> RN 与 RD 分家(专咬"负数向零舍方向错")
 *    14( 3.5)   平局且下档奇(正侧) -> RN 与 RD/RZ 分家
 *     2( 0.5)   平局且结果为 0 -> 抓"整数没有 -0"这一类
 *    -2(-0.5)   同上负侧 -> RN/RU/RZ 全 0, 只有 RD 是 -1(本向量里唯一独一行的档)
 *    12( 3.0)   r=0 精确行(四档恒同, 对照)
 *   -16(-4.0)   r=0 精确行 + 计划"边界整数"(整型边界由 P1 钉, 这里要负整数值)
 * 没有 0: qbits() 那条注解释过, 对 0.0 的指数域做减法算出来是 NaN 位形。 */
static const int32_t RVQ[IB_KAT_N] = { -15, 10, -10, 14, 2, -2, 12, -16 };


/* FAVEC/FBVEC: pc24_fadd 与 pc53_fadd **共用**的一对加数(档间断言的前提: 两档必须
 * 是同一算式, 否则"两档结果不同"说明不了 PC)。1.0 + 2^-k 的精确和需要 k+1 位有效位,
 * 所以 k >= 24 的行两档必然分家; k=23 是"两档都精确"的对照行, k=53 是 53 档的平局行
 * (舍回 1.0), 最后一行换量级(2^30 + 2^6 需 25 位), 防止结论只成立于指数 0。 */
static const uint64_t FAVEC[IB_KAT_N] = {
    D_ONE, D_ONE, D_ONE, D_ONE, D_ONE, D_ONE, D_ONE, D_POW2(30)
};

static const uint64_t FBVEC[IB_KAT_N] = {
    D_POW2(-24), D_POW2(-25), D_POW2(-23), D_POW2(-30),
    D_POW2(-40), D_POW2(-52), D_POW2(-53), D_POW2(6)
};

/* FMVEC: pc64_fmul 的乘数(两侧同值), 2^n+1 自乘 -> 精确积需 2n+1 位有效位。
 * n=12..30 在 64 档全精确(2n+1 <= 61), n=40/52 出量程 -> 连默认档也要舍,
 * 那两行同时是"PC=64 不等于不舍"的证据(取证 g2 的 (2^27+1)^2 就是本向量的一项)。 */
static const uint64_t FMVEC[IB_KAT_N] = {
    D_2PN1(12), D_2PN1(20), D_2PN1(24), D_2PN1(26),
    D_2PN1(27), D_2PN1(30), D_2PN1(40), D_2PN1(52)
};


/* ---- fsqrt_neg_ie: 负数开方、±0 开方、NaN 静默返回 ---- [解析]
 * 取证 7 G7a 实测八档(计划 105 行的"负值 -> IE"在这里只成立一半: SDM 的 #IE 判据是
 * **源 < 0**, 所以 -0 与 NaN 都不入判):
 *   +1 -> 3800/1.0;  -1 -4 -Inf -> 3801 + indefinite;  -0 -> 3800 + **-0**(无任何异常);
 *   -dmin -> **3803** = IE|DE。这条原本写成"3801 不置 DE(FLD 非规格化 double 不置 DE)"
 *     —— 那是把探针 G7a 的结论套到了不同形状的入值上: G7a 的 dmin 两档入的是 **m80**
 *     形(fldt), 本条入的是 **double** 形(fldl)。_tmp/x87_p6chk.c 把两者拆开到位:
 *     A) fldl +dmin(double) -> sw=3802(装载就置 DE);  C) fldt +dmin(m80) -> sw=3800
 *     (不置);  D) fldt +dmin 再 fsqrt -> 3822(算术指令自己置) —— 即 **DE 只在"源需要
 *     格式转换"时由装载带来**, fldt 无需转换故归算术指令, 两条不矛盾。另 E1) 不写一
 *     条 asm、只用普通 volatile double 表达式(dmin*2 -> sw=0002)同形复现了这条。
 *   -QNaN -> 3800 + 原值静默返回(比较不成立故不入 IE 分支)。
 *   第十档 sqrt(+dmin) -> DE|PE 且结果 2^-8222.5 是无理尾数 -> **不上表**(纯整数
 *   算式推不出来, 拿采集值当期望就是"不拿没解释的图案当承诺"的反面), 换成正侧
 *   精确对照行 +4 -> 3800 / 2.0(幂指数为偶 -> 开方精确、不置 PE)。
 * 期望 o0 == 结果 mant, o1 == 结果 se | (sw<<16)。 */
static const uint64_t SQRTA[IB_KAT_N] = {
    D_POW2(0),                                   /* +1   */
    D_POW2(0) | D_NEG,                           /* -1   */
    D_POW2(2) | D_NEG,                           /* -4   */
    D_NEG,                                       /* -0   */
    D_NEG | 1ULL,                                /* -dmin(非规格化负数) */
    D_POW2(1024) | D_NEG,                        /* -Inf(指数域全 1) */
    D_POW2(1024) | D_NEG | (1ULL << 51),         /* -QNaN(再置 quiet 位) */
    D_POW2(2)                                    /* +4   精确对照 */
};


/* ---- denormal_ue / precision_pe: 双目 m80 的下溢档与不精确档 ---- [解析]
 * 两条共用一个执行体(G7c 与 G7d 的表), 因为要量的不是助记符而是**标志位的分工**:
 *   DE 跟**入值**走(操作数非规格化就置, 与结果无关);
 *   UE 跟"结果下溢**且**不精确"走(结果是非规格化但精确 -> 不置, 见 dmin*2 那行);
 *   PE 跟精度损失走(舍回原值也算, 见 1.0+2^-64/2^-65 两行)。
 * 反例档是 min_norm*0.5: 结果非规格化而两个入值都规格化 -> 读回 **3800**(一位都不置),
 *   这一行专门把"结果非规格化就置 DE"那条错判据否掉(取证 7 e))。
 * 方向不靠约定: 两档非对称除法(dmin/2 与 1/3)在真机上读回的就是这个名字(反向的话两档
 *   都差 10^9846 量级), 所以表里的 (li, ri) 就是"算的是 li op ri", 见文件头 g)。
 * 入值两个 m80 共 160 位 > 两个 64 位输入字段 -> 尾数落 i0/i1, **指数字段不重复登记**:
 *   审计端按 kk 重算同一张表(含指数)并拿 i0/i1 对账尾数; 内核侧若抄错指数, 结果位形
 *   必对不上 -> 由 o1 兜住(指数错而结果仍相同的组合在本表里不存在)。
 * 期望 o0 == 结果 mant, o1 == 结果 se | (sw<<16); sw 的底是 0x3800(TOP=7: 弹栈后回到
 *   finit 前压了两项的状态), 与探针的"运算后"读数同形 —— 取在 fstpt 之前(本节头)。 */
enum { XB_ADD = 0, XB_MUL = 1, XB_DIV = 2 };

enum { BO_DMIN = 0, BO_MINNORM, BO_HALF, BO_ONE, BO_TWO, BO_THREE, BO_SEVEN,
       BO_2PM64, BO_2PM65, BO_1P2M63, BO_1P5, BO_2P126, BO_2P16383 };


static const xb80 XBOP[] = {
    { 1ULL,              0              },   /* dmin: 非规格化最小正数 = 1 x 2^-16445 */
    { X1,                M80_E(-16382)  },   /* min_norm: 最小正规格化数 */
    { X1,                M80_E(-1)      },   /* 0.5 */
    { X1,                M80_E(0)       },   /* 1.0 */
    { X1,                M80_E(1)       },   /* 2 */
    { M80_1PN(1),        M80_E(1)       },   /* 3 */
    { M80_1PN(1) | M80_F(2), M80_E(2)   },   /* 7 */
    { X1,                M80_E(-64)     },   /* 2^-64 = 1.0 处 ULP(2^-63) 的一半 */
    { X1,                M80_E(-65)     },   /* 2^-65 = 不足半个 ULP */
    { M80_1PN(63),       M80_E(0)       },   /* 1+2^-63: 80 位能精确表示 */
    { M80_1PN(1),        M80_E(0)       },   /* 1.5 */
    { X1,                M80_E(126)     },   /* 2^126 */
    { X1,                M80_E(16383)   },   /* 2^16383: 最大指数档的 2 的幂 */
};


struct xbop { uint8_t op; uint16_t li, ri; };   /* 算的是 li op ri; ri 先入栈(在 ST1) */


static const struct xbop XBDEN[IB_KAT_N] = {     /* G7c 的八档 */
    { XB_MUL, BO_DMIN,    BO_DMIN    },         /* dmin*dmin     -> 舍到 +0 */
    { XB_MUL, BO_DMIN,    BO_HALF    },         /* dmin*0.5      -> 半个 dmin, ties 取偶 -> +0 */
    { XB_DIV, BO_DMIN,    BO_TWO     },         /* dmin/2        -> 同上 */
    { XB_MUL, BO_DMIN,    BO_TWO     },         /* dmin*2        -> 非规格化但**精确** */
    { XB_ADD, BO_DMIN,    BO_DMIN    },         /* dmin+dmin     -> 同上一行 */
    { XB_MUL, BO_MINNORM, BO_HALF    },         /* min_norm*0.5  -> 反例档(见注释) */
    { XB_MUL, BO_MINNORM, BO_DMIN    },         /* min_norm*dmin -> 舍到 +0 */
    { XB_ADD, BO_ONE,     BO_DMIN    },         /* 1.0+dmin      -> 结果 1.0, DE|PE */
};

static const struct xbop XBPRC[IB_KAT_N] = {     /* G7d 的八档 */
    { XB_DIV, BO_ONE,     BO_THREE   },         /* 1/3            -> PE + C1(向上舍) */
    { XB_DIV, BO_ONE,     BO_SEVEN   },         /* 1/7            -> PE 无 C1(向下舍) */
    { XB_ADD, BO_ONE,     BO_2PM64   },         /* 1.0+2^-64      -> 半个 ULP, ties 取偶 */
    { XB_ADD, BO_ONE,     BO_2PM65   },         /* 1.0+2^-65      -> 不足半个 ULP */
    { XB_MUL, BO_1P2M63,  BO_1P2M63  },         /* (1+2^-63)^2    -> 1+2^-62 */
    { XB_MUL, BO_1P5,     BO_TWO     },         /* 1.5*2          -> 精确对照 */
    { XB_MUL, BO_2P126,   BO_2P126   },         /* 2^126*2^126    -> 2^252 精确(大指数不是 OE) */
    { XB_MUL, BO_2P16383, BO_TWO     },         /* 2^16383*2      -> +Inf, PE|OE|C1 */
};


/* ---- fnclex_clears: 置异常后 fnclex 清哪几位 ---- [解析]
 * 取证 7 b) 的实测规则(计划 103 行"清全部 Px 与 ES"在这里被限定):
 *   三个实测对 = 0x3801->0x3800(IE 清、TOP 不变)、0x3800->0x3800(不误伤)、
 *   0x3a41->0x3a00(**C1 仍留着**, 所以不是"清全部 Cx")。
 * => 判据写成一条纯位式: **o1 == o0 & ~0xff**(清 IE..PE + SF + ES, 不清 C0/C1/C2/C3/TOP)。
 * 八档的 **o0 全部是实测值**(0x3804/0x3801/0x3800/0x3a41/0x0841/0x3841/0x0041/0x4d41,
 * 与 P6 其余条、P5 的栈行互为交叉验证); o1 是由上面那条规则推的期望 —— 规则的两个锚点
 * 之外(带 CC 位的 0x4d41、带 ZE 的 0x3804)若被真机否掉, 采集值与推导值当场不一致, 由
 * kat_audit 报出(不在这里预先放宽)。 */
static const uint16_t FC_MASK[IB_KAT_N] = {   /* 本档要在 o0 里看到的异常位(bits 0-7) */
    0x0004u, 0x0001u, 0x0000u, 0x0041u, 0x0041u, 0x0041u, 0x0041u, 0x0041u
};


/* ---- fcom_cc: FCOM m64fp(DC /2, **不弹栈**)的 C0/C2/C3 ---- [解析]
 * 规则四句话(取证 6 的 b9 三路 + 取证 7 G7e 的无序行, 全按新位序读):
 *   ST0 > 源 -> 三位全 0;  ST0 < 源 -> C0;  ST0 == 源(±0 相等、Inf 自比也相等) -> C3;
 *   无序(任一侧是 NaN) -> C3C2C0 全 1 **并且置 IE**(masked 路径上只留标志)。
 * ★ b9 的标签是按**先入栈那个数**命名的("gt(2 vs 1)"= lhs>rhs = ST0<源 = C0=1),
 *   拿它当"ST0 vs ST1"读就会读反 —— 所以本条的入值明写成 {ST0, 内存} 两个数,
 *   表里不出现 gt/lt 这种省掉操作数次序的名字(文件头 g) 的同一条纪律)。
 * 八档 = b9 实测的五对 + 三对(±0 互比、+Inf 自比、-Inf vs +Inf) —— 后三对不引入
 *   新形状, 只是把"相等"这一支从 4vs4 一档扩到三种量级, 防"C3 只在整数相等时置"。
 * 期望 o0 == 比较后的 sw(低 16; TOP=7: fldl 压一项、fcoml 不弹),
 *      o1 == drain(fstpt) 之后的 sw —— CC 与 IE **不随弹栈消失**, 只有 TOP 归 0。
 *   这一对合起来兼到两件事: "FCOM 不弹栈"与"比较码住在状态字里、不住在栈槽里"。
 * C 侧锚点 = _tmp/x87_p7chk.c 的 G2 八行(同一张入值表的 lt/gt/eq + 无序行置 IE);
 *   而 CC 落在哪一位只能由本条的 fnstsw 读数钉, 理由见节头 ①。 */
static const uint64_t FCOP[IB_KAT_N][2] = {         /* {ST0 = fldl 的数, 内存操作数} */
    { D_TWO,    D_ONE    },     /* 2 vs 1  -> ST0 大 -> CC=000 */
    { D_ONE,    D_TWO    },     /* 1 vs 2  -> C0 */
    { D_FOUR,   D_FOUR   },     /* 4 vs 4  -> C3 */
    { D_QNAN,   D_ONE    },     /* NaN     -> C3C2C0=111 + IE */
    { D_ONE,    D_MZERO  },     /* 1 vs -0 -> C3(±0 相等) */
    { D_MZERO,  D_ZERO   },     /* -0 vs +0 -> C3 */
    { D_PINF,   D_PINF   },     /* +Inf 自比 -> C3(同量级不等于同槽位) */
    { D_MINF,   D_PINF   }      /* -Inf vs +Inf -> C0 */
};


/* ---- fcompp_cc: FCOMPP(DDE9, 弹两格)的同一张 CC 表 ---- [解析]
 * 与 fcom_cc 是**同五个数对、反主客**: 这里先入栈的落在 ST(1), 所以比较方向整个
 * 反过来(fcom_cc 的 ST0=2/源=1 在这里变成 ST0=1/ST1=2)。两条凑在一起才把
 * "C0 到底表示 ST0 小还是 ST1 小"钉死 —— 单看任何一条都能被"名字读反"这种错解释。
 * 实测锚点(b9 的第一路, 弹两格 -> TOP=0): gt 行 sw=0100、lt 行 0000、eq 行 4000、
 *   无序行 4501、mz 行 0100(与 G7e 的"1 项时 fcompp -> 第二格按空栈读"同一条指令、
 *   不同的栈深, 所以本条的八档全都先压两项)。
 * 期望 o0 == fcompp 之后的 sw(TOP=0), o1 == 再 fldl 一项之后的 sw(TOP=7、CC/IE 不变)
 *   —— 第二读法与 fcom_cc 的正好**反**(那里 drain 让 TOP 归 0), 两个方向都读一次,
 *   "CC 位与栈无关"这件事才不依赖任何一处的约定。 */
static const uint64_t FCPP[IB_KAT_N][2] = {         /* {先入栈 = ST1, 后入栈 = ST0} */
    { D_TWO,    D_ONE    },     /* ST0=1 vs ST1=2 -> C0 */
    { D_ONE,    D_TWO    },     /* ST0=2 vs ST1=1 -> CC=000 */
    { D_FOUR,   D_FOUR   },     /* C3 */
    { D_QNAN,   D_ONE    },     /* 111 + IE */
    { D_ONE,    D_MZERO  },     /* ST0=-0 vs ST1=1 -> C0 */
    { D_MZERO,  D_ZERO   },     /* C3 */
    { D_PINF,   D_PINF   },     /* C3 */
    { D_MINF,   D_PINF   }      /* ST0=+Inf vs ST1=-Inf -> CC=000 */
};


/* ---- fsubr_pair: FSUB/FSUBR 的「弹栈形 x 内存形」四路方向对 ---- [解析]
 * 要量的不是减法本身(P1/P6 已量过舍入与异常), 而是**同一对操作数在四种编码形状下
 * 算的是同一个方向**: 带 R 的两条换序、不带 R 的两条不换, 而"换序"这件事在弹栈形里
 * 表现为 ST(1) 收到 b-a、在内存形里表现为 ST(0) 收到 b-a —— 只登记一种形状就能被
 * "把 R 理解成对调压栈序"这种错解释蒙过, 四路同表才关死。
 * 入值两对**非对称**数 (4,1) 与 (2,4): 同序给 3、反序给 -3 与 -2, 两对量级不同,
 * 所以"方向对但操作数抄反"也当场露(锚点 = _tmp/x87_p7chk.c 的 B1-B4 四行, 双机同字:
 *   4-1 -> c000….4000 = +3、1-4 -> c000….c000 = -3、2-4 -> 8000….c000 = -2、4-2 -> 8000….4000)。
 * 期望 o0 == 结果 mant, o1 == 结果 se | (sw<<16); sw 恒 0x3800(四路算完都剩一项:
 *   弹栈形 2 压 1 弹、内存形 1 压不弹, 都回到 TOP=7)、且八档结果全在 64 位有效位内
 *   -> 无 PE(这是本节挑小整数的原因, 见节头)。 */
static const uint64_t FSUBAB[2][2] = {                /* {a = 先入栈/栈上那个, b = 另一个} */
    { D_FOUR, D_ONE   },                              /* 4, 1  -> |a-b| = 3 */
    { D_TWO,  D_FOUR  }                               /* 2, 4  -> |a-b| = 2 */
};


/* ---- fisubr_m64: 整型减数参与减法的两条路(m32int 直接形 / m64int 只能先 FILD) ---- [解析]
 * ★ 计划 109 行的词干写的是 m64int, 但架构里**没有 FISUB/FISUBR m64int 形**: FI* 整型族
 *   只有 m16int(DE /4、/5)与 m32int(DA /4、/5)两种宽度, DF 段的 /6 已被 FBSTP 占、/7 已被
 *   FISTP m64int 占(取证 1 当年订正的就是 DF/7), gas 亦拒 `fisubll`/`fisub qword ptr`
 *   (逐条汇编见 _tmp/p7_mn3.sh 与 _tmp/p7_mn6.sh: `da 26`=fisubl、`de 26`=fisubs、
 *   `df 2e`=fildll、`df 36`=fbstp、`df 3e`=fistpll)。所以本条按**「64 位整数参与减法」
 *   的实形**登记 = fildll(DF/5) + fsubp/fsubrp(DE/7、DE/6), 并把 m32int 直接形放进同一张
 *   八档表对读: 两条路的期望是同一个整数式(先按精确整数算差, 再写左规位形)。
 *   这条也是 LATX 的高价值形状: gcc -m32 自己**从不**发 FISUB/FISUBR(实测它把 int 先转
 *   浮点再 fsubl, 见 _tmp/_p7dis.txt 的 sec_b 直方图), 只有手写 asm 与老二进制才走 DA/4。
 * 八档 = {机械 0=m32int, 1=m64int} x {方向: 偶档 a-c、奇档 c-a} x 两对值:
 *   档 0/1: a=4, c=3            -> ±1        (B6/B7 实测行)
 *   档 2:   a=4, c=0x00020003   -> -131071   ★ 宽度分水岭: 若真机按 m16int 读就得到 +1
 *   档 3:   a=4, c=INT32_MAX    -> +2147483643(反向的 -2147483643 就是 B10 那行)
 *   档 4/5: a=2^62, c=3         -> ±(2^62-3) (B12/B13)
 *   档 6:   a=2^62, c=INT64_MIN -> 1.5x2^63  (B15; 全组唯一**占满 64 位有效位**的档, 仍精确)
 *   档 7:   a=2^62, c=2^62+1    -> +1        (B16 的反序)
 * 期望 o0 == 结果 mant, o1 == 结果 se | (sw<<16), sw 恒 0x3800(两条路算完都剩一项)、
 *   八档全不置 PE(FILD/FISUB 的整型装载按 SDM 无损, m32int 的符号扩展由取证 g) 的
 *   c1/c2 逐值核过)。 */
static const uint64_t FIA[2] = { D_FOUR, D_2P62 };     /* 按机械分的被减数 */

static const uint64_t FIC[IB_KAT_N] = {                /* 减数: 低 4 字节给 m32int 形用 */
    3ULL, 3ULL,
    0x00020003ULL,           /* 131075: 低 16 位是 3 -> 读成 m16int 就会与档 0 同字 */
    0x7fffffffULL,           /* INT32_MAX */
    3ULL, 3ULL,
    0x8000000000000000ULL,   /* INT64_MIN */
    0x4000000000000001ULL    /* 2^62 + 1: 第一个 double 表示不了的整数位形 */
};


/* ---- fscale_int: FSCALE = ST(0) x 2^trunc(ST(1)), 且**不弹栈** ---- [解析]
 * 两条与文档相反的事实(取证 g) ②, 双机一致):
 *   ① ST(1) 的取整是**向零截断**: n=-2.5 -> 2^-2、n=-0.5 -> 2^0(排除 floor);
 *      n=+1.5 -> 2^1(排除"按当前 RC 舍", 默认 RNE 会把 1.5 舍成 2)。
 *   ② 结果只覆盖 ST(0)、ST(1) 原样留着、TOP 不动 -> fscale 后 fnstsw 恒 0x3000(TOP=6),
 *      与 SDM 结尾那句 FPOP ST(1) 相反。
 * 入值: a 取 1/4/3, n 取 ±半整数与 -100/-0.0, 全部落在 m80 量程内且**精确** -> 期望是纯
 *   整数式: mant 不动(a 的左规尾数)、se = 16383 + (a 的指数 + (int)n)。
 *   八档逐个可核(每行的期望与结果值都写在括号里, 尾数恒 X1 除档 5):
 *     档 0 (1,-2.5) -> 2^-2 =0.25  se 0x3ffd | 档 1 (4,-2.5) -> 1     se 0x3fff
 *     档 2 (4,-1.5) -> 2           se 0x4000 | 档 3 (4,-0.5) -> 4     se 0x4001
 *     档 4 (4,+1.5) -> 8           se 0x4002 | 档 5 (3,+2.5) -> 12    mant 0xc000…. se 0x4003
 *     档 6 (1,-100) -> 2^-100      se 0x3f9b | 档 7 (4,-0.0) -> 4     se 0x4001
 *   ★ 档 5 换成了 a=3(不是 2 的幂): 它是"指数平移、尾数一位不动"这条规则的唯一直接证据
 *     —— 2 的幂在两类错实现(重舍入 / 尾数参与位移)下都可能撞对(锚点 = C 侧 A2 行
 *     ldexpl(3,(int)-2.5) -> c000….3ffe = 0.75, 与内核档 5 同一个尾数)。
 * 期望 o0 == 结果 mant, o1 == 结果 se | (sw<<16) | (原 ST1 的 se<<32):
 *   第三项钉的是②里"ST(1) 留着"—— 八档里 结果 se 与 n 的 se **全部不同**, 所以
 *   "把结果同时写进两格"或"弹掉 ST1 后读到垃圾"都会当场错(若某档两者相同, 这一项
 *   在该档就没有区分力, 故每档都核一次而不是只看一条规则)。 */
static const uint64_t FSA[IB_KAT_N] = {
    D_ONE, D_FOUR, D_FOUR, D_FOUR, D_FOUR, D_THREE, D_ONE, D_FOUR
};

static const uint64_t FSN[IB_KAT_N] = {                /* ST(1): 先入栈那格 */
    D_M2P5, D_M2P5, D_M1P5, D_MHALF, D_1P5, D_2P5, D_M100, D_MZERO
};


/* ---- fxam_kinds: FXAM 把栈顶分成七类时写哪四位(C3C2C1C0) ---- [解析]
 * 分类表(取证 f, 双机逐条与公开表吻合): C3C2C0 = Unsupported 000 / NaN 001 /
 *   Normal 010 / Infinity 011 / Zero 100 / Empty 101 / Denormal 110, **C1 = 符号**。
 *   本条的期望式就是这张表 + 一个纯整数判据"入值属于哪一类", 两者都已[解析]化。
 * 八档的实测锚点(行名取自 _tmp/x87_fx_box31.txt 的 c4/c4b 段, PE 同字):
 *   0 +0      -> Zero, 符号 0      -> 0x7800   (c4 zero)
 *   1 -0      -> Zero, 符号 1      -> 0x7a00   (c4 -zero)
 *   2 1.0     -> Normal            -> 0x3c00   (c4 normal)
 *   3 +Inf    -> Infinity          -> 0x3d00   (c4 +inf)
 *   4 QNaN    -> NaN               -> 0x3900   (c4 qnan)
 *   5 SNaN    -> NaN + **装载侧** IE -> 0x3901 (c4 snan; 文档明写 FXAM 不产生异常,
 *                                          所以这一位归 fldl 不归 fxam —— 写出来免得
 *                                          下一轮再去"复测 fxam 置不置 IE")
 *   6 fld1 后 ffree -> Empty        -> 0x7900   (c4 empty(after ffree))
 *   7 真 m80 非规格化 -> Denormal    -> 0x7c00   (c4b m80 denormal; 注意这里 **不置 DE**,
 *                                          与档 2 的 double 非规格化形成对照: DE 由装载
 *                                          非规格化 **double** 置, 见取证 e))
 * o1 的 mant/se 部分钉另一件事: **FXAM 不改被它检查的那格**(值原样存回)。两个 NaN
 *   档还顺带钉住装载侧的 quiet 位形: SNaN 0x7ff4….0001 装进来 = e000000000000800(bit62
 *   被 quiet、bit50 与 bit11 的载荷保留)、QNaN = c000….7fff —— 两行都是 _tmp/x87_p7chk.c
 *   的 D 节实测值(gcc 发的 fldl, 与本条的内联 asm 无关)。
 * ★ 档 6 同时钉住"FFREE 只改 tag 字节、不动寄存器数据"(取证 c) 只量了 tag 与 TOP,
 *   这一档是其另一半; 若真机在 ffree 后读出不同尾数, 采集值与这里写的期望当场不一致。 */
static const uint64_t FXAV[IB_KAT_N] = {              /* 档 0-5: fldl 的 double 位形 */
    D_ZERO, D_MZERO, D_ONE, D_PINF, D_QNAN, D_SNAN,
    D_ONE,                                               /* 档 6: fld1 的值(随后 ffree) */
    0x4000000000000000ULL                                /* 档 7: 真 m80 非规格化的 mant */
};

/* 本档要看到的异常位(与 FC_MASK 同样只当**入值描述符**、不是期望; 归零后的断言在下
 * 一条的 o1 里)。档 3 这里记 0x41(SF|IE) 而不含 C1: C1 不是异常位、由 TOP 走位规则管。 */
static const uint16_t FDIRTY[IB_KAT_N] = {
    0x0004u, 0x0001u, 0x0002u, 0x0041u, 0x0041u, 0x0041u, 0x0041u, 0x0041u
};

/* ---- 全局缓冲 (定义在 isb_x87_main.c) ---- */
extern uint64_t g_f[16];
extern uint16_t g_cw[8];
extern uint16_t g_sw[8];
extern uint16_t g_env[32];
extern xb80 g_t[8];
extern unsigned char g_bcd[16];

/* ---- 入值向量 (定义在 isb_x87_main.c) ---- */
extern const uint64_t XVEC[IB_KAT_N];
extern const uint64_t BVEC[IB_KAT_N];
extern const uint64_t IVEC[IB_KAT_N];

/* ---- helper 原型 (定义在 isb_x87_main.c) ---- */
uint64_t xq(int kk);
uint64_t xd(int kk);
uint64_t xw(int kk);
void *fput(int idx, uint64_t bits);
uint64_t fget(int idx);
uint16_t swgetn(int idx);
uint16_t swget(void);
uint16_t envget16(int idx);
uint16_t cwget(int idx);
void *tput80(int idx, uint64_t mant, uint16_t se);
uint64_t tget_m(int idx);
uint16_t tget_s(int idx);
unsigned char *bput(uint64_t v, int neg);
void ext_form(uint64_t v, uint64_t *mant, uint16_t *se);
uint64_t q4bits(int32_t q);
void rc_fistp_core(int kk, unsigned enc, const char *stem, ib_kv *g);
uint64_t rc_fistp_tp_core(unsigned long long iters, unsigned enc);
void pc_fadd_core(int kk, unsigned enc, const char *stem, ib_kv *g);
void pc_fmul_core(int kk, unsigned enc, const char *stem, ib_kv *g);
uint64_t pc_fadd_tp(unsigned long long iters, unsigned enc);
uint64_t pc_fmul_tp(unsigned long long iters, unsigned enc);
uint64_t x87n(const char *sn, int kk, int slot);
uint64_t qbits(uint64_t n);
uint64_t qv(const char *sn, int kk, int slot);
void x87_bin80_core(int kk, const struct xbop *t, const char *stem, ib_kv *g);
uint64_t x87_bin80_tp(unsigned long long iters, const struct xbop *t);
void x87_dirty(int kk);

/* ---- 用例函数原型 ---- */
extern void k_fild_fistp_q_rt_kat(int kk, ib_kv *g);
extern void k_fild_fistp_d_rt_kat(int kk, ib_kv *g);
extern void k_fild_fistp_w_rt_kat(int kk, ib_kv *g);
extern void k_fild_fistp_q_neg_kat(int kk, ib_kv *g);
extern void k_fild_q_odd_rt_kat(int kk, ib_kv *g);
extern void k_fild_fstp_q_dbl_kat(int kk, ib_kv *g);
extern void k_fild_fstp_t_ext_kat(int kk, ib_kv *g);
extern void k_fistp_q_indef_kat(int kk, ib_kv *g);
extern void k_fisttp_q_rt_kat(int kk, ib_kv *g);
extern void k_fld_t_fstp_t_rt_kat(int kk, ib_kv *g);
extern void k_fbld_fistp_q_rt_kat(int kk, ib_kv *g);
extern void k_fild_fistp_q_x8_kat(int kk, ib_kv *g);
extern void k_rc_fstcw_rt_kat(int kk, ib_kv *g);
extern void k_fld_fstp_kat(int kk, ib_kv *g);
extern void k_fadd_kat(int kk, ib_kv *g);
extern void k_fmul_kat(int kk, ib_kv *g);
extern void k_fistp_kat(int kk, ib_kv *g);
extern void k_fcomip_kat(int kk, ib_kv *g);
extern void k_fcw_rt_kat(int kk, ib_kv *g);
extern void k_stack_top_after_fild_kat(int kk, ib_kv *g);
extern void k_stack_fld8_st8_kat(int kk, ib_kv *g);
extern void k_fxch_st3_kat(int kk, ib_kv *g);
extern void k_fldst_st1_to_st0_kat(int kk, ib_kv *g);
extern void k_fincstp_fdecstp_rt_kat(int kk, ib_kv *g);
extern void k_ffree_tag_kat(int kk, ib_kv *g);
extern void k_fdiv_zero_ze_kat(int kk, ib_kv *g);
extern void k_fsqrt_neg_ie_kat(int kk, ib_kv *g);
extern void k_fistp_oe_kat(int kk, ib_kv *g);
extern void k_stack_underflow_is_kat(int kk, ib_kv *g);
extern void k_denormal_ue_kat(int kk, ib_kv *g);
extern void k_precision_pe_kat(int kk, ib_kv *g);
extern void k_fnclex_clears_kat(int kk, ib_kv *g);
extern void k_fcom_cc_kat(int kk, ib_kv *g);
extern void k_fcompp_cc_kat(int kk, ib_kv *g);
extern void k_fsubr_pair_kat(int kk, ib_kv *g);
extern void k_fisubr_m64_kat(int kk, ib_kv *g);
extern void k_fscale_int_kat(int kk, ib_kv *g);
extern void k_fxam_kinds_kat(int kk, ib_kv *g);
extern void k_fstsw_allbits_kat(int kk, ib_kv *g);
extern void k_fninit_defaults_kat(int kk, ib_kv *g);
extern uint64_t k_fild_fistp_q_rt_tp(unsigned long long iters);
extern uint64_t k_fild_fistp_d_rt_tp(unsigned long long iters);
extern uint64_t k_fild_fistp_w_rt_tp(unsigned long long iters);
extern uint64_t k_fild_fistp_q_neg_tp(unsigned long long iters);
extern uint64_t k_fild_q_odd_rt_tp(unsigned long long iters);
extern uint64_t k_fild_fstp_q_dbl_tp(unsigned long long iters);
extern uint64_t k_fild_fstp_t_ext_tp(unsigned long long iters);
extern uint64_t k_fistp_q_indef_tp(unsigned long long iters);
extern uint64_t k_fisttp_q_rt_tp(unsigned long long iters);
extern uint64_t k_fld_t_fstp_t_rt_tp(unsigned long long iters);
extern uint64_t k_fbld_fistp_q_rt_tp(unsigned long long iters);
extern uint64_t k_fild_fistp_q_x8_tp(unsigned long long iters);
extern uint64_t k_rc_fstcw_rt_tp(unsigned long long iters);
extern uint64_t k_fld_fstp_tp(unsigned long long iters);
extern uint64_t k_fadd_tp(unsigned long long iters);
extern uint64_t k_fmul_tp(unsigned long long iters);
extern uint64_t k_fistp_tp(unsigned long long iters);
extern uint64_t k_fcomip_tp(unsigned long long iters);
extern uint64_t k_fcw_rt_tp(unsigned long long iters);
extern uint64_t k_stack_top_after_fild_tp(unsigned long long iters);
extern uint64_t k_stack_fld8_st8_tp(unsigned long long iters);
extern uint64_t k_fxch_st3_tp(unsigned long long iters);
extern uint64_t k_fldst_st1_to_st0_tp(unsigned long long iters);
extern uint64_t k_fincstp_fdecstp_rt_tp(unsigned long long iters);
extern uint64_t k_ffree_tag_tp(unsigned long long iters);
extern uint64_t k_fdiv_zero_ze_tp(unsigned long long iters);
extern uint64_t k_fsqrt_neg_ie_tp(unsigned long long iters);
extern uint64_t k_fistp_oe_tp(unsigned long long iters);
extern uint64_t k_stack_underflow_is_tp(unsigned long long iters);
extern uint64_t k_denormal_ue_tp(unsigned long long iters);
extern uint64_t k_precision_pe_tp(unsigned long long iters);
extern uint64_t k_fnclex_clears_tp(unsigned long long iters);
extern uint64_t k_fcom_cc_tp(unsigned long long iters);
extern uint64_t k_fcompp_cc_tp(unsigned long long iters);
extern uint64_t k_fsubr_pair_tp(unsigned long long iters);
extern uint64_t k_fisubr_m64_tp(unsigned long long iters);
extern uint64_t k_fscale_int_tp(unsigned long long iters);
extern uint64_t k_fxam_kinds_tp(unsigned long long iters);
extern uint64_t k_fstsw_allbits_tp(unsigned long long iters);
extern uint64_t k_fninit_defaults_tp(unsigned long long iters);
extern uint64_t k_fadd(unsigned long long iters);
extern uint64_t k_fmul(unsigned long long iters);
extern uint64_t k_x87_generic_lat(unsigned long long iters);
/* P1 精度类专用延迟 */
extern uint64_t k_fild_fistp_q_rt_lat(unsigned long long iters);
extern uint64_t k_fild_fistp_d_rt_lat(unsigned long long iters);
extern uint64_t k_fild_fistp_w_rt_lat(unsigned long long iters);
extern uint64_t k_fild_fistp_q_neg_lat(unsigned long long iters);
extern uint64_t k_fild_q_odd_rt_lat(unsigned long long iters);
extern uint64_t k_fild_fstp_q_dbl_lat(unsigned long long iters);
extern uint64_t k_fild_fstp_t_ext_lat(unsigned long long iters);
extern uint64_t k_fistp_q_indef_lat(unsigned long long iters);
extern uint64_t k_fisttp_q_rt_lat(unsigned long long iters);
extern uint64_t k_fld_t_fstp_t_rt_lat(unsigned long long iters);
extern uint64_t k_fbld_fistp_q_rt_lat(unsigned long long iters);
extern uint64_t k_fild_fistp_q_x8_lat(unsigned long long iters);
/* P2/P3 专用延迟 */
extern uint64_t k_rc_fistp_q_rn_lat(unsigned long long iters);
extern uint64_t k_rc_fistp_q_rd_lat(unsigned long long iters);
extern uint64_t k_rc_fistp_q_ru_lat(unsigned long long iters);
extern uint64_t k_rc_fistp_q_rz_lat(unsigned long long iters);
extern uint64_t k_rc_fstcw_rt_lat(unsigned long long iters);
extern uint64_t k_pc24_fadd_lat(unsigned long long iters);
extern uint64_t k_pc53_fadd_lat(unsigned long long iters);
extern uint64_t k_pc64_fmul_lat(unsigned long long iters);
/* 迁入/栈/异常/特殊类专用延迟 */
extern uint64_t k_fld_fstp_lat(unsigned long long iters);
extern uint64_t k_fistp_m64_lat(unsigned long long iters);
extern uint64_t k_fcomip_lat(unsigned long long iters);
extern uint64_t k_fcw_rt_lat(unsigned long long iters);
extern uint64_t k_stack_top_after_fild_lat(unsigned long long iters);
extern uint64_t k_stack_fld8_st8_lat(unsigned long long iters);
extern uint64_t k_fxch_st3_lat(unsigned long long iters);
extern uint64_t k_fldst_st1_to_st0_lat(unsigned long long iters);
extern uint64_t k_fincstp_fdecstp_rt_lat(unsigned long long iters);
extern uint64_t k_ffree_tag_lat(unsigned long long iters);
extern uint64_t k_fdiv_zero_ze_lat(unsigned long long iters);
extern uint64_t k_fsqrt_neg_ie_lat(unsigned long long iters);
extern uint64_t k_fistp_oe_lat(unsigned long long iters);
extern uint64_t k_stack_underflow_is_lat(unsigned long long iters);
extern uint64_t k_denormal_ue_lat(unsigned long long iters);
extern uint64_t k_precision_pe_lat(unsigned long long iters);
extern uint64_t k_fnclex_clears_lat(unsigned long long iters);
extern uint64_t k_fcom_cc_lat(unsigned long long iters);
extern uint64_t k_fcompp_cc_lat(unsigned long long iters);
extern uint64_t k_fsubr_pair_lat(unsigned long long iters);
extern uint64_t k_fisubr_m64_lat(unsigned long long iters);
extern uint64_t k_fscale_int_lat(unsigned long long iters);
extern uint64_t k_fxam_kinds_lat(unsigned long long iters);
extern uint64_t k_fstsw_allbits_lat(unsigned long long iters);
extern uint64_t k_fninit_defaults_lat(unsigned long long iters);

#endif /* ISB_X87_H */
