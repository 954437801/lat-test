/* isb_vec.c —— isbench 组16: 向量族功能补齐(直写口径)
 *
 * 口径(与 special 组同为定稿后的直写风格): 一条指令 = 一个定时长函数 + 一个
 * lat 函数(+ 高危族一个 KAT 探针), 不引参数化模板宏, 不为对齐 实测 的
 * form_key/权重穷举「宽度档 x 寻址段 x 前缀」组合 —— 要哪条形制就写死在函数里。
 * 测的是「这条指令的功能在目标机上对不对、代价多少」, 不是形态覆盖率。
 *
 * 只登记功能缺口: sse 组现有 38 条 + avx 组 12 条已覆盖的指令(palignr/movq/
 * pshufb/paddd/pcmpeqd/roundps/...) 一律不重复登记, 也不改动它们(保护历史对拍
 * 基线)。计划清单里的 palignr/movq 两条因此撤下(已存在), 换成同族的真实缺口:
 * movd 的两个方向、ptest、cvtsi2sd、cvtdq2pd。
 *
 * 命名 = <isa段>_<助记符>(isa 段兼作 --only 切片与 CPUID 能力名); 只有需要区分
 * 功能差时才加后段: movd_in/movd_out = GPR->XMM 与 XMM->GPR 两个方向(对翻译器
 * 是两条不同的寄存器分配路径, 不是同一条指令的形态变体)。
 *
 * 防折叠纪律(逐条照 isb_sse.c 头注那 5 条实测结论):
 *   1) 第二操作数一律 wrot()/wrot256() 轮转缓冲(load 不在依赖链上);
 *   2) 置换/幂等/衰减类(移位、and/or、乘高/乘低、unpack、shuffle、packus)链尾
 *      再 xor 一块新鲜位流 —— 光有被测那一条时 a>>3 或 a&w 十几轮就把位洗光进
 *      不动点(与 isb_shift.c 链尾 ROLL 同一个理由); 目的半恒等保留的 merge 形
 *      (punpcklqdq/cvtsi2sd/roundsd)更会被 GCC 化成「只留最后一次」;
 *   3) 纯访存/纯 store(movntdq/stmxcsr/ldmxcsr/vmovdqu)与只写标志的(ptest/comisd/
 *      vptest)用 asm volatile 钉死 + "r" 地址约束(不用 "m"), 且 lat 不给(没有
 *      寄存器依赖链, 给了也是假数) -> 该类只登记定时长, 与 special 的栅栏族同法;
 *   4) 结果落 GPR 的(pmovmskb/movd_out)链上必带 2 条骨架(rol + xor), 否则同样
 *      被最后一次化简吃掉;
 *   5) 上面那种链里被测指令每轮都执行、但不在关键路径上(它的源是轮转缓冲而非
 *      链上值) -> 这两行的 lat 读作「含提取跳的链下界」, 不当真单指令延迟;
 *      语义判定靠 KAT 逐位(o0 = 提取值本身)。想把它做成真往返链试过: GCC 会
 *      把 movd 一对(cvtsi32_si128 -> cvtsi128_si32)直接对消成标量 add。
 *   6) NEXTK(k, n) 的 n 必须是 2 的幂(宏内是 & (n-1)): 本组首版拿 64 元素的
 *      数组传了 63 -> mask 62 把 k 钉死在 0 -> 四条累加器拿到同一个值 -> GCC 的
 *      xor 对消把整个 _tp 体清空(现象: tput_ops 冲到 2.7e12)。轮转窗口统一 16。
 *
 * KAT(只上高危子集, 26/36 条): 跨寄存器类(movd 两向/cvtsi2sd)、合成标志(ptest/
 * comisd)、浮点<->整数(cvtsi2sd/cvtdq2pd/roundsd)这三类是 LATX 最容易错、而
 * 签名又最不容易定位的地方 -> 逐字段上表; 整族 lane 运算一并上表(通用 lane 模型
 * 在审计端一次写完, 边际成本低)。不上表的 10 条各有硬理由: ldmxcsr/stmxcsr 的
 * 保留位与屏蔽位组合跨机不必同; movntdq 是 store(结果 == 输入, 上了等于自证);
 * 7 条 ymm 形态结果宽 256 位, 而 ib_kv 只有 o0/o1 两个 64 位槽 -> 装不下, 语义
 * 口径继续走 sse/avx 两组的 ib_sig256(全宽, 高低半都进签名), 不为它扩表。
 * 两 ABI 共表: 探针的操作数宽与 ABI 无关(128 位 SIMD / 32 位 GPR), 计数与 imm
 * 写死在源码里 -> 只需在 x86_64 采一份。已实测(构建机真机 x86_64): 表在
 * x86_64 采完后, i386_windows.exe 与 x86_64_windows.exe 原生各跑一次 = 36 行 T /
 * 26 行 kat OK / 零 KATFAIL / 零 CRASH / K 行 0(两 ABI 的 T 行数相同, 本组没有
 * #ifdef __x86_64__ 门控的形态)。
 */
#include "ib_core.h"
#include "ib_buf.h"       /* KAT 输入推导(IB_KIN8/IB_KIN/IB_KFL)与标志注入(IB_SETF/IB_GETF) */
#include "isb_vec_kat.h"    /* KAT 真值表(采集后生成; 未取数时全是 UNSET 壳) */

static int32_t  g_ibuf[64] __attribute__((aligned(64)));   /* 128 位扰动源 */
static uint64_t g_obuf[32] __attribute__((aligned(64)));   /* store 落点(16B 对齐) */
static int32_t  g_yi[128]  __attribute__((aligned(64)));   /* 256 位扰动源 */
static uint32_t g_csr[8]   __attribute__((aligned(16)));   /* MXCSR 槽(全局: 红区口径) */
#define NEXTK(k, n) ((k) = ((k) + 1) & ((n) - 1), (k))

static inline __m128i wrot(int *k)
{
    return _mm_load_si128((const __m128i *)&g_ibuf[NEXTK(*k, 16) << 2]);
}
__attribute__((target("avx"))) static inline __m256i wrot256(int *k)
{
    return _mm256_load_si256((const __m256i *)&g_yi[NEXTK(*k, 16) << 3]);
}
/* 链尾灌回新鲜位流的统一写法(纪律 2): 被测一指令 + 1 load + 1 xor */
#define V128(a, w) _mm_xor_si128((a), w)

/* ==================== 1. SSE2 移位族(计数取计数向量的低 64 位) ====================
 * 计数走寄存器形(xmm, xmm)而不是立即数形: 前者才是真实 x86 应用里的常见形制。每条的
 * 计数是各自写死的常数(3/5/7/11/3), 审计端按同一常数复算; 全部落在
 * 1 <= 计数 < lane 宽度 区间内(计数 >= 宽度时 CF 机型相关, 不上表)。 */
static uint64_t k_psrlw(ib_uw iters){ __m128i a=_mm_set1_epi16((short)0xf0f0),n=_mm_set_epi64x(0,3); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_srl_epi16(a,n),w); }
    return ib_sig128(a); }
static uint64_t k_psrlw_tp(ib_uw iters){ __m128i a=_mm_set1_epi16((short)0xf0f0),b=_mm_set1_epi16((short)0x0f0f),
    c=_mm_set1_epi16((short)0x3333),d=_mm_set1_epi16((short)0x7777),n=_mm_set_epi64x(0,3); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_srl_epi16(a,n),w); b=V128(_mm_srl_epi16(b,n),w);
        c=V128(_mm_srl_epi16(c,n),w); d=V128(_mm_srl_epi16(d,n),w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_psrld(ib_uw iters){ __m128i a=_mm_set1_epi32(0x5a5a5a5a),n=_mm_set_epi64x(0,5); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_srl_epi32(a,n),w); }
    return ib_sig128(a); }
static uint64_t k_psrld_tp(ib_uw iters){ __m128i a=_mm_set1_epi32(0x5a5a5a5a),b=_mm_set1_epi32(0x3c3c3c3c),
    c=_mm_set1_epi32(0x0f0f0f0f),d=_mm_set1_epi32(0x77777777),n=_mm_set_epi64x(0,5); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_srl_epi32(a,n),w); b=V128(_mm_srl_epi32(b,n),w);
        c=V128(_mm_srl_epi32(c,n),w); d=V128(_mm_srl_epi32(d,n),w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_psrlq(ib_uw iters){ __m128i a=_mm_set1_epi64x(0x0123456789abcdefULL),n=_mm_set_epi64x(0,7); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_srl_epi64(a,n),w); }
    return ib_sig128(a); }
static uint64_t k_psrlq_tp(ib_uw iters){ __m128i a=_mm_set1_epi64x(0x0123456789abcdefULL),
    b=_mm_set1_epi64x(0xfedcba9876543210ULL),c=_mm_set1_epi64x(0x1122334455667788ULL),
    d=_mm_set1_epi64x(0x99aabbccddeeff00ULL),n=_mm_set_epi64x(0,7); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_srl_epi64(a,n),w); b=V128(_mm_srl_epi64(b,n),w);
        c=V128(_mm_srl_epi64(c,n),w); d=V128(_mm_srl_epi64(d,n),w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_psllq(ib_uw iters){ __m128i a=_mm_set1_epi64x(0xdeadbeefcafebabeULL),n=_mm_set_epi64x(0,11); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_sll_epi64(a,n),w); }
    return ib_sig128(a); }
static uint64_t k_psllq_tp(ib_uw iters){ __m128i a=_mm_set1_epi64x(0xdeadbeefcafebabeULL),
    b=_mm_set1_epi64x(0x0f1e2d3c4b5a6978ULL),c=_mm_set1_epi64x(0x8978675645342312ULL),
    d=_mm_set1_epi64x(0xf0f0f0f00f0f0f0fULL),n=_mm_set_epi64x(0,11); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_sll_epi64(a,n),w); b=V128(_mm_sll_epi64(b,n),w);
        c=V128(_mm_sll_epi64(c,n),w); d=V128(_mm_sll_epi64(d,n),w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
/* 算术右移: 种子取负数(最高位置 1) —— 种子恒正时符号扩展分支从头到尾不走, 实测
 * 与逻辑右移逐位相同(同 isb_shift.c 那句 IB_TOPBIT 的教训) */
static uint64_t k_psraw(ib_uw iters){ __m128i a=_mm_set1_epi16((short)0x8000),n=_mm_set_epi64x(0,3); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_sra_epi16(a,n),w); }
    return ib_sig128(a); }
static uint64_t k_psraw_tp(ib_uw iters){ __m128i a=_mm_set1_epi16((short)0x8000),b=_mm_set1_epi16((short)0xc000),
    c=_mm_set1_epi16((short)0xffff),d=_mm_set1_epi16((short)0xaaaa),n=_mm_set_epi64x(0,3); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_sra_epi16(a,n),w); b=V128(_mm_sra_epi16(b,n),w);
        c=V128(_mm_sra_epi16(c,n),w); d=V128(_mm_sra_epi16(d,n),w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }

/* ==================== 2. SSE2 洗牌/拼包族 ==================== */
static uint64_t k_punpcklwd(ib_uw iters){ __m128i a=_mm_set1_epi16((short)0x1111); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_unpacklo_epi16(a,w),w); }
    return ib_sig128(a); }
static uint64_t k_punpcklwd_tp(ib_uw iters){ __m128i a=_mm_set1_epi16((short)0x1111),b=_mm_set1_epi16((short)0x2222),
    c=_mm_set1_epi16((short)0x3333),d=_mm_set1_epi16((short)0x4444); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_unpacklo_epi16(a,w),w); b=V128(_mm_unpacklo_epi16(b,w),w);
        c=V128(_mm_unpacklo_epi16(c,w),w); d=V128(_mm_unpacklo_epi16(d,w),w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_punpcklbw(ib_uw iters){ __m128i a=_mm_set1_epi8(0x5a); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_unpacklo_epi8(a,w),w); }
    return ib_sig128(a); }
static uint64_t k_punpcklbw_tp(ib_uw iters){ __m128i a=_mm_set1_epi8(0x5a),b=_mm_set1_epi8(0xa5),
    c=_mm_set1_epi8(0x3c),d=_mm_set1_epi8(0xc3); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_unpacklo_epi8(a,w),w); b=V128(_mm_unpacklo_epi8(b,w),w);
        c=V128(_mm_unpacklo_epi8(c,w),w); d=V128(_mm_unpacklo_epi8(d,w),w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_punpcklqdq(ib_uw iters){ __m128i a=_mm_set1_epi64x(0x0102030405060708ULL); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_unpacklo_epi64(a,w),w); }
    return ib_sig128(a); }
static uint64_t k_punpcklqdq_tp(ib_uw iters){ __m128i a=_mm_set1_epi64x(0x0102030405060708ULL),
    b=_mm_set1_epi64x(0x1112131415161718ULL),c=_mm_set1_epi64x(0x2122232425262728ULL),
    d=_mm_set1_epi64x(0x3132333435363738ULL); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_unpacklo_epi64(a,w),w); b=V128(_mm_unpacklo_epi64(b,w),w);
        c=V128(_mm_unpacklo_epi64(c,w),w); d=V128(_mm_unpacklo_epi64(d,w),w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
/* 两条 shuffle 的 imm 都取 0x4E(字/双字选序 2,3,0,1): 是置换而不是复制。
 * pshuflw 的高 4 字来自 dst(即 a 自身) -> 顺带盯「merge 不许动另一半」这条语义 */
static uint64_t k_pshuflw(ib_uw iters){ __m128i a=_mm_set1_epi32(1); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_shufflelo_epi16(a,0x4E),w); }
    return ib_sig128(a); }
static uint64_t k_pshuflw_tp(ib_uw iters){ __m128i a=_mm_set1_epi32(1),b=_mm_set1_epi32(2),
    c=_mm_set1_epi32(3),d=_mm_set1_epi32(4); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_shufflelo_epi16(a,0x4E),w); b=V128(_mm_shufflelo_epi16(b,0x4E),w);
        c=V128(_mm_shufflelo_epi16(c,0x4E),w); d=V128(_mm_shufflelo_epi16(d,0x4E),w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_pshufd(ib_uw iters){ __m128i a=_mm_set1_epi32(0x0f0f0f0f); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_shuffle_epi32(a,0x4E),w); }
    return ib_sig128(a); }
static uint64_t k_pshufd_tp(ib_uw iters){ __m128i a=_mm_set1_epi32(0x0f0f0f0f),b=_mm_set1_epi32(0xf0f0f0f0),
    c=_mm_set1_epi32(0x12345678),d=_mm_set1_epi32((int)0x9abcdef0u); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_shuffle_epi32(a,0x4E),w); b=V128(_mm_shuffle_epi32(b,0x4E),w);
        c=V128(_mm_shuffle_epi32(c,0x4E),w); d=V128(_mm_shuffle_epi32(d,0x4E),w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_packuswb(ib_uw iters){ __m128i a=_mm_set1_epi16((short)-2); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_packus_epi16(a,w),w); }
    return ib_sig128(a); }
static uint64_t k_packuswb_tp(ib_uw iters){ __m128i a=_mm_set1_epi16((short)-2),b=_mm_set1_epi16((short)300),
    c=_mm_set1_epi16((short)-300),d=_mm_set1_epi16((short)2); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=V128(_mm_packus_epi16(a,w),w); b=V128(_mm_packus_epi16(b,w),w);
        c=V128(_mm_packus_epi16(c,w),w); d=V128(_mm_packus_epi16(d,w),w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }

/* ==================== 3. SSE2 算术/逻辑族 ==================== */
static uint64_t k_paddq(ib_uw iters){ __m128i a=_mm_set1_epi64x(1); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_add_epi64(a,wrot(&k)); return ib_sig128(a); }
static uint64_t k_paddq_tp(ib_uw iters){ __m128i a=_mm_set1_epi64x(1),b=_mm_set1_epi64x(2),
    c=_mm_set1_epi64x(3),d=_mm_set1_epi64x(4); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=_mm_add_epi64(a,w); b=_mm_add_epi64(b,w);
        c=_mm_add_epi64(c,w); d=_mm_add_epi64(d,w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_psubd(ib_uw iters){ __m128i a=_mm_set1_epi32(0x77777777); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_sub_epi32(a,wrot(&k)); return ib_sig128(a); }
static uint64_t k_psubd_tp(ib_uw iters){ __m128i a=_mm_set1_epi32(0x77777777),b=_mm_set1_epi32(0x12345678),
    c=_mm_set1_epi32((int)0x80000000u),d=_mm_setzero_si128(); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k); a=_mm_sub_epi32(a,w); b=_mm_sub_epi32(b,w);
        c=_mm_sub_epi32(c,w); d=_mm_sub_epi32(d,w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_pand(ib_uw iters){ __m128i a=_mm_set1_epi32((int)0xffff0000u); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ __m128i w=wrot(&k),v=wrot(&k); a=_mm_xor_si128(_mm_and_si128(a,w),v); }
    return ib_sig128(a); }
static uint64_t k_pand_tp(ib_uw iters){ __m128i a=_mm_set1_epi32((int)0xffff0000u),b=_mm_set1_epi32(0x00ff00ff),
    c=_mm_set1_epi32(0x0f0f0f0f),d=_mm_set1_epi32((int)0xf0f0f0f0); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k),v=wrot(&k);
        a=_mm_xor_si128(_mm_and_si128(a,w),v); b=_mm_xor_si128(_mm_and_si128(b,w),v);
        c=_mm_xor_si128(_mm_and_si128(c,w),v); d=_mm_xor_si128(_mm_and_si128(d,w),v); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_por(ib_uw iters){ __m128i a=_mm_setzero_si128(); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ __m128i w=wrot(&k),v=wrot(&k); a=_mm_xor_si128(_mm_or_si128(a,w),v); }
    return ib_sig128(a); }
static uint64_t k_por_tp(ib_uw iters){ __m128i a=_mm_setzero_si128(),b=_mm_set1_epi32(0x0000ff00),
    c=_mm_set1_epi32(0xff00ff00),d=_mm_set1_epi32(0x00ff0000); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k),v=wrot(&k);
        a=_mm_xor_si128(_mm_or_si128(a,w),v); b=_mm_xor_si128(_mm_or_si128(b,w),v);
        c=_mm_xor_si128(_mm_or_si128(c,w),v); d=_mm_xor_si128(_mm_or_si128(d,w),v); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_pmulhuw(ib_uw iters){ __m128i a=_mm_set1_epi16((short)0x3fff); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ __m128i w=wrot(&k),v=wrot(&k); a=_mm_xor_si128(_mm_mulhi_epu16(a,w),v); }
    return ib_sig128(a); }
static uint64_t k_pmulhuw_tp(ib_uw iters){ __m128i a=_mm_set1_epi16((short)0x3fff),b=_mm_set1_epi16((short)0x0f0f),
    c=_mm_set1_epi16((short)12345),d=_mm_set1_epi16((short)-32768); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k),v=wrot(&k);
        a=_mm_xor_si128(_mm_mulhi_epu16(a,w),v); b=_mm_xor_si128(_mm_mulhi_epu16(b,w),v);
        c=_mm_xor_si128(_mm_mulhi_epu16(c,w),v); d=_mm_xor_si128(_mm_mulhi_epu16(d,w),v); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_pmullw(ib_uw iters){ __m128i a=_mm_set1_epi16((short)0x0101); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ __m128i w=wrot(&k),v=wrot(&k); a=_mm_xor_si128(_mm_mullo_epi16(a,w),v); }
    return ib_sig128(a); }
static uint64_t k_pmullw_tp(ib_uw iters){ __m128i a=_mm_set1_epi16((short)0x0101),b=_mm_set1_epi16((short)0x0202),
    c=_mm_set1_epi16((short)-1),d=_mm_set1_epi16((short)7); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k),v=wrot(&k);
        a=_mm_xor_si128(_mm_mullo_epi16(a,w),v); b=_mm_xor_si128(_mm_mullo_epi16(b,w),v);
        c=_mm_xor_si128(_mm_mullo_epi16(c,w),v); d=_mm_xor_si128(_mm_mullo_epi16(d,w),v); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
/* pmuludq 只取每个 qword 的低 32 位相乘 -> 「高 32 位必须被忽略」本身就是被测语义
 * (译成整 64 位乘在这里现形) */
static uint64_t k_pmuludq(ib_uw iters){ __m128i a=_mm_set1_epi64x(0x00000001ffffffffULL); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ __m128i w=wrot(&k),v=wrot(&k); a=_mm_xor_si128(_mm_mul_epu32(a,w),v); }
    return ib_sig128(a); }
static uint64_t k_pmuludq_tp(ib_uw iters){ __m128i a=_mm_set1_epi64x(0x00000001ffffffffULL),
    b=_mm_set1_epi64x(0x0000000212345678ULL),c=_mm_set1_epi64x(0x00000003ffffffffULL),
    d=_mm_set1_epi64x(0x000000040f0f0f0fULL); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k),v=wrot(&k);
        a=_mm_xor_si128(_mm_mul_epu32(a,w),v); b=_mm_xor_si128(_mm_mul_epu32(b,w),v);
        c=_mm_xor_si128(_mm_mul_epu32(c,w),v); d=_mm_xor_si128(_mm_mul_epu32(d,w),v); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }

/* ==================== 4. 跨寄存器类 / 只写标志 / 控制字 / 流存储 ==================== */
/* NEXTK 的 n 必须是 2 的幂(宏内部是 & (n-1)): 这里写 63 会得到 mask 62 ->
 * k 永停 0 -> 四条累加器拿到同一个值 -> GCC 的 xor 对消直接把 _tp 体清空
 * (现象: tput_ops 冲到 1e12 量级)。轮转窗口统一用 16。 */
static uint64_t k_movd_in(ib_uw iters){ __m128i a=_mm_setzero_si128(); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_xor_si128(a,_mm_cvtsi32_si128(g_ibuf[NEXTK(k,16)]));
    return ib_sig128(a); }
static uint64_t k_movd_in_tp(ib_uw iters){ __m128i a=_mm_setzero_si128(),b=a,c=a,d=a; int k=0; ib_uw i;
    for(i=0;i<iters;i++){ a=_mm_xor_si128(a,_mm_cvtsi32_si128(g_ibuf[NEXTK(k,16)]));
        b=_mm_xor_si128(b,_mm_cvtsi32_si128(g_ibuf[NEXTK(k,16)]));
        c=_mm_xor_si128(c,_mm_cvtsi32_si128(g_ibuf[NEXTK(k,16)]));
        d=_mm_xor_si128(d,_mm_cvtsi32_si128(g_ibuf[NEXTK(k,16)])); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_movd_out(ib_uw iters){ unsigned x=0; int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k); x=(x<<1)|(x>>31); x^=(unsigned)_mm_cvtsi128_si32(w); }
    return x; }
static uint64_t k_movd_out_tp(ib_uw iters){ unsigned x=0,y=0,z=0,u=0; int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        x=(x<<1)|(x>>31); x^=(unsigned)_mm_cvtsi128_si32(w);
        y=(y<<5)|(y>>27); y^=(unsigned)_mm_cvtsi128_si32(w);
        z=(z<<9)|(z>>23); z^=(unsigned)_mm_cvtsi128_si32(w);
        u=(u<<17)|(u>>15); u^=(unsigned)_mm_cvtsi128_si32(w); }
    return x^y^z^u; }
static uint64_t k_pmovmskb(ib_uw iters){ unsigned m=0; int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k); m=(m<<1)|(m>>31); m^=(unsigned)_mm_movemask_epi8(w); }
    return m; }
static uint64_t k_pmovmskb_tp(ib_uw iters){ unsigned m=0,n=0,p=0,q=0; int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        m=(m<<1)|(m>>31); m^=(unsigned)_mm_movemask_epi8(w);
        n=(n<<5)|(n>>27); n^=(unsigned)_mm_movemask_epi8(w);
        p=(p<<9)|(p>>23); p^=(unsigned)_mm_movemask_epi8(w);
        q=(q<<17)|(q>>15); q^=(unsigned)_mm_movemask_epi8(w); }
    return m^n^p^q; }
/* ptest/comisd/vptest 只写标志 -> 没有寄存器依赖链, lat 不给(见头注纪律 3);
 * 四条 asm 之间是标志 WAW 依赖, 测的就是「连续两条能否并行」 */
__attribute__((target("sse4.1"))) static uint64_t k_ptest_tp(ib_uw iters)
{
    __m128i a = _mm_set1_epi32(0x0f0f0f0f); int k = 0; ib_uw i;
    for (i = 0; i < iters; i++) { __m128i w = wrot(&k);
        __asm__ volatile("ptest %1,%0" : : "x"(a), "x"(w) : "cc");
        __asm__ volatile("ptest %1,%0" : : "x"(a), "x"(w) : "cc");
        __asm__ volatile("ptest %1,%0" : : "x"(a), "x"(w) : "cc");
        __asm__ volatile("ptest %1,%0" : : "x"(a), "x"(w) : "cc"); }
    return (uint64_t)_mm_movemask_epi8(a);
}
static uint64_t k_comisd_tp(ib_uw iters){ __m128d a=_mm_set_pd(2.5,1.5); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128d w=_mm_castsi128_pd(wrot(&k));
        __asm__ volatile("comisd %1,%0" : : "x"(a), "x"(w) : "cc");
        __asm__ volatile("comisd %1,%0" : : "x"(a), "x"(w) : "cc");
        __asm__ volatile("comisd %1,%0" : : "x"(a), "x"(w) : "cc");
        __asm__ volatile("comisd %1,%0" : : "x"(a), "x"(w) : "cc"); }
    return ib_sig128(_mm_castpd_si128(a)); }
/* 非临时流存储: 目的必须 16 字节对齐(g_obuf 是 64 对齐 + 步长 2 个 u64)。asm 钉死
 * 防「只留最后一次 store」; 结果 == 写进去的那块 -> 不上 KAT 表 */
static uint64_t k_movntdq_tp(ib_uw iters){ __m128i v=_mm_set1_epi32(0x5a5a5a5a); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ int j=NEXTK(k,16); uint64_t *p0=&g_obuf[j<<1], *p1=&g_obuf[((j+4)&15)<<1],
        *p2=&g_obuf[((j+8)&15)<<1], *p3=&g_obuf[((j+12)&15)<<1];
        __asm__ volatile("movntdq %0,(%1)" :: "x"(v), "r"(p0) : "memory");
        __asm__ volatile("movntdq %0,(%1)" :: "x"(v), "r"(p1) : "memory");
        __asm__ volatile("movntdq %0,(%1)" :: "x"(v), "r"(p2) : "memory");
        __asm__ volatile("movntdq %0,(%1)" :: "x"(v), "r"(p3) : "memory"); }
    return ib_sig128(v); }
/* MXCSR 两条: ldmxcsr 会改掉本进程的舍入/屏蔽状态 -> 进内核先存、出内核还原,
 * 不许串扰同组后面的浮点用例(风险隔离口径, 同 ctrl 组管 %rsp 的写法)。写进去的
 * 值只用合法位: 0x5f80 = 默认 0x1f80 之上只把 RC 置成 10b(向 -inf), 保留位一律
 * 留 0 —— 拿保留位置 1 去 ldmxcsr 是 #GP, 不是被测语义 */
#define MXCSR_RC_DOWN  0x5f80u
static uint64_t k_ldmxcsr_tp(ib_uw iters)
{
    uint32_t saved = 0; ib_uw i; int k = 0;
    __asm__ volatile("stmxcsr (%0)" : : "r"(&saved) : "memory");   /* 无输出操作数 -> 编号从 %0 起 */
    for (i = 0; i < iters; i++) {
        uint32_t *p = &g_csr[NEXTK(k, 8)];
        __asm__ volatile("ldmxcsr (%0)" : : "r"(p) : "memory");
    }
    __asm__ volatile("ldmxcsr (%0)" : : "r"(&saved) : "memory");
    return saved;
}
static uint64_t k_stmxcsr_tp(ib_uw iters)
{
    uint32_t v = 0; ib_uw i; int k = 0;
    for (i = 0; i < iters; i++) {
        uint32_t *p = &g_csr[NEXTK(k, 8)];
        __asm__ volatile("stmxcsr (%0)" : : "r"(p) : "memory");
        v = *p;
    }
    return v;
}

/* ==================== 5. 浮点转换/舍入族(结果精确可反算 -> 上表) ==================== */
static uint64_t k_cvtsi2sd(ib_uw iters){ __m128d a=_mm_set_pd(0.5,0.25); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_xor_pd(a,_mm_cvtsi32_sd(_mm_setzero_pd(),g_ibuf[NEXTK(k,16)]));
    return ib_sig128(_mm_castpd_si128(a)); }
static uint64_t k_cvtsi2sd_tp(ib_uw iters){ __m128d a=_mm_set_pd(0.5,0.25),b=a,c=a,d=a; int k=0; ib_uw i;
    for(i=0;i<iters;i++){ const __m128d z=_mm_setzero_pd();
        a=_mm_xor_pd(a,_mm_cvtsi32_sd(z,g_ibuf[NEXTK(k,16)])); b=_mm_xor_pd(b,_mm_cvtsi32_sd(z,g_ibuf[NEXTK(k,16)]));
        c=_mm_xor_pd(c,_mm_cvtsi32_sd(z,g_ibuf[NEXTK(k,16)])); d=_mm_xor_pd(d,_mm_cvtsi32_sd(z,g_ibuf[NEXTK(k,16)])); }
    return ib_sig128(_mm_castpd_si128(a))^ib_sig128(_mm_castpd_si128(b))^
           ib_sig128(_mm_castpd_si128(c))^ib_sig128(_mm_castpd_si128(d)); }
static uint64_t k_cvtdq2pd(ib_uw iters){ __m128i v=_mm_setzero_si128(); __m128d a=_mm_set_pd(1.5,0.5); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ v=_mm_xor_si128(v,wrot(&k)); a=_mm_xor_pd(a,_mm_cvtepi32_pd(v)); }
    return ib_sig128(_mm_castpd_si128(a)); }
static uint64_t k_cvtdq2pd_tp(ib_uw iters){ __m128i v=_mm_setzero_si128(); __m128d a=_mm_set_pd(1.5,0.5),
    b=_mm_set_pd(2.5,3.5),c=_mm_set_pd(0.25,0.125),d=_mm_set_pd(7.75,8.125); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ v=_mm_xor_si128(v,wrot(&k)); __m128d r=_mm_cvtepi32_pd(v);
        a=_mm_xor_pd(a,r); b=_mm_xor_pd(b,r); c=_mm_xor_pd(c,r); d=_mm_xor_pd(d,r); }
    return ib_sig128(_mm_castpd_si128(a))^ib_sig128(_mm_castpd_si128(b))^
           ib_sig128(_mm_castpd_si128(c))^ib_sig128(_mm_castpd_si128(d)); }
/* roundsd $4 = 最近-取偶 + 隐藏不精确异常; 高半来自 dst -> dst==src 是合法形制,
 * 而「高半原样保留」这条 merge 语义正是探针要盯的地方 */
__attribute__((target("sse4.1"))) static uint64_t k_roundsd(ib_uw iters)
{
    __m128d a = _mm_set_pd(2.5, 1.25); int k = 0; ib_uw i;
    for (i = 0; i < iters; i++) { __m128d w = _mm_castsi128_pd(wrot(&k));
        a = _mm_xor_pd(_mm_round_sd(a, w, _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC), w); }
    return ib_sig128(_mm_castpd_si128(a));
}
__attribute__((target("sse4.1"))) static uint64_t k_roundsd_tp(ib_uw iters)
{
    __m128d a = _mm_set_pd(2.5, 1.25), b = _mm_set_pd(3.5, 0.75),
           c = _mm_set_pd(4.5, -1.5), d = _mm_set_pd(5.5, 12.25);
    int k = 0; ib_uw i;
    const int RM = _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC;
    for (i = 0; i < iters; i++) { __m128d w = _mm_castsi128_pd(wrot(&k));
        a = _mm_xor_pd(_mm_round_sd(a, w, RM), w);
        b = _mm_xor_pd(_mm_round_sd(b, w, RM), w);
        c = _mm_xor_pd(_mm_round_sd(c, w, RM), w);
        d = _mm_xor_pd(_mm_round_sd(d, w, RM), w); }
    return ib_sig128(_mm_castpd_si128(a)) ^ ib_sig128(_mm_castpd_si128(b)) ^
           ib_sig128(_mm_castpd_si128(c)) ^ ib_sig128(_mm_castpd_si128(d));
}

/* AVX/AVX2 ymm 形态的 7 条(vmovdqu/vptest/vinsertf128/vpsllq/vpsrlq/vpsrlw/
 * vpaddq)已迁入 isb_avx.c —— 归位口径: avx = 全部 VEX 编码(见 docs/设计/功能测试标准.md §5.3)。 */
/* 三条 ymm 移位与 vpaddq 的同构宏已随 7 条 VEX 形态一并迁入 isb_avx.c。 */

/* ==================== KAT 探针(26 条, 直写: 一条一个探针) ====================
 * 输入构造(与 kat_audit.py 的 v_ab()/fpd() 完全独立地各写一遍、互不参照):
 *   a  = (低 qword = i0, 高 qword = i1)                        VIN
 *   b  = (低 qword = i1, 高 qword = rotr64(i0,13))             VIN2
 *   —— b 不取 a 的交换形: 那样 paddq/pand 这类两 lane 结果会同值或被抵消,
 *      「lane 序译反」这一类错误就检不出来。
 * 标志: 整数族架构上不碰 EFLAGS -> inf/outf 一律记 0 = 不审(与 bits 组同一约定);
 *   ptest/comisd 现读标志, 只上 CF/ZF/PF(0x045) —— 这二族的 SF/AF/OF 未定义。
 * 浮点入值: 由哈希整数精确构造有限 double(fpd) —— 不拿哈希位形直当 double, 那是
 *   随机的 NaN/Inf, 无序比较的结果位形跨机不必相同(同 special 组 x87n() 的 |1
 *   一个理由)。 */
#define I0(sn, kk)  IB_KIN8(sn, kk, 0, uint64_t)
#define I1(sn, kk)  IB_KIN8(sn, kk, 1, uint64_t)
#define RB64(x, n)  (((x) >> (n)) | ((x) << (64 - (n))))
#define VIN(sn, kk)   _mm_set_epi64x((long long)I1(sn, kk), (long long)I0(sn, kk))
#define VIN2(sn, kk)  _mm_set_epi64x((long long)RB64(I0(sn, kk), 13), (long long)I1(sn, kk))
#define KIN(sn, kk)   (g->i0 = I0(sn, kk), g->i1 = I1(sn, kk), g->inf = 0)
#define VOUT(r)  do { union { __m128i v_; uint64_t q[2]; } u_; u_.v_ = (r); \
                      g->o0 = u_.q[0]; g->o1 = u_.q[1]; g->outf = 0; } while (0)

/* 由哈希整数值造有限 double: part 0 取低 32 位除 4(留 .25/.5/.75 三种小数, 出现
 * .5 平局), part 1 取高 32 位除 8(与低半不同构, 两半不会撞等值) */
static double fpd(uint64_t u, int part)
{
    int32_t v = part ? (int32_t)(uint32_t)(u >> 32) : (int32_t)(uint32_t)u;
    return (double)v / (part ? 8.0 : 4.0);
}

static void k_psrlw_kat(int kk, ib_kv *g){ __m128i a = VIN("psrlw", kk);
    KIN("psrlw", kk); VOUT(_mm_srl_epi16(a, _mm_set_epi64x(0, 3))); }
static void k_psrld_kat(int kk, ib_kv *g){ __m128i a = VIN("psrld", kk);
    KIN("psrld", kk); VOUT(_mm_srl_epi32(a, _mm_set_epi64x(0, 5))); }
static void k_psrlq_kat(int kk, ib_kv *g){ __m128i a = VIN("psrlq", kk);
    KIN("psrlq", kk); VOUT(_mm_srl_epi64(a, _mm_set_epi64x(0, 7))); }
static void k_psllq_kat(int kk, ib_kv *g){ __m128i a = VIN("psllq", kk);
    KIN("psllq", kk); VOUT(_mm_sll_epi64(a, _mm_set_epi64x(0, 11))); }
static void k_psraw_kat(int kk, ib_kv *g){ __m128i a = VIN("psraw", kk);
    KIN("psraw", kk); VOUT(_mm_sra_epi16(a, _mm_set_epi64x(0, 3))); }
static void k_punpcklwd_kat(int kk, ib_kv *g){ __m128i a = VIN("punpcklwd", kk), b = VIN2("punpcklwd", kk);
    KIN("punpcklwd", kk); VOUT(_mm_unpacklo_epi16(a, b)); }
static void k_punpcklbw_kat(int kk, ib_kv *g){ __m128i a = VIN("punpcklbw", kk), b = VIN2("punpcklbw", kk);
    KIN("punpcklbw", kk); VOUT(_mm_unpacklo_epi8(a, b)); }
static void k_punpcklqdq_kat(int kk, ib_kv *g){ __m128i a = VIN("punpcklqdq", kk), b = VIN2("punpcklqdq", kk);
    KIN("punpcklqdq", kk); VOUT(_mm_unpacklo_epi64(a, b)); }
static void k_pshuflw_kat(int kk, ib_kv *g){ __m128i a = VIN("pshuflw", kk);
    KIN("pshuflw", kk); VOUT(_mm_shufflelo_epi16(a, 0x4E)); }
static void k_pshufd_kat(int kk, ib_kv *g){ __m128i a = VIN("pshufd", kk);
    KIN("pshufd", kk); VOUT(_mm_shuffle_epi32(a, 0x4E)); }
static void k_packuswb_kat(int kk, ib_kv *g){ __m128i a = VIN("packuswb", kk), b = VIN2("packuswb", kk);
    KIN("packuswb", kk); VOUT(_mm_packus_epi16(a, b)); }
static void k_paddq_kat(int kk, ib_kv *g){ __m128i a = VIN("paddq", kk), b = VIN2("paddq", kk);
    KIN("paddq", kk); VOUT(_mm_add_epi64(a, b)); }
static void k_psubd_kat(int kk, ib_kv *g){ __m128i a = VIN("psubd", kk), b = VIN2("psubd", kk);
    KIN("psubd", kk); VOUT(_mm_sub_epi32(a, b)); }
static void k_pand_kat(int kk, ib_kv *g){ __m128i a = VIN("pand", kk), b = VIN2("pand", kk);
    KIN("pand", kk); VOUT(_mm_and_si128(a, b)); }
static void k_por_kat(int kk, ib_kv *g){ __m128i a = VIN("por", kk), b = VIN2("por", kk);
    KIN("por", kk); VOUT(_mm_or_si128(a, b)); }
static void k_pmulhuw_kat(int kk, ib_kv *g){ __m128i a = VIN("pmulhuw", kk), b = VIN2("pmulhuw", kk);
    KIN("pmulhuw", kk); VOUT(_mm_mulhi_epu16(a, b)); }
static void k_pmullw_kat(int kk, ib_kv *g){ __m128i a = VIN("pmullw", kk), b = VIN2("pmullw", kk);
    KIN("pmullw", kk); VOUT(_mm_mullo_epi16(a, b)); }
static void k_pmuludq_kat(int kk, ib_kv *g){ __m128i a = VIN("pmuludq", kk), b = VIN2("pmuludq", kk);
    KIN("pmuludq", kk); VOUT(_mm_mul_epu32(a, b)); }
static void k_pmovmskb_kat(int kk, ib_kv *g){ __m128i a = VIN("pmovmskb", kk);
    KIN("pmovmskb", kk); g->o0 = (uint32_t)_mm_movemask_epi8(a); g->o1 = 0; g->outf = 0; }
static void k_movd_in_kat(int kk, ib_kv *g){ uint32_t x = (uint32_t)I0("movd_in", kk);
    g->i0 = x; g->i1 = 0; g->inf = 0; VOUT(_mm_cvtsi32_si128((int)x)); }
static void k_movd_out_kat(int kk, ib_kv *g){ __m128i a = VIN("movd_out", kk);
    KIN("movd_out", kk); g->o0 = (uint32_t)_mm_cvtsi128_si32(a); g->o1 = 0; g->outf = 0; }
__attribute__((target("sse4.1"))) static void k_ptest_kat(int kk, ib_kv *g)
{
    __m128i a = VIN("ptest", kk), b = VIN2("ptest", kk);
    uintptr_t fl = 0;
    KIN("ptest", kk);
    /* AT&T 反序: 这里等价 Intel 的 PTEST a, b -> CF=(a AND NOT b)==0、ZF=(a AND b)==0 */
    __asm__ volatile("ptest %2,%1\n\t" IB_GETF : [fl] "=&r"(fl) : "x"(a), "x"(b) : "cc", "memory");
    g->o0 = 0; g->o1 = 0; g->outf = (uint64_t)fl & 0x045ULL;
}
static void k_comisd_kat(int kk, ib_kv *g)
{
    union { double d; uint64_t u; } ua, ub;
    __m128d a, b; uintptr_t fl = 0;
    ua.d = fpd(IB_KIN("comisd", kk, 0), 0);
    ub.d = fpd(IB_KIN("comisd", kk, 1), 1);
    g->i0 = ua.u; g->i1 = ub.u; g->inf = 0;
    a = _mm_set_pd(ua.d, ua.d); b = _mm_set_pd(ub.d, ub.d);
    /* Intel COMISD a, b: 比的是 a 的低 double vs b 的低 double(无序时 CF/ZF/PF 全 1,
     * 但入值已保证有限, 不会走到那一支) */
    __asm__ volatile("comisd %2,%1\n\t" IB_GETF : [fl] "=&r"(fl) : "x"(a), "x"(b) : "cc", "memory");
    g->o0 = 0; g->o1 = 0; g->outf = (uint64_t)fl & 0x045ULL;
}
static void k_cvtsi2sd_kat(int kk, ib_kv *g)
{
    union { double d; uint64_t u; } r;
    int32_t x = (int32_t)(uint32_t)I0("cvtsi2sd", kk);
    g->i0 = (uint32_t)x; g->i1 = I1("cvtsi2sd", kk); g->inf = 0;
    /* 高半取 i1 且架构上不许被改 -> o1 == i1 这条断言抓的就是 merge 写坏另一半 */
    r.d = _mm_cvtsd_f64(_mm_cvtsi32_sd(_mm_set_pd((double)(long long)g->i1, 0.0), x));
    g->o0 = r.u; g->o1 = I1("cvtsi2sd", kk); g->outf = 0;
}
static void k_cvtdq2pd_kat(int kk, ib_kv *g){ __m128i a = VIN("cvtdq2pd", kk);
    KIN("cvtdq2pd", kk); VOUT(_mm_castpd_si128(_mm_cvtepi32_pd(a))); }
__attribute__((target("sse4.1"))) static void k_roundsd_kat(int kk, ib_kv *g)
{
    union { double d; uint64_t u; } lo, hi;
    __m128d a;
    lo.d = fpd(IB_KIN("roundsd", kk, 0), 0);
    hi.d = fpd(IB_KIN("roundsd", kk, 1), 1);
    g->i0 = lo.u; g->i1 = hi.u; g->inf = 0;
    a = _mm_set_pd(hi.d, lo.d);
    VOUT(_mm_castpd_si128(_mm_round_sd(a, a, _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC)));
}

/* ---------------- 用例表(一行一 case; 字段序 = ib_case) ----------------
 * bpop 只给访存族(折 MB/s); lits 全 0(向量族单条代价小, 不需要卡迭代数);
 * 只写标志/纯 store 的那几条 lat = NULL(理由见头注纪律 3)。 */
static const ib_case g_cases[] = {
    { "sse2_psrlw", "sse2", k_psrlw, k_psrlw_tp, 0, NULL, 0, NULL, 0,
      k_psrlw_kat, IB_KAT_psrlw, "psrlw" },
    { "sse2_psrld", "sse2", k_psrld, k_psrld_tp, 0, NULL, 0, NULL, 0,
      k_psrld_kat, IB_KAT_psrld, "psrld" },
    { "sse2_psrlq", "sse2", k_psrlq, k_psrlq_tp, 0, NULL, 0, NULL, 0,
      k_psrlq_kat, IB_KAT_psrlq, "psrlq" },
    { "sse2_psllq", "sse2", k_psllq, k_psllq_tp, 0, NULL, 0, NULL, 0,
      k_psllq_kat, IB_KAT_psllq, "psllq" },
    { "sse2_psraw", "sse2", k_psraw, k_psraw_tp, 0, NULL, 0, NULL, 0,
      k_psraw_kat, IB_KAT_psraw, "psraw" },
    { "sse2_punpcklwd", "sse2", k_punpcklwd, k_punpcklwd_tp, 0, NULL, 0, NULL, 0,
      k_punpcklwd_kat, IB_KAT_punpcklwd, "punpcklwd" },
    { "sse2_punpcklbw", "sse2", k_punpcklbw, k_punpcklbw_tp, 0, NULL, 0, NULL, 0,
      k_punpcklbw_kat, IB_KAT_punpcklbw, "punpcklbw" },
    { "sse2_punpcklqdq", "sse2", k_punpcklqdq, k_punpcklqdq_tp, 0, NULL, 0, NULL, 0,
      k_punpcklqdq_kat, IB_KAT_punpcklqdq, "punpcklqdq" },
    { "sse2_pshuflw", "sse2", k_pshuflw, k_pshuflw_tp, 0, NULL, 0, NULL, 0,
      k_pshuflw_kat, IB_KAT_pshuflw, "pshuflw" },
    { "sse2_pshufd", "sse2", k_pshufd, k_pshufd_tp, 0, NULL, 0, NULL, 0,
      k_pshufd_kat, IB_KAT_pshufd, "pshufd" },
    { "sse2_packuswb", "sse2", k_packuswb, k_packuswb_tp, 0, NULL, 0, NULL, 0,
      k_packuswb_kat, IB_KAT_packuswb, "packuswb" },
    { "sse2_paddq", "sse2", k_paddq, k_paddq_tp, 0, NULL, 0, NULL, 0,
      k_paddq_kat, IB_KAT_paddq, "paddq" },
    { "sse2_psubd", "sse2", k_psubd, k_psubd_tp, 0, NULL, 0, NULL, 0,
      k_psubd_kat, IB_KAT_psubd, "psubd" },
    { "sse2_pand", "sse2", k_pand, k_pand_tp, 0, NULL, 0, NULL, 0,
      k_pand_kat, IB_KAT_pand, "pand" },
    { "sse2_por", "sse2", k_por, k_por_tp, 0, NULL, 0, NULL, 0,
      k_por_kat, IB_KAT_por, "por" },
    { "sse2_pmulhuw", "sse2", k_pmulhuw, k_pmulhuw_tp, 0, NULL, 0, NULL, 0,
      k_pmulhuw_kat, IB_KAT_pmulhuw, "pmulhuw" },
    { "sse2_pmullw", "sse2", k_pmullw, k_pmullw_tp, 0, NULL, 0, NULL, 0,
      k_pmullw_kat, IB_KAT_pmullw, "pmullw" },
    { "sse2_pmuludq", "sse2", k_pmuludq, k_pmuludq_tp, 0, NULL, 0, NULL, 0,
      k_pmuludq_kat, IB_KAT_pmuludq, "pmuludq" },
    { "sse2_pmovmskb", "sse2", k_pmovmskb, k_pmovmskb_tp, 0, NULL, 0, NULL, 0,
      k_pmovmskb_kat, IB_KAT_pmovmskb, "pmovmskb" },
    { "sse2_movd_in", "sse2", k_movd_in, k_movd_in_tp, 0, NULL, 0, NULL, 0,
      k_movd_in_kat, IB_KAT_movd_in, "movd_in" },
    { "sse2_movd_out", "sse2", k_movd_out, k_movd_out_tp, 0, NULL, 0, NULL, 0,
      k_movd_out_kat, IB_KAT_movd_out, "movd_out" },
    { "sse41_ptest", "sse4.1", NULL, k_ptest_tp, 0, NULL, 0, NULL, 0,
      k_ptest_kat, IB_KAT_ptest, "ptest" },
    { "sse_comisd", "sse", NULL, k_comisd_tp, 0, NULL, 0, NULL, 0,
      k_comisd_kat, IB_KAT_comisd, "comisd" },
    { "sse2_cvtsi2sd", "sse2", k_cvtsi2sd, k_cvtsi2sd_tp, 0, NULL, 0, NULL, 0,
      k_cvtsi2sd_kat, IB_KAT_cvtsi2sd, "cvtsi2sd" },
    { "sse2_cvtdq2pd", "sse2", k_cvtdq2pd, k_cvtdq2pd_tp, 0, NULL, 0, NULL, 0,
      k_cvtdq2pd_kat, IB_KAT_cvtdq2pd, "cvtdq2pd" },
    { "sse41_roundsd", "sse4.1", k_roundsd, k_roundsd_tp, 0, NULL, 0, NULL, 0,
      k_roundsd_kat, IB_KAT_roundsd, "roundsd" },
    { "sse2_movntdq", "sse2", NULL, k_movntdq_tp, 0, NULL, 16 },
    { "sse_ldmxcsr", "sse", NULL, k_ldmxcsr_tp, 0, NULL, 4 },
    { "sse_stmxcsr", "sse", NULL, k_stmxcsr_tp, 0, NULL, 4 },
};
#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

int main(int argc, char **argv)
{
    volatile int32_t *vi = g_ibuf;      /* volatile 写: 内容对编译器不可知, 防被常数化 */
    volatile uint64_t *vo = g_obuf;
    volatile uint32_t *vc = g_csr;
    volatile int32_t *vy = g_yi;   /* ymm 扰动源同口径走 volatile 写 */
    int i;

    for (i = 0; i < 64; i++) { vi[i] = i * 3 + 1; vy[i] = i * 7 + 5; }
    for (i = 0; i < 64; i++) vy[64 + i] = 0x5a00 + i * 131;
    for (i = 0; i < 32; i++) { union { double d; uint64_t u; } cv; cv.d = 1.5 * i + 1.5;
        vo[i] = cv.u; }
    for (i = 0; i < 8; i++) vc[i] = MXCSR_RC_DOWN;
    /* asm "+m": 声明缓冲被外部读改写 -> 破坏 GCC 的「无写者 -> 内容恒 0」推理 */
    __asm__ volatile("" : "+m"(g_ibuf[0]), "+m"(g_obuf[0]), "+m"(g_yi[0]), "+m"(g_csr[0])
                     : : "memory");
    ib_init(argc, argv);
    ib_hdr("vec", NCASES);
    /* 不回传 ib_run_cases 的返回值(= 全绿用例数): isbench.py 与 gen_val.sh 都按
     * rc!=0 判整组失败。成败看 T 行的 status/kat_st/CRASH 列, 同其余各组。 */
    ib_run_cases("vec", g_cases, NCASES);
    return 0;
}
