/* isb_sse.c —— isbench 组2: legacy SSE/SSE2/SSE3/SSSE3/SSE4.x 全族
 * 迁移来源: hf_probe.c SSE~SSE4.2 段, insn_probe.c R4_LEGACY 段。
 * 度量: 算术/洗牌类 = lat(单依赖链) + tput(多独立链); 访存类 = tput 为主
 *       (bpop 折算 MB/s), lat 近似参考(无寄存器依赖链, 同 legacy 注释)。
 * 编码纪律: 全局不开 -mavx*, SSE3 及以上 target attr 单启 -> legacy 66/0F 编码。
 * 用例名约定: 首段 = ISA 段(sse/sse2/sse3/ssse3/sse41/sse42), 供报告肉眼分辨与
 *   --only=<段>_ 子集过滤; 原名(如 pshufb)保留为名字后段, legacy 数值抽查按子串 grep 仍可命中。
 *
 * 防折叠纪律(GCC 14 实测, 假数据事故复盘):
 *   1) 常数种子+常数掩码的依赖链会被闭式折叠/不动点化简, 甚至整循环 DCE
 *      (tput 虚报 1e12~2.5e12 ops/s, lat 虚报 0.07ns);
 *   2) 第二操作数/掩码一律从轮转缓冲读(wrot/wrotf/wrotd)——load 不在依赖链上,
 *      不污染被测 op 延迟; 单目/幂等指令(pshufb/pabsw/roundps...)链输入先 xor 扰动;
 *   3) 纯访存用例(结果不喂回控制流)会被「最后一次 load/store 化」或 xor 奇偶
 *      代数化简删除 —— movss/movsd/movq/movaps_st 用 asm volatile 单指令钉死;
 *   4) 访存地址必须用寄存器约束 "r"(p), 不要用 "m"(*p) —— GCC 会把 "m" 的
 *      地址提升为循环不变量(实测 rdx 恒指数组首元素);
 *   5) 签名收敛(不动点/同址)的用例 tput 物理合理即真执行, 勿仅凭 SAME 判假;
 *      自检手段: 不同 --iters 双跑, 签名变 = 真依赖链(见冒烟脚本)。
 */
#include "ib_core.h"
#include "ib_buf.h"        /* KAT 输入推导(IB_KIN8) */
#include "isb_sse_kat.h"   /* KAT 真值表(采集后生成; 未取数时全 UNSET) */

static float    g_fbuf[64] __attribute__((aligned(64)));
static double   g_dbuf[32] __attribute__((aligned(64)));
static int32_t  g_ibuf[64] __attribute__((aligned(64)));
static uint64_t g_obuf[32] __attribute__((aligned(64)));
static float    g_sbuf[64] __attribute__((aligned(64)));   /* movaps_st 专用: 不污染 load 缓冲 */
#define NEXTK(k, n) ((k) = ((k) + 1) & ((n) - 1), (k))
/* ---- 反折叠扰动源: 每轮从 g_ibuf 轮转 movdqa 一块(内容为非对称常量) ---- */
static inline __m128i wrot(int *k)
{
    return _mm_load_si128((const __m128i *)&g_ibuf[NEXTK(*k, 16) << 2]);
}
/* 浮点扰动源: wrotd 读 g_obuf(double 位模式, 有限非零 1.5..48, 跨机确定);
 * wrotf 从 g_ibuf 位模式 cast(denormal: 加不进主值, 但每轮真执行, 数值保真)。 */
static inline __m128 wrotf(int *k)
{
    return _mm_castsi128_ps(wrot(k));
}
static inline __m128d wrotd(int *k)
{
    return _mm_load_pd((const double *)&g_obuf[NEXTK(*k, 16) << 1]);
}

/* ==================== SSE (legacy): 访存族(load 轮转防提出循环) ==================== */
static uint64_t k_movdqa(ib_uw iters){ __m128i s=_mm_setzero_si128(); int k=0;
    ib_uw i; for(i=0;i<iters;i++) s=_mm_load_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]);
    return ib_sig128(s); }
static uint64_t k_movdqa_tp(ib_uw iters){ __m128i s0=_mm_setzero_si128(),s1=_mm_setzero_si128(),
    s2=_mm_setzero_si128(),s3=_mm_setzero_si128(); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ s0=_mm_load_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]);
        s1=_mm_load_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]); s2=_mm_load_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]);
        s3=_mm_load_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]); }
    return ib_sig128(s0)^ib_sig128(s1)^ib_sig128(s2)^ib_sig128(s3); }
static uint64_t k_movdqu(ib_uw iters){ __m128i s=_mm_setzero_si128(); int k=0;
    ib_uw i; for(i=0;i<iters;i++) s=_mm_loadu_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]);
    return ib_sig128(s); }
static uint64_t k_movdqu_tp(ib_uw iters){ __m128i s0=_mm_setzero_si128(),s1=_mm_setzero_si128(),
    s2=_mm_setzero_si128(),s3=_mm_setzero_si128(); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ s0=_mm_loadu_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]);
        s1=_mm_loadu_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]); s2=_mm_loadu_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]);
        s3=_mm_loadu_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]); }
    return ib_sig128(s0)^ib_sig128(s1)^ib_sig128(s2)^ib_sig128(s3); }

static uint64_t k_movups(ib_uw iters){ __m128 s=_mm_setzero_ps(); int k=0;
    ib_uw i; for(i=0;i<iters;i++) s=_mm_loadu_ps(&g_fbuf[NEXTK(k,16)<<2]);
    return ib_sig128(_mm_castps_si128(s)); }
static uint64_t k_movups_tp(ib_uw iters){ __m128 s0=_mm_setzero_ps(),s1=_mm_setzero_ps(),
    s2=_mm_setzero_ps(),s3=_mm_setzero_ps(); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ s0=_mm_loadu_ps(&g_fbuf[NEXTK(k,16)<<2]);
        s1=_mm_loadu_ps(&g_fbuf[NEXTK(k,16)<<2]); s2=_mm_loadu_ps(&g_fbuf[NEXTK(k,16)<<2]);
        s3=_mm_loadu_ps(&g_fbuf[NEXTK(k,16)<<2]); }
    return ib_sig128(_mm_castps_si128(s0))^ib_sig128(_mm_castps_si128(s1))^
           ib_sig128(_mm_castps_si128(s2))^ib_sig128(_mm_castps_si128(s3)); }
static uint64_t k_movaps(ib_uw iters){ __m128 s=_mm_setzero_ps(); int k=0;
    ib_uw i; for(i=0;i<iters;i++) s=_mm_load_ps(&g_fbuf[NEXTK(k,16)<<2]);
    return ib_sig128(_mm_castps_si128(s)); }
static uint64_t k_movaps_tp(ib_uw iters){ __m128 s0=_mm_setzero_ps(),s1=_mm_setzero_ps(),
    s2=_mm_setzero_ps(),s3=_mm_setzero_ps(); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ s0=_mm_load_ps(&g_fbuf[NEXTK(k,16)<<2]);
        s1=_mm_load_ps(&g_fbuf[NEXTK(k,16)<<2]); s2=_mm_load_ps(&g_fbuf[NEXTK(k,16)<<2]);
        s3=_mm_load_ps(&g_fbuf[NEXTK(k,16)<<2]); }
    return ib_sig128(_mm_castps_si128(s0))^ib_sig128(_mm_castps_si128(s1))^
           ib_sig128(_mm_castps_si128(s2))^ib_sig128(_mm_castps_si128(s3)); }
static uint64_t k_movaps_st(ib_uw iters){ __m128 v=_mm_set1_ps(1.5f); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ const float *p=&g_sbuf[(NEXTK(k,16)<<2)];
        __asm__ volatile("movaps %0,(%1)" :: "x"(v), "r"(p)); }
    return ib_sig128(_mm_castps_si128(v)); }
static uint64_t k_movaps_st_tp(ib_uw iters){ __m128 v=_mm_set1_ps(1.5f); int k=0;
    ib_uw i;
    for(i=0;i<iters;i++){ int j=NEXTK(k,16);
        const float *p0=&g_sbuf[j<<2], *p1=&g_sbuf[((j+1)&15)<<2],
            *p2=&g_sbuf[((j+4)&15)<<2], *p3=&g_sbuf[((j+8)&15)<<2];
        __asm__ volatile("movaps %0,(%1)" :: "x"(v), "r"(p0));
        __asm__ volatile("movaps %0,(%1)" :: "x"(v), "r"(p1));
        __asm__ volatile("movaps %0,(%1)" :: "x"(v), "r"(p2));
        __asm__ volatile("movaps %0,(%1)" :: "x"(v), "r"(p3)); }
    return ib_sig128(_mm_castps_si128(v)); }
static uint64_t k_movss(ib_uw iters){ __m128 s=_mm_setzero_ps(); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ const float *p=&g_fbuf[NEXTK(k,63)];
        __asm__ volatile("movss (%1),%0" : "=x"(s) : "r"(p)); }
    return ib_sig128(_mm_castps_si128(s)); }
static uint64_t k_movss_tp(ib_uw iters){ __m128 s0=_mm_setzero_ps(),s1=_mm_setzero_ps(),
    s2=_mm_setzero_ps(),s3=_mm_setzero_ps(); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ const float *p0=&g_fbuf[NEXTK(k,63)], *p1=&g_fbuf[NEXTK(k,63)],
        *p2=&g_fbuf[NEXTK(k,63)], *p3=&g_fbuf[NEXTK(k,63)];
        __asm__ volatile("movss (%1),%0" : "=x"(s0) : "r"(p0));
        __asm__ volatile("movss (%1),%0" : "=x"(s1) : "r"(p1));
        __asm__ volatile("movss (%1),%0" : "=x"(s2) : "r"(p2));
        __asm__ volatile("movss (%1),%0" : "=x"(s3) : "r"(p3)); }
    return ib_sig128(_mm_castps_si128(s0))^ib_sig128(_mm_castps_si128(s1))^
           ib_sig128(_mm_castps_si128(s2))^ib_sig128(_mm_castps_si128(s3)); }
static uint64_t k_movsd(ib_uw iters){ __m128d s=_mm_setzero_pd(); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ const double *p=&g_dbuf[NEXTK(k,31)];
        __asm__ volatile("movsd (%1),%0" : "=x"(s) : "r"(p)); }
    return ib_sig128(_mm_castpd_si128(s)); }
static uint64_t k_movsd_tp(ib_uw iters){ __m128d s0=_mm_setzero_pd(),s1=_mm_setzero_pd(),
    s2=_mm_setzero_pd(),s3=_mm_setzero_pd(); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ const double *p0=&g_dbuf[NEXTK(k,31)], *p1=&g_dbuf[NEXTK(k,31)],
        *p2=&g_dbuf[NEXTK(k,31)], *p3=&g_dbuf[NEXTK(k,31)];
        __asm__ volatile("movsd (%1),%0" : "=x"(s0) : "r"(p0));
        __asm__ volatile("movsd (%1),%0" : "=x"(s1) : "r"(p1));
        __asm__ volatile("movsd (%1),%0" : "=x"(s2) : "r"(p2));
        __asm__ volatile("movsd (%1),%0" : "=x"(s3) : "r"(p3)); }
    return ib_sig128(_mm_castpd_si128(s0))^ib_sig128(_mm_castpd_si128(s1))^
           ib_sig128(_mm_castpd_si128(s2))^ib_sig128(_mm_castpd_si128(s3)); }
static uint64_t k_movq(ib_uw iters){ __m128i s=_mm_setzero_si128(); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ const uint64_t *p=&g_obuf[NEXTK(k,31)];
        __asm__ volatile("movq (%1),%0" : "=x"(s) : "r"(p)); }
    return ib_sig128(s); }
static uint64_t k_movq_tp(ib_uw iters){ __m128i s0=_mm_setzero_si128(),s1=_mm_setzero_si128(),
    s2=_mm_setzero_si128(),s3=_mm_setzero_si128(); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ const uint64_t *p0=&g_obuf[NEXTK(k,31)], *p1=&g_obuf[NEXTK(k,31)],
        *p2=&g_obuf[NEXTK(k,31)], *p3=&g_obuf[NEXTK(k,31)];
        __asm__ volatile("movq (%1),%0" : "=x"(s0) : "r"(p0));
        __asm__ volatile("movq (%1),%0" : "=x"(s1) : "r"(p1));
        __asm__ volatile("movq (%1),%0" : "=x"(s2) : "r"(p2));
        __asm__ volatile("movq (%1),%0" : "=x"(s3) : "r"(p3)); }
    return ib_sig128(s0)^ib_sig128(s1)^ib_sig128(s2)^ib_sig128(s3); }

/* ============ 逐指令紧凑手写: lat(单依赖链) + tput(4 独立链), 种子与 legacy 对齐 ============ */
/* ---- SSE 浮点族(编码 0F, 非 VEX) ---- */
static uint64_t k_mulss(ib_uw iters){ __m128 a=_mm_set_ss(1.0f); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_mul_ss(a,wrotf(&k)); return ib_sig128(_mm_castps_si128(a)); }
static uint64_t k_mulss_tp(ib_uw iters){ __m128 a=_mm_set_ss(1.0f),b=_mm_set_ss(1.25f),
    c=_mm_set_ss(0.75f),d=_mm_set_ss(2.0f); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128 w=wrotf(&k);
        a=_mm_mul_ss(a,w); b=_mm_mul_ss(b,w); c=_mm_mul_ss(c,w); d=_mm_mul_ss(d,w); }
    return ib_sig128(_mm_castps_si128(a))^ib_sig128(_mm_castps_si128(b))^
           ib_sig128(_mm_castps_si128(c))^ib_sig128(_mm_castps_si128(d)); }
static uint64_t k_addss(ib_uw iters){ __m128 a=_mm_set_ss(1.0f); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_add_ss(a,wrotf(&k)); return ib_sig128(_mm_castps_si128(a)); }
static uint64_t k_addss_tp(ib_uw iters){ __m128 a=_mm_set_ss(1.0f),b=_mm_set_ss(1.25f),
    c=_mm_set_ss(0.75f),d=_mm_set_ss(2.0f); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128 w=wrotf(&k);
        a=_mm_add_ss(a,w); b=_mm_add_ss(b,w); c=_mm_add_ss(c,w); d=_mm_add_ss(d,w); }
    return ib_sig128(_mm_castps_si128(a))^ib_sig128(_mm_castps_si128(b))^
           ib_sig128(_mm_castps_si128(c))^ib_sig128(_mm_castps_si128(d)); }
static uint64_t k_subss(ib_uw iters){ __m128 a=_mm_set_ss(1e6f); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_sub_ss(a,wrotf(&k)); return ib_sig128(_mm_castps_si128(a)); }
static uint64_t k_subss_tp(ib_uw iters){ __m128 a=_mm_set_ss(1e6f),b=_mm_set_ss(1e7f),
    c=_mm_set_ss(1e8f),d=_mm_set_ss(1e9f); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128 w=wrotf(&k);
        a=_mm_sub_ss(a,w); b=_mm_sub_ss(b,w); c=_mm_sub_ss(c,w); d=_mm_sub_ss(d,w); }
    return ib_sig128(_mm_castps_si128(a))^ib_sig128(_mm_castps_si128(b))^
           ib_sig128(_mm_castps_si128(c))^ib_sig128(_mm_castps_si128(d)); }
static uint64_t k_shufps(ib_uw iters){ __m128 a=_mm_set_ps(4,3,2,1); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_shuffle_ps(a,_mm_castsi128_ps(wrot(&k)),0x4e);
    return ib_sig128(_mm_castps_si128(a)); }
static uint64_t k_shufps_tp(ib_uw iters){ __m128 a=_mm_set_ps(4,3,2,1),b=_mm_set_ps(1,2,3,4),
    c=_mm_set_ps(5,6,7,8),d=_mm_set_ps(9,10,11,12); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128 w=_mm_castsi128_ps(wrot(&k));
        a=_mm_shuffle_ps(a,w,0x4e); b=_mm_shuffle_ps(b,w,0x1b);
        c=_mm_shuffle_ps(c,w,0x4e); d=_mm_shuffle_ps(d,w,0x1b); }
    return ib_sig128(_mm_castps_si128(a))^ib_sig128(_mm_castps_si128(b))^
           ib_sig128(_mm_castps_si128(c))^ib_sig128(_mm_castps_si128(d)); }
/* ---- SSE2 族 ---- */
/* ---- sse2_paddd 的 b8: 连续8指令块执行时间(同行新列, 不新建 case 行) ----
 * 与单指令 paddd_tp(4 链共享同一 wrot)对照: 8 个 wrot 相位起点错开 2 块,
 * 同轮 8 条 paddd 操作数互异且逐轮轮转 —— 防"同值重复"被数据级优化利用;
 * 只测每块执行 ns(定时长窗口), 结果与 paddd 行 lat_ns/tput_ops 同列族对照;
 * 链初值用互异大常数(非连续小整数): 周期对称下 8 链只差初值, 若初值
 * 连续(1..8)+lane 等距会令 sig16 数学归零(实测恒 0000) —— 乱序种子
 * 打破相消, 签名恢复区分度。
 * x86-64: 8 链; i386 仅 8 个 xmm: 4 链 x 每轮 2 相位, 块内仍 8 条连续指令。 */
static uint64_t k_paddd_b8(ib_uw iters){
#ifdef __x86_64__
    __m128i a0=_mm_set1_epi32(0x9e3779b9),a1=_mm_set1_epi32(0x85ebca6b),a2=_mm_set1_epi32(0xc2b2ae35),a3=_mm_set1_epi32(0x27d4eb2f),
            a4=_mm_set1_epi32(0x165667b1),a5=_mm_set1_epi32(0xd5a9d4c5),a6=_mm_set1_epi32(0xbe9e7c55),a7=_mm_set1_epi32(0x53e5a0c2);
    int k0=0,k1=2,k2=4,k3=6,k4=8,k5=10,k6=12,k7=14; ib_uw i;
    for(i=0;i<iters;i++){
        a0=_mm_add_epi32(a0,wrot(&k0)); a1=_mm_add_epi32(a1,wrot(&k1));
        a2=_mm_add_epi32(a2,wrot(&k2)); a3=_mm_add_epi32(a3,wrot(&k3));
        a4=_mm_add_epi32(a4,wrot(&k4)); a5=_mm_add_epi32(a5,wrot(&k5));
        a6=_mm_add_epi32(a6,wrot(&k6)); a7=_mm_add_epi32(a7,wrot(&k7)); }
    return ib_sig128(a0)^ib_sig128(a1)^ib_sig128(a2)^ib_sig128(a3)^
           ib_sig128(a4)^ib_sig128(a5)^ib_sig128(a6)^ib_sig128(a7);
#else
    __m128i a=_mm_set1_epi32(0x9e3779b9),b=_mm_set1_epi32(0x85ebca6b),c=_mm_set1_epi32(0xc2b2ae35),d=_mm_set1_epi32(0x27d4eb2f);
    int k0=0,k1=2,k2=4,k3=6,k4=8,k5=10,k6=12,k7=14; ib_uw i;
    for(i=0;i<iters;i++){          /* 4 链 x 每轮 2 相位, 块内仍 8 条连续 paddd */
        a=_mm_add_epi32(a,wrot(&k0)); b=_mm_add_epi32(b,wrot(&k1));
        c=_mm_add_epi32(c,wrot(&k2)); d=_mm_add_epi32(d,wrot(&k3));
        a=_mm_add_epi32(a,wrot(&k4)); b=_mm_add_epi32(b,wrot(&k5));
        c=_mm_add_epi32(c,wrot(&k6)); d=_mm_add_epi32(d,wrot(&k7)); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d);
#endif
}
static uint64_t k_xorps(ib_uw iters){ __m128 a=_mm_set1_ps(1.0f); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_xor_ps(a,_mm_castsi128_ps(wrot(&k)));
    return ib_sig128(_mm_castps_si128(a)); }
static uint64_t k_xorps_tp(ib_uw iters){ __m128 a=_mm_set1_ps(1.0f),b=_mm_set1_ps(1.25f),
    c=_mm_set1_ps(2.5f),d=_mm_set1_ps(3.75f); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128 w=_mm_castsi128_ps(wrot(&k));
        a=_mm_xor_ps(a,w); b=_mm_xor_ps(b,w); c=_mm_xor_ps(c,w); d=_mm_xor_ps(d,w); }
    return ib_sig128(_mm_castps_si128(a))^ib_sig128(_mm_castps_si128(b))^
           ib_sig128(_mm_castps_si128(c))^ib_sig128(_mm_castps_si128(d)); }
static uint64_t k_pcmpeqd(ib_uw iters){ __m128i a=_mm_set1_epi32(1); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_or_si128(a,_mm_cmpeq_epi32(a,wrot(&k)));
    return ib_sig128(a); }
static uint64_t k_pcmpeqd_tp(ib_uw iters){ __m128i a=_mm_set1_epi32(1),b=_mm_set1_epi32(2),
    c=_mm_set1_epi32(3),d=_mm_set1_epi32(4); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_or_si128(a,_mm_cmpeq_epi32(a,w)); b=_mm_or_si128(b,_mm_cmpeq_epi32(b,w));
        c=_mm_or_si128(c,_mm_cmpeq_epi32(c,w)); d=_mm_or_si128(d,_mm_cmpeq_epi32(d,w)); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_paddd(ib_uw iters){ __m128i a=_mm_set1_epi32(0x5a5a5a5a); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_add_epi32(a,wrot(&k)); return ib_sig128(a); }
static uint64_t k_paddd_tp(ib_uw iters){ __m128i a=_mm_set1_epi32(1),b=_mm_set1_epi32(2),
    c=_mm_set1_epi32(3),d=_mm_set1_epi32(4); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_add_epi32(a,w); b=_mm_add_epi32(b,w); c=_mm_add_epi32(c,w); d=_mm_add_epi32(d,w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_paddw(ib_uw iters){ __m128i a=_mm_set1_epi16(0x0102); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_add_epi16(a,wrot(&k)); return ib_sig128(a); }
static uint64_t k_paddw_tp(ib_uw iters){ __m128i a=_mm_set1_epi16(1),b=_mm_set1_epi16(2),
    c=_mm_set1_epi16(3),d=_mm_set1_epi16(4); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_add_epi16(a,w); b=_mm_add_epi16(b,w); c=_mm_add_epi16(c,w); d=_mm_add_epi16(d,w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_pmaddwd(ib_uw iters){ __m128i a=_mm_set1_epi16(3); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_madd_epi16(a,wrot(&k)); return ib_sig128(a); }
static uint64_t k_pmaddwd_tp(ib_uw iters){ __m128i a=_mm_set1_epi16(3),b=_mm_set1_epi16(5),
    c=_mm_set1_epi16(7),d=_mm_set1_epi16(9); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_madd_epi16(a,w); b=_mm_madd_epi16(b,w); c=_mm_madd_epi16(c,w); d=_mm_madd_epi16(d,w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_addpd(ib_uw iters){ __m128d a=_mm_set1_pd(1.0); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_add_pd(a,wrotd(&k)); return ib_sig128(_mm_castpd_si128(a)); }
static uint64_t k_addpd_tp(ib_uw iters){ __m128d a=_mm_set1_pd(1.0),b=_mm_set1_pd(1.5),
    c=_mm_set1_pd(2.5),d=_mm_set1_pd(3.5); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128d w=wrotd(&k);
        a=_mm_add_pd(a,w); b=_mm_add_pd(b,w); c=_mm_add_pd(c,w); d=_mm_add_pd(d,w); }
    return ib_sig128(_mm_castpd_si128(a))^ib_sig128(_mm_castpd_si128(b))^
           ib_sig128(_mm_castpd_si128(c))^ib_sig128(_mm_castpd_si128(d)); }
static uint64_t k_mulpd(ib_uw iters){ __m128d a=_mm_set1_pd(1.0); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_mul_pd(a,wrotd(&k)); return ib_sig128(_mm_castpd_si128(a)); }
static uint64_t k_mulpd_tp(ib_uw iters){ __m128d a=_mm_set1_pd(1.0),b=_mm_set1_pd(1.5),
    c=_mm_set1_pd(2.5),d=_mm_set1_pd(3.5); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128d w=wrotd(&k);
        a=_mm_mul_pd(a,w); b=_mm_mul_pd(b,w); c=_mm_mul_pd(c,w); d=_mm_mul_pd(d,w); }
    return ib_sig128(_mm_castpd_si128(a))^ib_sig128(_mm_castpd_si128(b))^
           ib_sig128(_mm_castpd_si128(c))^ib_sig128(_mm_castpd_si128(d)); }
static uint64_t k_addsd(ib_uw iters){ __m128d a=_mm_setzero_pd(); int k=0;
    ib_uw i; for(i=0;i<iters;i++){ const double *p=(const double*)&g_obuf[NEXTK(k,16)<<1];
        __asm__ volatile("addsd (%1),%0" : "+x"(a) : "r"(p)); }
    return ib_sig128(_mm_castpd_si128(a)); }
static uint64_t k_addsd_tp(ib_uw iters){ __m128d a=_mm_setzero_pd(),b=_mm_setzero_pd(),
    c=_mm_setzero_pd(),d=_mm_setzero_pd(); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ const double *p=(const double*)&g_obuf[NEXTK(k,16)<<1];
        __asm__ volatile("addsd (%1),%0" : "+x"(a) : "r"(p));
        __asm__ volatile("addsd (%1),%0" : "+x"(b) : "r"(p));
        __asm__ volatile("addsd (%1),%0" : "+x"(c) : "r"(p));
        __asm__ volatile("addsd (%1),%0" : "+x"(d) : "r"(p)); }
    return ib_sig128(_mm_castpd_si128(a))^ib_sig128(_mm_castpd_si128(b))^
           ib_sig128(_mm_castpd_si128(c))^ib_sig128(_mm_castpd_si128(d)); }
static uint64_t k_divsd(ib_uw iters){ __m128d a=_mm_set_sd(1e9); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_div_sd(a,wrotd(&k)); return ib_sig128(_mm_castpd_si128(a)); }
static uint64_t k_divsd_tp(ib_uw iters){ __m128d a=_mm_set_sd(1e9),b=_mm_set_sd(1e8),
    c=_mm_set_sd(1e7),d=_mm_set_sd(1e6); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128d w=wrotd(&k);
        a=_mm_div_sd(a,w); b=_mm_div_sd(b,w); c=_mm_div_sd(c,w); d=_mm_div_sd(d,w); }
    return ib_sig128(_mm_castpd_si128(a))^ib_sig128(_mm_castpd_si128(b))^
           ib_sig128(_mm_castpd_si128(c))^ib_sig128(_mm_castpd_si128(d)); }
static uint64_t k_cvttpd2dq(ib_uw iters){ __m128d d=_mm_set_pd(3.5,1.25); int k=0;
    ib_uw i; for(i=0;i<iters;i++) d=_mm_add_pd(d,wrotd(&k)); return ib_sig128(_mm_cvttpd_epi32(d)); }
static uint64_t k_cvttpd2dq_tp(ib_uw iters){ __m128d a=_mm_set_pd(3.5,1.25),b=_mm_set_pd(4.5,2.25),
    c=_mm_set_pd(5.5,3.25),d=_mm_set_pd(6.5,4.25); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128d w=wrotd(&k);
        a=_mm_add_pd(a,w); b=_mm_add_pd(b,w); c=_mm_add_pd(c,w); d=_mm_add_pd(d,w); }
    return ib_sig128(_mm_cvttpd_epi32(a))^ib_sig128(_mm_cvttpd_epi32(b))^
           ib_sig128(_mm_cvttpd_epi32(c))^ib_sig128(_mm_cvttpd_epi32(d)); }
/* ---- SSE3(target="sse3") ---- */
__attribute__((target("sse3"))) static uint64_t k_haddpd(ib_uw iters){ __m128d a=_mm_set_pd(1,2); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_hadd_pd(a,wrotd(&k)); return ib_sig128(_mm_castpd_si128(a)); }
__attribute__((target("sse3"))) static uint64_t k_haddpd_tp(ib_uw iters){ __m128d a=_mm_set_pd(1,2),b=_mm_set_pd(1.5,2.5),
    c=_mm_set_pd(3,4),d=_mm_set_pd(3.5,4.5); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128d w=wrotd(&k);
        a=_mm_hadd_pd(a,w); b=_mm_hadd_pd(b,w); c=_mm_hadd_pd(c,w); d=_mm_hadd_pd(d,w); }
    return ib_sig128(_mm_castpd_si128(a))^ib_sig128(_mm_castpd_si128(b))^
           ib_sig128(_mm_castpd_si128(c))^ib_sig128(_mm_castpd_si128(d)); }
__attribute__((target("sse3"))) static uint64_t k_addsubpd(ib_uw iters){ __m128d a=_mm_set1_pd(1.0); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_addsub_pd(a,wrotd(&k)); return ib_sig128(_mm_castpd_si128(a)); }
__attribute__((target("sse3"))) static uint64_t k_addsubpd_tp(ib_uw iters){ __m128d a=_mm_set1_pd(1.0),b=_mm_set1_pd(1.5),
    c=_mm_set1_pd(2.5),d=_mm_set1_pd(3.5); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128d w=wrotd(&k);
        a=_mm_addsub_pd(a,w); b=_mm_addsub_pd(b,w); c=_mm_addsub_pd(c,w); d=_mm_addsub_pd(d,w); }
    return ib_sig128(_mm_castpd_si128(a))^ib_sig128(_mm_castpd_si128(b))^
           ib_sig128(_mm_castpd_si128(c))^ib_sig128(_mm_castpd_si128(d)); }
/* ---- SSSE3(target="ssse3") ---- */
__attribute__((target("ssse3"))) static uint64_t k_lddqu(ib_uw iters){ __m128i s=_mm_setzero_si128(); int k=0;
    ib_uw i; for(i=0;i<iters;i++) s=_mm_lddqu_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]);
    return ib_sig128(s); }
__attribute__((target("ssse3"))) static uint64_t k_lddqu_tp(ib_uw iters){ __m128i s0=_mm_setzero_si128(),
    s1=_mm_setzero_si128(),s2=_mm_setzero_si128(),s3=_mm_setzero_si128(); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ s0=_mm_lddqu_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]);
        s1=_mm_lddqu_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]); s2=_mm_lddqu_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]);
        s3=_mm_lddqu_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]); }
    return ib_sig128(s0)^ib_sig128(s1)^ib_sig128(s2)^ib_sig128(s3); }
__attribute__((target("ssse3"))) static uint64_t k_pshufb(ib_uw iters){ __m128i a=_mm_set1_epi64x(0x0102030405060708ULL);
    int k=0; ib_uw i;
    for(i=0;i<iters;i++) a=_mm_shuffle_epi8(a,wrot(&k));
    return ib_sig128(a); }
__attribute__((target("ssse3"))) static uint64_t k_pshufb_tp(ib_uw iters){ __m128i a=_mm_set1_epi64x(0x0102030405060708ULL),
    b=_mm_set1_epi64x(0x1112131415161718ULL),c=_mm_set1_epi64x(0x2122232425262728ULL),
    d=_mm_set1_epi64x(0x3132333435363738ULL); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_shuffle_epi8(a,w); b=_mm_shuffle_epi8(b,w); c=_mm_shuffle_epi8(c,w); d=_mm_shuffle_epi8(d,w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
__attribute__((target("ssse3"))) static uint64_t k_pmaddubsw(ib_uw iters){ __m128i a=_mm_set1_epi16(0x0201); int k=0;
    ib_uw i;
    for(i=0;i<iters;i++) a=_mm_maddubs_epi16(a,wrot(&k));
    return ib_sig128(a); }
__attribute__((target("ssse3"))) static uint64_t k_pmaddubsw_tp(ib_uw iters){ __m128i a=_mm_set1_epi16(0x0201),
    b=_mm_set1_epi16(0x0403),c=_mm_set1_epi16(0x0605),d=_mm_set1_epi16(0x0807); int k=0;
    ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_maddubs_epi16(a,w); b=_mm_maddubs_epi16(b,w); c=_mm_maddubs_epi16(c,w); d=_mm_maddubs_epi16(d,w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
__attribute__((target("ssse3"))) static uint64_t k_pmulhrsw(ib_uw iters){ __m128i a=_mm_set1_epi16(0x0102); int k=0;
    ib_uw i;
    for(i=0;i<iters;i++) a=_mm_mulhrs_epi16(a,wrot(&k));
    return ib_sig128(a); }
__attribute__((target("ssse3"))) static uint64_t k_pmulhrsw_tp(ib_uw iters){ __m128i a=_mm_set1_epi16(0x0102),
    b=_mm_set1_epi16(0x0304),c=_mm_set1_epi16(0x0506),d=_mm_set1_epi16(0x0708); int k=0;
    ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_mulhrs_epi16(a,w); b=_mm_mulhrs_epi16(b,w); c=_mm_mulhrs_epi16(c,w); d=_mm_mulhrs_epi16(d,w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
__attribute__((target("ssse3"))) static uint64_t k_pabsw(ib_uw iters){ __m128i a=_mm_set1_epi16(-7); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_abs_epi16(_mm_xor_si128(a,wrot(&k)));
    return ib_sig128(a); }
__attribute__((target("ssse3"))) static uint64_t k_pabsw_tp(ib_uw iters){ __m128i a=_mm_set1_epi16(-7),
    b=_mm_set1_epi16(-9),c=_mm_set1_epi16(-13),d=_mm_set1_epi16(-17); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_abs_epi16(_mm_xor_si128(a,w)); b=_mm_abs_epi16(_mm_xor_si128(b,w));
        c=_mm_abs_epi16(_mm_xor_si128(c,w)); d=_mm_abs_epi16(_mm_xor_si128(d,w)); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
__attribute__((target("ssse3"))) static uint64_t k_palignr(ib_uw iters){ __m128i a=_mm_set1_epi32(1); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_alignr_epi8(a,wrot(&k),5); return ib_sig128(a); }
__attribute__((target("ssse3"))) static uint64_t k_palignr_tp(ib_uw iters){ __m128i a=_mm_set1_epi32(1),
    b=_mm_set1_epi32(2),c=_mm_set1_epi32(3),d=_mm_set1_epi32(4); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_alignr_epi8(a,w,5); b=_mm_alignr_epi8(b,w,5); c=_mm_alignr_epi8(c,w,5); d=_mm_alignr_epi8(d,w,5); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
/* ---- SSE4.1(target="sse4.1") ---- */
__attribute__((target("sse4.1"))) static uint64_t k_pmulld(ib_uw iters){ __m128i a=_mm_set1_epi32(3); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_mullo_epi32(a,wrot(&k)); return ib_sig128(a); }
__attribute__((target("sse4.1"))) static uint64_t k_pmulld_tp(ib_uw iters){ __m128i a=_mm_set1_epi32(3),
    b=_mm_set1_epi32(5),c=_mm_set1_epi32(7),d=_mm_set1_epi32(9); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_mullo_epi32(a,w); b=_mm_mullo_epi32(b,w); c=_mm_mullo_epi32(c,w); d=_mm_mullo_epi32(d,w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
__attribute__((target("sse4.1"))) static uint64_t k_pmovsxwd(ib_uw iters){ __m128i a=_mm_set1_epi16(-3); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_cvtepi16_epi32(_mm_xor_si128(a,wrot(&k)));
    return ib_sig128(a); }
__attribute__((target("sse4.1"))) static uint64_t k_pmovsxwd_tp(ib_uw iters){ __m128i a=_mm_set1_epi16(-3),
    b=_mm_set1_epi16(3),c=_mm_set1_epi16(-300),d=_mm_set1_epi16(300); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_cvtepi16_epi32(_mm_xor_si128(a,w)); b=_mm_cvtepi16_epi32(_mm_xor_si128(b,w));
        c=_mm_cvtepi16_epi32(_mm_xor_si128(c,w)); d=_mm_cvtepi16_epi32(_mm_xor_si128(d,w)); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
__attribute__((target("sse4.1"))) static uint64_t k_pblendw(ib_uw iters){ __m128i a=_mm_set1_epi32(1); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_blend_epi16(a,wrot(&k),0x3c); return ib_sig128(a); }
__attribute__((target("sse4.1"))) static uint64_t k_pblendw_tp(ib_uw iters){ __m128i a=_mm_set1_epi32(1),
    b=_mm_set1_epi32(2),c=_mm_set1_epi32(3),d=_mm_set1_epi32(4); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_blend_epi16(a,w,0x3c); b=_mm_blend_epi16(b,w,0x3c); c=_mm_blend_epi16(c,w,0x3c); d=_mm_blend_epi16(d,w,0x3c); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
__attribute__((target("sse4.1"))) static uint64_t k_mpsadbw(ib_uw iters){ __m128i a=_mm_set1_epi16(0x0102); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_mpsadbw_epu8(a,wrot(&k),3); return ib_sig128(a); }
__attribute__((target("sse4.1"))) static uint64_t k_mpsadbw_tp(ib_uw iters){ __m128i a=_mm_set1_epi16(0x0102),
    b=_mm_set1_epi16(0x0304),c=_mm_set1_epi16(0x0506),d=_mm_set1_epi16(0x0708); int k=0;
    ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_mpsadbw_epu8(a,w,3); b=_mm_mpsadbw_epu8(b,w,3); c=_mm_mpsadbw_epu8(c,w,3); d=_mm_mpsadbw_epu8(d,w,3); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
__attribute__((target("sse4.1"))) static uint64_t k_phminposuw(ib_uw iters){ __m128i a=_mm_set1_epi16(0x0102); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_minpos_epu16(_mm_xor_si128(a,wrot(&k)));
    return ib_sig128(a); }
__attribute__((target("sse4.1"))) static uint64_t k_phminposuw_tp(ib_uw iters){ __m128i a=_mm_set1_epi16(0x0102),
    b=_mm_set1_epi16(0x0a02),c=_mm_set1_epi16(0x0a0b),d=_mm_set1_epi16(0xffff); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_minpos_epu16(_mm_xor_si128(a,w)); b=_mm_minpos_epu16(_mm_xor_si128(b,w));
        c=_mm_minpos_epu16(_mm_xor_si128(c,w)); d=_mm_minpos_epu16(_mm_xor_si128(d,w)); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
__attribute__((target("sse4.1"))) static uint64_t k_roundps(ib_uw iters){ __m128 a=_mm_set1_ps(1.5f); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_round_ps(_mm_castsi128_ps(_mm_xor_si128(_mm_castps_si128(a),wrot(&k))),0x00);
    return ib_sig128(_mm_castps_si128(a)); }
__attribute__((target("sse4.1"))) static uint64_t k_roundps_tp(ib_uw iters){ __m128 a=_mm_set1_ps(1.5f),
    b=_mm_set1_ps(2.5f),c=_mm_set1_ps(3.5f),d=_mm_set1_ps(4.5f); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_round_ps(_mm_castsi128_ps(_mm_xor_si128(_mm_castps_si128(a),w)),0x00);
        b=_mm_round_ps(_mm_castsi128_ps(_mm_xor_si128(_mm_castps_si128(b),w)),0x00);
        c=_mm_round_ps(_mm_castsi128_ps(_mm_xor_si128(_mm_castps_si128(c),w)),0x00);
        d=_mm_round_ps(_mm_castsi128_ps(_mm_xor_si128(_mm_castps_si128(d),w)),0x00); }
    return ib_sig128(_mm_castps_si128(a))^ib_sig128(_mm_castps_si128(b))^
           ib_sig128(_mm_castps_si128(c))^ib_sig128(_mm_castps_si128(d)); }
/* ---- SSE4.2(target="sse4.2") ---- */
__attribute__((target("sse4.2"))) static uint64_t k_pcmpeqq(ib_uw iters){ __m128i a=_mm_set1_epi64x(1); int k=0;
    ib_uw i; for(i=0;i<iters;i++) a=_mm_cmpeq_epi64(a,wrot(&k)); return ib_sig128(a); }
__attribute__((target("sse4.2"))) static uint64_t k_pcmpeqq_tp(ib_uw iters){ __m128i a=_mm_set1_epi64x(1),
    b=_mm_set1_epi64x(2),c=_mm_set1_epi64x(3),d=_mm_set1_epi64x(4); int k=0; ib_uw i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_cmpeq_epi64(a,w); b=_mm_cmpeq_epi64(b,w); c=_mm_cmpeq_epi64(c,w); d=_mm_cmpeq_epi64(d,w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }


/* ---------------- 用例表(名字首段=ISA 段, 见头注释; 访存族 bpop=16/8/4 折算 MB/s) ----
 * 顺序: 访存族/算术族各按 legacy 源排列, ISA 由名字前缀分辨(与输出顺序无关)。 */
/* ==================== KAT 探针(每词干一条) ====================
 * 口径: 输入由词干哈希重导: 甲=(i0,i1), 乙=(i1, rotl(i0,13)) —— 与 vec 的 VIN/VIN2
 * 同构, 但独立各写一遍(互不参照)。位/整数族直接用位形; 浮点族由哈希整数精确构造
 * 有限 double/float(fpd/fpf), 不拿哈希位形直当浮点(那可能撞成 NaN/Inf, 跨机尾数
 * 位形不必相同)。128 位结果 -> o0,o1; outf=0(SSE 族不改 EFLAGS)。
 * 访存族: 逐字填 i0,i1 后按宽度读回 -> 输出 == 输入(装错地址/宽度即 FAIL)。 */
#define SI0(sn, kk)  IB_KIN8(sn, kk, 0, uint64_t)
#define SI1(sn, kk)  IB_KIN8(sn, kk, 1, uint64_t)
#define SRB(x, n)    (((x) >> (n)) | ((x) << (64 - (n))))
#define SVIN(sn, kk)   _mm_set_epi64x((long long)SI1(sn, kk), (long long)SI0(sn, kk))
#define SVIN2(sn, kk)  _mm_set_epi64x((long long)SRB(SI0(sn, kk), 13), (long long)SI1(sn, kk))
#define SIN(sn, kk)    (g->i0 = SI0(sn, kk), g->i1 = SI1(sn, kk), g->inf = 0)
#define SOUT(r)  do { union { __m128i v_; uint64_t q[2]; } u_; u_.v_ = (r); \
                      g->o0 = u_.q[0]; g->o1 = u_.q[1]; g->outf = 0; } while (0)

static uint64_t g_smk[2] __attribute__((aligned(16)));   /* KAT 访存源 */

static double s_fpd(uint64_t u, int part)
{
    int32_t v = part ? (int32_t)(uint32_t)(u >> 32) : (int32_t)(uint32_t)u;
    return (double)v / (part ? 8.0 : 4.0);
}
static __m128d s_pd2(uint64_t u0, uint64_t u1)
{
    return _mm_set_pd(s_fpd(u1, 1), s_fpd(u0, 0));
}
static __m128 s_ps4(uint64_t u0, uint64_t u1)
{
    return _mm_set_ps((float)s_fpd(u1, 1), (float)s_fpd(u1, 0),
                      (float)s_fpd(u0, 1), (float)s_fpd(u0, 0));
}
#define SFL(sn, kk)  SI1(sn, kk), SRB(SI0(sn, kk), 13)   /* 乙的两字: 供 s_ps4(sn)/s_pd2(sn) 当两参展开 */

/* 二元整数/位运算; 一元; 访存 */
#define K_BIN(sn, TGT, EXPR)  __attribute__((target(TGT))) \
static void k_##sn##_kat(int kk, ib_kv *g) { \
    __m128i a = SVIN(#sn, kk), b = SVIN2(#sn, kk); SIN(#sn, kk); SOUT(EXPR); }
#define K_UN(sn, TGT, EXPR)   __attribute__((target(TGT))) \
static void k_##sn##_kat(int kk, ib_kv *g) { \
    __m128i a = SVIN(#sn, kk); SIN(#sn, kk); SOUT(EXPR); }
#define K_MOV(sn, TGT, EXPR)  __attribute__((target(TGT))) \
static void k_##sn##_kat(int kk, ib_kv *g) { \
    g_smk[0] = SI0(#sn, kk); g_smk[1] = SI1(#sn, kk); SIN(#sn, kk); SOUT(EXPR); }

/* ---- 访存族 ---- */
K_MOV(movups_ld, "sse2", _mm_loadu_si128((const __m128i *)g_smk))
K_MOV(movaps_ld, "sse2", _mm_load_si128((const __m128i *)g_smk))
K_MOV(movdqa,    "sse2", _mm_load_si128((const __m128i *)g_smk))
K_MOV(movdqu,    "sse2", _mm_loadu_si128((const __m128i *)g_smk))
K_MOV(movq,      "sse2", _mm_loadl_epi64((const __m128i *)g_smk))
K_MOV(movss,     "sse2", _mm_castps_si128(_mm_load_ss((const float *)g_smk)))
K_MOV(movsd,     "sse2", _mm_castpd_si128(_mm_load_sd((const double *)g_smk)))
K_MOV(lddqu,     "ssse3", _mm_lddqu_si128((const __m128i *)g_smk))
static void k_movaps_st_kat(int kk, ib_kv *g)
{
    __m128i a = SVIN("movaps_st", kk); SIN("movaps_st", kk);
    _mm_store_si128((__m128i *)g_smk, a);
    SOUT(_mm_load_si128((const __m128i *)g_smk));
}

/* ---- 位/整数 lane 族 ---- */
K_BIN(xorps,  "sse2", _mm_castps_si128(_mm_xor_ps(_mm_castsi128_ps(a), _mm_castsi128_ps(b))))
K_BIN(shufps, "sse2", _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(a), _mm_castsi128_ps(b), 0x4e)))
K_BIN(pcmpeqd,   "sse2",  _mm_cmpeq_epi32(a, b))
K_BIN(paddd,     "sse2",  _mm_add_epi32(a, b))
K_BIN(paddw,     "sse2",  _mm_add_epi16(a, b))
K_BIN(pmaddwd,   "sse2",  _mm_madd_epi16(a, b))
K_BIN(pcmpeqq,   "sse4.2", _mm_cmpeq_epi64(a, b))
K_BIN(pshufb,       "ssse3", _mm_shuffle_epi8(a, b))
K_BIN(pshufb_sem,   "ssse3", _mm_shuffle_epi8(a, b))
K_BIN(pmaddubsw,    "ssse3", _mm_maddubs_epi16(a, b))
K_BIN(pmaddubsw_sem,"ssse3", _mm_maddubs_epi16(a, b))
K_BIN(pmulhrsw,     "ssse3", _mm_mulhrs_epi16(a, b))
K_BIN(pmulhrsw_sem, "ssse3", _mm_mulhrs_epi16(a, b))
K_BIN(palignr,      "ssse3", _mm_alignr_epi8(a, b, 5))
K_BIN(phaddsw_sem,  "ssse3", _mm_hadds_epi16(a, b))
K_BIN(pmulld,   "sse4.1", _mm_mullo_epi32(a, b))
K_BIN(pblendw,  "sse4.1", _mm_blend_epi16(a, b, 0x3c))
K_BIN(mpsadbw,  "sse4.1", _mm_mpsadbw_epu8(a, b, 3))
K_UN(pabsw,      "ssse3",  _mm_abs_epi16(a))
K_UN(pabsb_sem,  "ssse3",  _mm_abs_epi8(a))
K_UN(pmovsxwd,   "sse4.1", _mm_cvtepi16_epi32(a))
K_UN(phminposuw, "sse4.1", _mm_minpos_epu16(a))

/* ---- 浮点族(有限值构造) ---- */
__attribute__((target("sse2"))) static void k_mulss_kat(int kk, ib_kv *g)
{ __m128 a = s_ps4(SI0("mulss", kk), SI1("mulss", kk)), b = s_ps4(SFL("mulss", kk));
  SIN("mulss", kk); SOUT(_mm_castps_si128(_mm_mul_ss(a, b))); }
__attribute__((target("sse2"))) static void k_addss_kat(int kk, ib_kv *g)
{ __m128 a = s_ps4(SI0("addss", kk), SI1("addss", kk)), b = s_ps4(SFL("addss", kk));
  SIN("addss", kk); SOUT(_mm_castps_si128(_mm_add_ss(a, b))); }
__attribute__((target("sse2"))) static void k_subss_kat(int kk, ib_kv *g)
{ __m128 a = s_ps4(SI0("subss", kk), SI1("subss", kk)), b = s_ps4(SFL("subss", kk));
  SIN("subss", kk); SOUT(_mm_castps_si128(_mm_sub_ss(a, b))); }
__attribute__((target("sse2"))) static void k_addpd_kat(int kk, ib_kv *g)
{ __m128d a = s_pd2(SI0("addpd", kk), SI1("addpd", kk)), b = s_pd2(SFL("addpd", kk));
  SIN("addpd", kk); SOUT(_mm_castpd_si128(_mm_add_pd(a, b))); }
__attribute__((target("sse2"))) static void k_mulpd_kat(int kk, ib_kv *g)
{ __m128d a = s_pd2(SI0("mulpd", kk), SI1("mulpd", kk)), b = s_pd2(SFL("mulpd", kk));
  SIN("mulpd", kk); SOUT(_mm_castpd_si128(_mm_mul_pd(a, b))); }
__attribute__((target("sse2"))) static void k_addsd_kat(int kk, ib_kv *g)
{ __m128d a = s_pd2(SI0("addsd", kk), SI1("addsd", kk)), b = s_pd2(SFL("addsd", kk));
  SIN("addsd", kk); SOUT(_mm_castpd_si128(_mm_add_sd(a, b))); }
__attribute__((target("sse2"))) static void k_divsd_kat(int kk, ib_kv *g)
{ __m128d a = s_pd2(SI0("divsd", kk), SI1("divsd", kk)), b = s_pd2(SFL("divsd", kk));
  SIN("divsd", kk); SOUT(_mm_castpd_si128(_mm_div_sd(a, b))); }
__attribute__((target("sse2"))) static void k_cvttpd2dq_kat(int kk, ib_kv *g)
{ __m128d a = s_pd2(SI0("cvttpd2dq", kk), SI1("cvttpd2dq", kk));
  SIN("cvttpd2dq", kk); SOUT(_mm_cvttpd_epi32(a)); }
__attribute__((target("sse3"))) static void k_haddpd_kat(int kk, ib_kv *g)
{ __m128d a = s_pd2(SI0("haddpd", kk), SI1("haddpd", kk)), b = s_pd2(SFL("haddpd", kk));
  SIN("haddpd", kk); SOUT(_mm_castpd_si128(_mm_hadd_pd(a, b))); }
__attribute__((target("sse3"))) static void k_addsubpd_kat(int kk, ib_kv *g)
{ __m128d a = s_pd2(SI0("addsubpd", kk), SI1("addsubpd", kk)), b = s_pd2(SFL("addsubpd", kk));
  SIN("addsubpd", kk); SOUT(_mm_castpd_si128(_mm_addsub_pd(a, b))); }
__attribute__((target("sse4.1"))) static void k_roundps_kat(int kk, ib_kv *g)
{ __m128 a = s_ps4(SI0("roundps", kk), SI1("roundps", kk));
  SIN("roundps", kk); SOUT(_mm_castps_si128(_mm_round_ps(a, 0x00))); }

static const ib_case g_cases[] = {
    { "sse_movups_ld", NULL, k_movups, k_movups_tp, 0, NULL, 16, NULL, 0,
      k_movups_ld_kat, IB_KAT_movups_ld, "movups_ld" },
    { "sse_movaps_ld", NULL, k_movaps, k_movaps_tp, 0, NULL, 16, NULL, 0,
      k_movaps_ld_kat, IB_KAT_movaps_ld, "movaps_ld" },
    { "sse_movaps_st", NULL, k_movaps_st, k_movaps_st_tp, 0, NULL, 16, NULL, 0,
      k_movaps_st_kat, IB_KAT_movaps_st, "movaps_st" },
    { "sse_movss", NULL, k_movss, k_movss_tp, 0, NULL, 4, NULL, 0,
      k_movss_kat, IB_KAT_movss, "movss" },
    { "sse2_movsd", NULL, k_movsd, k_movsd_tp, 0, NULL, 8, NULL, 0,
      k_movsd_kat, IB_KAT_movsd, "movsd" },
    { "sse2_movdqa", NULL, k_movdqa, k_movdqa_tp, 0, NULL, 16, NULL, 0,
      k_movdqa_kat, IB_KAT_movdqa, "movdqa" },
    { "sse2_movdqu", NULL, k_movdqu, k_movdqu_tp, 0, NULL, 16, NULL, 0,
      k_movdqu_kat, IB_KAT_movdqu, "movdqu" },
    { "sse2_movq", NULL, k_movq, k_movq_tp, 0, NULL, 8, NULL, 0,
      k_movq_kat, IB_KAT_movq, "movq" },
    { "sse_mulss", NULL, k_mulss, k_mulss_tp, 0, NULL, 0, NULL, 0,
      k_mulss_kat, IB_KAT_mulss, "mulss" },
    { "sse_addss", NULL, k_addss, k_addss_tp, 0, NULL, 0, NULL, 0,
      k_addss_kat, IB_KAT_addss, "addss" },
    { "sse_subss", NULL, k_subss, k_subss_tp, 0, NULL, 0, NULL, 0,
      k_subss_kat, IB_KAT_subss, "subss" },
    { "sse_shufps", NULL, k_shufps, k_shufps_tp, 0, NULL, 0, NULL, 0,
      k_shufps_kat, IB_KAT_shufps, "shufps" },
    { "sse_xorps", NULL, k_xorps, k_xorps_tp, 0, NULL, 0, NULL, 0,
      k_xorps_kat, IB_KAT_xorps, "xorps" },
    { "sse2_pcmpeqd", NULL, k_pcmpeqd, k_pcmpeqd_tp, 0, NULL, 0, NULL, 0,
      k_pcmpeqd_kat, IB_KAT_pcmpeqd, "pcmpeqd" },
    { "sse2_paddd", NULL, k_paddd, k_paddd_tp, 0, NULL, 0, k_paddd_b8, 0,
      k_paddd_kat, IB_KAT_paddd, "paddd" },
    { "sse2_paddw", NULL, k_paddw, k_paddw_tp, 0, NULL, 0, NULL, 0,
      k_paddw_kat, IB_KAT_paddw, "paddw" },
    { "sse2_pmaddwd", NULL, k_pmaddwd, k_pmaddwd_tp, 0, NULL, 0, NULL, 0,
      k_pmaddwd_kat, IB_KAT_pmaddwd, "pmaddwd" },
    { "sse2_addpd", NULL, k_addpd, k_addpd_tp, 0, NULL, 0, NULL, 0,
      k_addpd_kat, IB_KAT_addpd, "addpd" },
    { "sse2_mulpd", NULL, k_mulpd, k_mulpd_tp, 0, NULL, 0, NULL, 0,
      k_mulpd_kat, IB_KAT_mulpd, "mulpd" },
    { "sse2_addsd", NULL, k_addsd, k_addsd_tp, 0, NULL, 0, NULL, 0,
      k_addsd_kat, IB_KAT_addsd, "addsd" },
    { "sse2_divsd", NULL, k_divsd, k_divsd_tp, 0, NULL, 0, NULL, 0,
      k_divsd_kat, IB_KAT_divsd, "divsd" },
    { "sse2_cvttpd2dq", NULL, k_cvttpd2dq, k_cvttpd2dq_tp, 0, NULL, 0, NULL, 0,
      k_cvttpd2dq_kat, IB_KAT_cvttpd2dq, "cvttpd2dq" },
    { "sse3_haddpd", "sse3", k_haddpd, k_haddpd_tp, 0, NULL, 0, NULL, 0,
      k_haddpd_kat, IB_KAT_haddpd, "haddpd" },
    { "sse3_addsubpd", "sse3", k_addsubpd, k_addsubpd_tp, 0, NULL, 0, NULL, 0,
      k_addsubpd_kat, IB_KAT_addsubpd, "addsubpd" },
    { "ssse3_lddqu", "ssse3", k_lddqu, k_lddqu_tp, 0, NULL, 16, NULL, 0,
      k_lddqu_kat, IB_KAT_lddqu, "lddqu" },
    { "ssse3_pshufb", "ssse3", k_pshufb, k_pshufb_tp, 0, NULL, 0, NULL, 0,
      k_pshufb_kat, IB_KAT_pshufb, "pshufb" },
    { "ssse3_pmaddubsw", "ssse3", k_pmaddubsw, k_pmaddubsw_tp, 0, NULL, 0, NULL, 0,
      k_pmaddubsw_kat, IB_KAT_pmaddubsw, "pmaddubsw" },
    { "ssse3_pmulhrsw", "ssse3", k_pmulhrsw, k_pmulhrsw_tp, 0, NULL, 0, NULL, 0,
      k_pmulhrsw_kat, IB_KAT_pmulhrsw, "pmulhrsw" },
    { "ssse3_pabsw", "ssse3", k_pabsw, k_pabsw_tp, 0, NULL, 0, NULL, 0,
      k_pabsw_kat, IB_KAT_pabsw, "pabsw" },
    { "ssse3_palignr", "ssse3", k_palignr, k_palignr_tp, 0, NULL, 0, NULL, 0,
      k_palignr_kat, IB_KAT_palignr, "palignr" },
    { "sse41_pmulld", "sse4.1", k_pmulld, k_pmulld_tp, 0, NULL, 0, NULL, 0,
      k_pmulld_kat, IB_KAT_pmulld, "pmulld" },
    { "sse41_pmovsxwd", "sse4.1", k_pmovsxwd, k_pmovsxwd_tp, 0, NULL, 0, NULL, 0,
      k_pmovsxwd_kat, IB_KAT_pmovsxwd, "pmovsxwd" },
    { "sse41_pblendw", "sse4.1", k_pblendw, k_pblendw_tp, 0, NULL, 0, NULL, 0,
      k_pblendw_kat, IB_KAT_pblendw, "pblendw" },
    { "sse41_mpsadbw", "sse4.1", k_mpsadbw, k_mpsadbw_tp, 0, NULL, 0, NULL, 0,
      k_mpsadbw_kat, IB_KAT_mpsadbw, "mpsadbw" },
    { "sse41_phminposuw", "sse4.1", k_phminposuw, k_phminposuw_tp, 0, NULL, 0, NULL, 0,
      k_phminposuw_kat, IB_KAT_phminposuw, "phminposuw" },
    { "sse41_roundps", "sse4.1", k_roundps, k_roundps_tp, 0, NULL, 0, NULL, 0,
      k_roundps_kat, IB_KAT_roundps, "roundps" },
    { "sse42_pcmpeqq", "sse4.2", k_pcmpeqq, k_pcmpeqq_tp, 0, NULL, 0, NULL, 0,
      k_pcmpeqq_kat, IB_KAT_pcmpeqq, "pcmpeqq" },
    { "ssse3_pshufb_sem", "ssse3", 0, 0, 0, NULL, 0, NULL, 0,
      k_pshufb_sem_kat, IB_KAT_pshufb_sem, "pshufb_sem" },
    { "ssse3_pmaddubsw_sem", "ssse3", 0, 0, 0, NULL, 0, NULL, 0,
      k_pmaddubsw_sem_kat, IB_KAT_pmaddubsw_sem, "pmaddubsw_sem" },
    { "ssse3_pmulhrsw_sem", "ssse3", 0, 0, 0, NULL, 0, NULL, 0,
      k_pmulhrsw_sem_kat, IB_KAT_pmulhrsw_sem, "pmulhrsw_sem" },
    { "ssse3_pabsb_sem", "ssse3", 0, 0, 0, NULL, 0, NULL, 0,
      k_pabsb_sem_kat, IB_KAT_pabsb_sem, "pabsb_sem" },
    { "ssse3_phaddsw_sem", "ssse3", 0, 0, 0, NULL, 0, NULL, 0,
      k_phaddsw_sem_kat, IB_KAT_phaddsw_sem, "phaddsw_sem" },
};
#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

int main(int argc, char **argv)
{
    int i;
    volatile float *vf = g_fbuf;      /* volatile 写: 内容对编译器不可知, 防 load 被 0 传播/常数化 */
    volatile double *vd = g_dbuf;
    volatile int32_t *vi = g_ibuf;
    volatile uint64_t *vo = g_obuf;
    for (i = 0; i < 64; i++) { vf[i] = 1.0f + (float)i; vi[i] = i * 3 + 1; }
    for (i = 0; i < 32; i++) { union { double d; uint64_t u; } cv; cv.d = 1.5 * i + 1.5;
        vd[i] = cv.d; vo[i] = cv.u; }
    /* asm "+m": 声明四个缓冲被外部读改写 -> 破坏 GCC 的「无写者->内容恒 0/可代数化简」
     * 推理(否则 movss/paddd 等 load 循环被折叠成 O(1), tput 虚报 1e12 ops/s) */
    __asm__ volatile("" : "+m"(g_fbuf[0]), "+m"(g_ibuf[0]), "+m"(g_dbuf[0]), "+m"(g_obuf[0])
                     : : "memory");
    ib_init(argc, argv);
    ib_hdr("sse", NCASES);
    ib_run_cases("sse", g_cases, NCASES);
    return 0;
}

