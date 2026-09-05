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
#include "ib.h"

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
static uint64_t k_movdqa(unsigned long long iters){ __m128i s=_mm_setzero_si128(); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) s=_mm_load_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]);
    return ib_sig128(s); }
static uint64_t k_movdqa_tp(unsigned long long iters){ __m128i s0=_mm_setzero_si128(),s1=_mm_setzero_si128(),
    s2=_mm_setzero_si128(),s3=_mm_setzero_si128(); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ s0=_mm_load_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]);
        s1=_mm_load_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]); s2=_mm_load_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]);
        s3=_mm_load_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]); }
    return ib_sig128(s0)^ib_sig128(s1)^ib_sig128(s2)^ib_sig128(s3); }
static uint64_t k_movdqu(unsigned long long iters){ __m128i s=_mm_setzero_si128(); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) s=_mm_loadu_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]);
    return ib_sig128(s); }
static uint64_t k_movdqu_tp(unsigned long long iters){ __m128i s0=_mm_setzero_si128(),s1=_mm_setzero_si128(),
    s2=_mm_setzero_si128(),s3=_mm_setzero_si128(); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ s0=_mm_loadu_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]);
        s1=_mm_loadu_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]); s2=_mm_loadu_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]);
        s3=_mm_loadu_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]); }
    return ib_sig128(s0)^ib_sig128(s1)^ib_sig128(s2)^ib_sig128(s3); }

static uint64_t k_movups(unsigned long long iters){ __m128 s=_mm_setzero_ps(); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) s=_mm_loadu_ps(&g_fbuf[NEXTK(k,16)<<2]);
    return ib_sig128(_mm_castps_si128(s)); }
static uint64_t k_movups_tp(unsigned long long iters){ __m128 s0=_mm_setzero_ps(),s1=_mm_setzero_ps(),
    s2=_mm_setzero_ps(),s3=_mm_setzero_ps(); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ s0=_mm_loadu_ps(&g_fbuf[NEXTK(k,16)<<2]);
        s1=_mm_loadu_ps(&g_fbuf[NEXTK(k,16)<<2]); s2=_mm_loadu_ps(&g_fbuf[NEXTK(k,16)<<2]);
        s3=_mm_loadu_ps(&g_fbuf[NEXTK(k,16)<<2]); }
    return ib_sig128(_mm_castps_si128(s0))^ib_sig128(_mm_castps_si128(s1))^
           ib_sig128(_mm_castps_si128(s2))^ib_sig128(_mm_castps_si128(s3)); }
static uint64_t k_movaps(unsigned long long iters){ __m128 s=_mm_setzero_ps(); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) s=_mm_load_ps(&g_fbuf[NEXTK(k,16)<<2]);
    return ib_sig128(_mm_castps_si128(s)); }
static uint64_t k_movaps_tp(unsigned long long iters){ __m128 s0=_mm_setzero_ps(),s1=_mm_setzero_ps(),
    s2=_mm_setzero_ps(),s3=_mm_setzero_ps(); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ s0=_mm_load_ps(&g_fbuf[NEXTK(k,16)<<2]);
        s1=_mm_load_ps(&g_fbuf[NEXTK(k,16)<<2]); s2=_mm_load_ps(&g_fbuf[NEXTK(k,16)<<2]);
        s3=_mm_load_ps(&g_fbuf[NEXTK(k,16)<<2]); }
    return ib_sig128(_mm_castps_si128(s0))^ib_sig128(_mm_castps_si128(s1))^
           ib_sig128(_mm_castps_si128(s2))^ib_sig128(_mm_castps_si128(s3)); }
static uint64_t k_movaps_st(unsigned long long iters){ __m128 v=_mm_set1_ps(1.5f); int k=0;
    unsigned long long i; for(i=0;i<iters;i++){ const float *p=&g_sbuf[(NEXTK(k,16)<<2)];
        __asm__ volatile("movaps %0,(%1)" :: "x"(v), "r"(p)); }
    return ib_sig128(_mm_castps_si128(v)); }
static uint64_t k_movaps_st_tp(unsigned long long iters){ __m128 v=_mm_set1_ps(1.5f); int k=0;
    unsigned long long i;
    for(i=0;i<iters;i++){ int j=NEXTK(k,16);
        const float *p0=&g_sbuf[j<<2], *p1=&g_sbuf[((j+1)&15)<<2],
            *p2=&g_sbuf[((j+4)&15)<<2], *p3=&g_sbuf[((j+8)&15)<<2];
        __asm__ volatile("movaps %0,(%1)" :: "x"(v), "r"(p0));
        __asm__ volatile("movaps %0,(%1)" :: "x"(v), "r"(p1));
        __asm__ volatile("movaps %0,(%1)" :: "x"(v), "r"(p2));
        __asm__ volatile("movaps %0,(%1)" :: "x"(v), "r"(p3)); }
    return ib_sig128(_mm_castps_si128(v)); }
static uint64_t k_movss(unsigned long long iters){ __m128 s=_mm_setzero_ps(); int k=0;
    unsigned long long i; for(i=0;i<iters;i++){ const float *p=&g_fbuf[NEXTK(k,63)];
        __asm__ volatile("movss (%1),%0" : "=x"(s) : "r"(p)); }
    return ib_sig128(_mm_castps_si128(s)); }
static uint64_t k_movss_tp(unsigned long long iters){ __m128 s0=_mm_setzero_ps(),s1=_mm_setzero_ps(),
    s2=_mm_setzero_ps(),s3=_mm_setzero_ps(); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ const float *p0=&g_fbuf[NEXTK(k,63)], *p1=&g_fbuf[NEXTK(k,63)],
        *p2=&g_fbuf[NEXTK(k,63)], *p3=&g_fbuf[NEXTK(k,63)];
        __asm__ volatile("movss (%1),%0" : "=x"(s0) : "r"(p0));
        __asm__ volatile("movss (%1),%0" : "=x"(s1) : "r"(p1));
        __asm__ volatile("movss (%1),%0" : "=x"(s2) : "r"(p2));
        __asm__ volatile("movss (%1),%0" : "=x"(s3) : "r"(p3)); }
    return ib_sig128(_mm_castps_si128(s0))^ib_sig128(_mm_castps_si128(s1))^
           ib_sig128(_mm_castps_si128(s2))^ib_sig128(_mm_castps_si128(s3)); }
static uint64_t k_movsd(unsigned long long iters){ __m128d s=_mm_setzero_pd(); int k=0;
    unsigned long long i; for(i=0;i<iters;i++){ const double *p=&g_dbuf[NEXTK(k,31)];
        __asm__ volatile("movsd (%1),%0" : "=x"(s) : "r"(p)); }
    return ib_sig128(_mm_castpd_si128(s)); }
static uint64_t k_movsd_tp(unsigned long long iters){ __m128d s0=_mm_setzero_pd(),s1=_mm_setzero_pd(),
    s2=_mm_setzero_pd(),s3=_mm_setzero_pd(); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ const double *p0=&g_dbuf[NEXTK(k,31)], *p1=&g_dbuf[NEXTK(k,31)],
        *p2=&g_dbuf[NEXTK(k,31)], *p3=&g_dbuf[NEXTK(k,31)];
        __asm__ volatile("movsd (%1),%0" : "=x"(s0) : "r"(p0));
        __asm__ volatile("movsd (%1),%0" : "=x"(s1) : "r"(p1));
        __asm__ volatile("movsd (%1),%0" : "=x"(s2) : "r"(p2));
        __asm__ volatile("movsd (%1),%0" : "=x"(s3) : "r"(p3)); }
    return ib_sig128(_mm_castpd_si128(s0))^ib_sig128(_mm_castpd_si128(s1))^
           ib_sig128(_mm_castpd_si128(s2))^ib_sig128(_mm_castpd_si128(s3)); }
static uint64_t k_movq(unsigned long long iters){ __m128i s=_mm_setzero_si128(); int k=0;
    unsigned long long i; for(i=0;i<iters;i++){ const uint64_t *p=&g_obuf[NEXTK(k,31)];
        __asm__ volatile("movq (%1),%0" : "=x"(s) : "r"(p)); }
    return ib_sig128(s); }
static uint64_t k_movq_tp(unsigned long long iters){ __m128i s0=_mm_setzero_si128(),s1=_mm_setzero_si128(),
    s2=_mm_setzero_si128(),s3=_mm_setzero_si128(); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ const uint64_t *p0=&g_obuf[NEXTK(k,31)], *p1=&g_obuf[NEXTK(k,31)],
        *p2=&g_obuf[NEXTK(k,31)], *p3=&g_obuf[NEXTK(k,31)];
        __asm__ volatile("movq (%1),%0" : "=x"(s0) : "r"(p0));
        __asm__ volatile("movq (%1),%0" : "=x"(s1) : "r"(p1));
        __asm__ volatile("movq (%1),%0" : "=x"(s2) : "r"(p2));
        __asm__ volatile("movq (%1),%0" : "=x"(s3) : "r"(p3)); }
    return ib_sig128(s0)^ib_sig128(s1)^ib_sig128(s2)^ib_sig128(s3); }

/* ============ 逐指令紧凑手写: lat(单依赖链) + tput(4 独立链), 种子与 legacy 对齐 ============ */
/* ---- SSE 浮点族(编码 0F, 非 VEX) ---- */
static uint64_t k_mulss(unsigned long long iters){ __m128 a=_mm_set_ss(1.0f); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_mul_ss(a,wrotf(&k)); return ib_sig128(_mm_castps_si128(a)); }
static uint64_t k_mulss_tp(unsigned long long iters){ __m128 a=_mm_set_ss(1.0f),b=_mm_set_ss(1.25f),
    c=_mm_set_ss(0.75f),d=_mm_set_ss(2.0f); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128 w=wrotf(&k);
        a=_mm_mul_ss(a,w); b=_mm_mul_ss(b,w); c=_mm_mul_ss(c,w); d=_mm_mul_ss(d,w); }
    return ib_sig128(_mm_castps_si128(a))^ib_sig128(_mm_castps_si128(b))^
           ib_sig128(_mm_castps_si128(c))^ib_sig128(_mm_castps_si128(d)); }
static uint64_t k_addss(unsigned long long iters){ __m128 a=_mm_set_ss(1.0f); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_add_ss(a,wrotf(&k)); return ib_sig128(_mm_castps_si128(a)); }
static uint64_t k_addss_tp(unsigned long long iters){ __m128 a=_mm_set_ss(1.0f),b=_mm_set_ss(1.25f),
    c=_mm_set_ss(0.75f),d=_mm_set_ss(2.0f); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128 w=wrotf(&k);
        a=_mm_add_ss(a,w); b=_mm_add_ss(b,w); c=_mm_add_ss(c,w); d=_mm_add_ss(d,w); }
    return ib_sig128(_mm_castps_si128(a))^ib_sig128(_mm_castps_si128(b))^
           ib_sig128(_mm_castps_si128(c))^ib_sig128(_mm_castps_si128(d)); }
static uint64_t k_subss(unsigned long long iters){ __m128 a=_mm_set_ss(1e6f); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_sub_ss(a,wrotf(&k)); return ib_sig128(_mm_castps_si128(a)); }
static uint64_t k_subss_tp(unsigned long long iters){ __m128 a=_mm_set_ss(1e6f),b=_mm_set_ss(1e7f),
    c=_mm_set_ss(1e8f),d=_mm_set_ss(1e9f); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128 w=wrotf(&k);
        a=_mm_sub_ss(a,w); b=_mm_sub_ss(b,w); c=_mm_sub_ss(c,w); d=_mm_sub_ss(d,w); }
    return ib_sig128(_mm_castps_si128(a))^ib_sig128(_mm_castps_si128(b))^
           ib_sig128(_mm_castps_si128(c))^ib_sig128(_mm_castps_si128(d)); }
static uint64_t k_shufps(unsigned long long iters){ __m128 a=_mm_set_ps(4,3,2,1); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_shuffle_ps(a,_mm_castsi128_ps(wrot(&k)),0x4e);
    return ib_sig128(_mm_castps_si128(a)); }
static uint64_t k_shufps_tp(unsigned long long iters){ __m128 a=_mm_set_ps(4,3,2,1),b=_mm_set_ps(1,2,3,4),
    c=_mm_set_ps(5,6,7,8),d=_mm_set_ps(9,10,11,12); int k=0; unsigned long long i;
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
static uint64_t k_paddd_b8(unsigned long long iters){
#ifdef __x86_64__
    __m128i a0=_mm_set1_epi32(0x9e3779b9),a1=_mm_set1_epi32(0x85ebca6b),a2=_mm_set1_epi32(0xc2b2ae35),a3=_mm_set1_epi32(0x27d4eb2f),
            a4=_mm_set1_epi32(0x165667b1),a5=_mm_set1_epi32(0xd5a9d4c5),a6=_mm_set1_epi32(0xbe9e7c55),a7=_mm_set1_epi32(0x53e5a0c2);
    int k0=0,k1=2,k2=4,k3=6,k4=8,k5=10,k6=12,k7=14; unsigned long long i;
    for(i=0;i<iters;i++){
        a0=_mm_add_epi32(a0,wrot(&k0)); a1=_mm_add_epi32(a1,wrot(&k1));
        a2=_mm_add_epi32(a2,wrot(&k2)); a3=_mm_add_epi32(a3,wrot(&k3));
        a4=_mm_add_epi32(a4,wrot(&k4)); a5=_mm_add_epi32(a5,wrot(&k5));
        a6=_mm_add_epi32(a6,wrot(&k6)); a7=_mm_add_epi32(a7,wrot(&k7)); }
    return ib_sig128(a0)^ib_sig128(a1)^ib_sig128(a2)^ib_sig128(a3)^
           ib_sig128(a4)^ib_sig128(a5)^ib_sig128(a6)^ib_sig128(a7);
#else
    __m128i a=_mm_set1_epi32(0x9e3779b9),b=_mm_set1_epi32(0x85ebca6b),c=_mm_set1_epi32(0xc2b2ae35),d=_mm_set1_epi32(0x27d4eb2f);
    int k0=0,k1=2,k2=4,k3=6,k4=8,k5=10,k6=12,k7=14; unsigned long long i;
    for(i=0;i<iters;i++){          /* 4 链 x 每轮 2 相位, 块内仍 8 条连续 paddd */
        a=_mm_add_epi32(a,wrot(&k0)); b=_mm_add_epi32(b,wrot(&k1));
        c=_mm_add_epi32(c,wrot(&k2)); d=_mm_add_epi32(d,wrot(&k3));
        a=_mm_add_epi32(a,wrot(&k4)); b=_mm_add_epi32(b,wrot(&k5));
        c=_mm_add_epi32(c,wrot(&k6)); d=_mm_add_epi32(d,wrot(&k7)); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d);
#endif
}
static uint64_t k_xorps(unsigned long long iters){ __m128 a=_mm_set1_ps(1.0f); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_xor_ps(a,_mm_castsi128_ps(wrot(&k)));
    return ib_sig128(_mm_castps_si128(a)); }
static uint64_t k_xorps_tp(unsigned long long iters){ __m128 a=_mm_set1_ps(1.0f),b=_mm_set1_ps(1.25f),
    c=_mm_set1_ps(2.5f),d=_mm_set1_ps(3.75f); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128 w=_mm_castsi128_ps(wrot(&k));
        a=_mm_xor_ps(a,w); b=_mm_xor_ps(b,w); c=_mm_xor_ps(c,w); d=_mm_xor_ps(d,w); }
    return ib_sig128(_mm_castps_si128(a))^ib_sig128(_mm_castps_si128(b))^
           ib_sig128(_mm_castps_si128(c))^ib_sig128(_mm_castps_si128(d)); }
static uint64_t k_pcmpeqd(unsigned long long iters){ __m128i a=_mm_set1_epi32(1); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_or_si128(a,_mm_cmpeq_epi32(a,wrot(&k)));
    return ib_sig128(a); }
static uint64_t k_pcmpeqd_tp(unsigned long long iters){ __m128i a=_mm_set1_epi32(1),b=_mm_set1_epi32(2),
    c=_mm_set1_epi32(3),d=_mm_set1_epi32(4); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_or_si128(a,_mm_cmpeq_epi32(a,w)); b=_mm_or_si128(b,_mm_cmpeq_epi32(b,w));
        c=_mm_or_si128(c,_mm_cmpeq_epi32(c,w)); d=_mm_or_si128(d,_mm_cmpeq_epi32(d,w)); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_paddd(unsigned long long iters){ __m128i a=_mm_set1_epi32(0x5a5a5a5a); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_add_epi32(a,wrot(&k)); return ib_sig128(a); }
static uint64_t k_paddd_tp(unsigned long long iters){ __m128i a=_mm_set1_epi32(1),b=_mm_set1_epi32(2),
    c=_mm_set1_epi32(3),d=_mm_set1_epi32(4); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_add_epi32(a,w); b=_mm_add_epi32(b,w); c=_mm_add_epi32(c,w); d=_mm_add_epi32(d,w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_paddw(unsigned long long iters){ __m128i a=_mm_set1_epi16(0x0102); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_add_epi16(a,wrot(&k)); return ib_sig128(a); }
static uint64_t k_paddw_tp(unsigned long long iters){ __m128i a=_mm_set1_epi16(1),b=_mm_set1_epi16(2),
    c=_mm_set1_epi16(3),d=_mm_set1_epi16(4); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_add_epi16(a,w); b=_mm_add_epi16(b,w); c=_mm_add_epi16(c,w); d=_mm_add_epi16(d,w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_pmaddwd(unsigned long long iters){ __m128i a=_mm_set1_epi16(3); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_madd_epi16(a,wrot(&k)); return ib_sig128(a); }
static uint64_t k_pmaddwd_tp(unsigned long long iters){ __m128i a=_mm_set1_epi16(3),b=_mm_set1_epi16(5),
    c=_mm_set1_epi16(7),d=_mm_set1_epi16(9); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_madd_epi16(a,w); b=_mm_madd_epi16(b,w); c=_mm_madd_epi16(c,w); d=_mm_madd_epi16(d,w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
static uint64_t k_addpd(unsigned long long iters){ __m128d a=_mm_set1_pd(1.0); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_add_pd(a,wrotd(&k)); return ib_sig128(_mm_castpd_si128(a)); }
static uint64_t k_addpd_tp(unsigned long long iters){ __m128d a=_mm_set1_pd(1.0),b=_mm_set1_pd(1.5),
    c=_mm_set1_pd(2.5),d=_mm_set1_pd(3.5); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128d w=wrotd(&k);
        a=_mm_add_pd(a,w); b=_mm_add_pd(b,w); c=_mm_add_pd(c,w); d=_mm_add_pd(d,w); }
    return ib_sig128(_mm_castpd_si128(a))^ib_sig128(_mm_castpd_si128(b))^
           ib_sig128(_mm_castpd_si128(c))^ib_sig128(_mm_castpd_si128(d)); }
static uint64_t k_mulpd(unsigned long long iters){ __m128d a=_mm_set1_pd(1.0); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_mul_pd(a,wrotd(&k)); return ib_sig128(_mm_castpd_si128(a)); }
static uint64_t k_mulpd_tp(unsigned long long iters){ __m128d a=_mm_set1_pd(1.0),b=_mm_set1_pd(1.5),
    c=_mm_set1_pd(2.5),d=_mm_set1_pd(3.5); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128d w=wrotd(&k);
        a=_mm_mul_pd(a,w); b=_mm_mul_pd(b,w); c=_mm_mul_pd(c,w); d=_mm_mul_pd(d,w); }
    return ib_sig128(_mm_castpd_si128(a))^ib_sig128(_mm_castpd_si128(b))^
           ib_sig128(_mm_castpd_si128(c))^ib_sig128(_mm_castpd_si128(d)); }
static uint64_t k_addsd(unsigned long long iters){ __m128d a=_mm_setzero_pd(); int k=0;
    unsigned long long i; for(i=0;i<iters;i++){ const double *p=(const double*)&g_obuf[NEXTK(k,16)<<1];
        __asm__ volatile("addsd (%1),%0" : "+x"(a) : "r"(p)); }
    return ib_sig128(_mm_castpd_si128(a)); }
static uint64_t k_addsd_tp(unsigned long long iters){ __m128d a=_mm_setzero_pd(),b=_mm_setzero_pd(),
    c=_mm_setzero_pd(),d=_mm_setzero_pd(); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ const double *p=(const double*)&g_obuf[NEXTK(k,16)<<1];
        __asm__ volatile("addsd (%1),%0" : "+x"(a) : "r"(p));
        __asm__ volatile("addsd (%1),%0" : "+x"(b) : "r"(p));
        __asm__ volatile("addsd (%1),%0" : "+x"(c) : "r"(p));
        __asm__ volatile("addsd (%1),%0" : "+x"(d) : "r"(p)); }
    return ib_sig128(_mm_castpd_si128(a))^ib_sig128(_mm_castpd_si128(b))^
           ib_sig128(_mm_castpd_si128(c))^ib_sig128(_mm_castpd_si128(d)); }
static uint64_t k_divsd(unsigned long long iters){ __m128d a=_mm_set_sd(1e9); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_div_sd(a,wrotd(&k)); return ib_sig128(_mm_castpd_si128(a)); }
static uint64_t k_divsd_tp(unsigned long long iters){ __m128d a=_mm_set_sd(1e9),b=_mm_set_sd(1e8),
    c=_mm_set_sd(1e7),d=_mm_set_sd(1e6); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128d w=wrotd(&k);
        a=_mm_div_sd(a,w); b=_mm_div_sd(b,w); c=_mm_div_sd(c,w); d=_mm_div_sd(d,w); }
    return ib_sig128(_mm_castpd_si128(a))^ib_sig128(_mm_castpd_si128(b))^
           ib_sig128(_mm_castpd_si128(c))^ib_sig128(_mm_castpd_si128(d)); }
static uint64_t k_cvttpd2dq(unsigned long long iters){ __m128d d=_mm_set_pd(3.5,1.25); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) d=_mm_add_pd(d,wrotd(&k)); return ib_sig128(_mm_cvttpd_epi32(d)); }
static uint64_t k_cvttpd2dq_tp(unsigned long long iters){ __m128d a=_mm_set_pd(3.5,1.25),b=_mm_set_pd(4.5,2.25),
    c=_mm_set_pd(5.5,3.25),d=_mm_set_pd(6.5,4.25); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128d w=wrotd(&k);
        a=_mm_add_pd(a,w); b=_mm_add_pd(b,w); c=_mm_add_pd(c,w); d=_mm_add_pd(d,w); }
    return ib_sig128(_mm_cvttpd_epi32(a))^ib_sig128(_mm_cvttpd_epi32(b))^
           ib_sig128(_mm_cvttpd_epi32(c))^ib_sig128(_mm_cvttpd_epi32(d)); }
/* ---- SSE3(target="sse3") ---- */
__attribute__((target("sse3"))) static uint64_t k_haddpd(unsigned long long iters){ __m128d a=_mm_set_pd(1,2); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_hadd_pd(a,wrotd(&k)); return ib_sig128(_mm_castpd_si128(a)); }
__attribute__((target("sse3"))) static uint64_t k_haddpd_tp(unsigned long long iters){ __m128d a=_mm_set_pd(1,2),b=_mm_set_pd(1.5,2.5),
    c=_mm_set_pd(3,4),d=_mm_set_pd(3.5,4.5); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128d w=wrotd(&k);
        a=_mm_hadd_pd(a,w); b=_mm_hadd_pd(b,w); c=_mm_hadd_pd(c,w); d=_mm_hadd_pd(d,w); }
    return ib_sig128(_mm_castpd_si128(a))^ib_sig128(_mm_castpd_si128(b))^
           ib_sig128(_mm_castpd_si128(c))^ib_sig128(_mm_castpd_si128(d)); }
__attribute__((target("sse3"))) static uint64_t k_addsubpd(unsigned long long iters){ __m128d a=_mm_set1_pd(1.0); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_addsub_pd(a,wrotd(&k)); return ib_sig128(_mm_castpd_si128(a)); }
__attribute__((target("sse3"))) static uint64_t k_addsubpd_tp(unsigned long long iters){ __m128d a=_mm_set1_pd(1.0),b=_mm_set1_pd(1.5),
    c=_mm_set1_pd(2.5),d=_mm_set1_pd(3.5); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128d w=wrotd(&k);
        a=_mm_addsub_pd(a,w); b=_mm_addsub_pd(b,w); c=_mm_addsub_pd(c,w); d=_mm_addsub_pd(d,w); }
    return ib_sig128(_mm_castpd_si128(a))^ib_sig128(_mm_castpd_si128(b))^
           ib_sig128(_mm_castpd_si128(c))^ib_sig128(_mm_castpd_si128(d)); }
/* ---- SSSE3(target="ssse3") ---- */
__attribute__((target("ssse3"))) static uint64_t k_lddqu(unsigned long long iters){ __m128i s=_mm_setzero_si128(); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) s=_mm_lddqu_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]);
    return ib_sig128(s); }
__attribute__((target("ssse3"))) static uint64_t k_lddqu_tp(unsigned long long iters){ __m128i s0=_mm_setzero_si128(),
    s1=_mm_setzero_si128(),s2=_mm_setzero_si128(),s3=_mm_setzero_si128(); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ s0=_mm_lddqu_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]);
        s1=_mm_lddqu_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]); s2=_mm_lddqu_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]);
        s3=_mm_lddqu_si128((__m128i*)&g_ibuf[NEXTK(k,16)<<2]); }
    return ib_sig128(s0)^ib_sig128(s1)^ib_sig128(s2)^ib_sig128(s3); }
__attribute__((target("ssse3"))) static uint64_t k_pshufb(unsigned long long iters){ __m128i a=_mm_set1_epi64x(0x0102030405060708ULL);
    int k=0; unsigned long long i;
    for(i=0;i<iters;i++) a=_mm_shuffle_epi8(a,wrot(&k)); return ib_sig128(a); }
__attribute__((target("ssse3"))) static uint64_t k_pshufb_tp(unsigned long long iters){ __m128i a=_mm_set1_epi64x(0x0102030405060708ULL),
    b=_mm_set1_epi64x(0x1112131415161718ULL),c=_mm_set1_epi64x(0x2122232425262728ULL),
    d=_mm_set1_epi64x(0x3132333435363738ULL); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_shuffle_epi8(a,w); b=_mm_shuffle_epi8(b,w); c=_mm_shuffle_epi8(c,w); d=_mm_shuffle_epi8(d,w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
__attribute__((target("ssse3"))) static uint64_t k_pmaddubsw(unsigned long long iters){ __m128i a=_mm_set1_epi16(0x0201); int k=0;
    unsigned long long i;
    for(i=0;i<iters;i++) a=_mm_maddubs_epi16(a,wrot(&k)); return ib_sig128(a); }
__attribute__((target("ssse3"))) static uint64_t k_pmaddubsw_tp(unsigned long long iters){ __m128i a=_mm_set1_epi16(0x0201),
    b=_mm_set1_epi16(0x0403),c=_mm_set1_epi16(0x0605),d=_mm_set1_epi16(0x0807); int k=0;
    unsigned long long i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_maddubs_epi16(a,w); b=_mm_maddubs_epi16(b,w); c=_mm_maddubs_epi16(c,w); d=_mm_maddubs_epi16(d,w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
__attribute__((target("ssse3"))) static uint64_t k_pmulhrsw(unsigned long long iters){ __m128i a=_mm_set1_epi16(0x0102); int k=0;
    unsigned long long i;
    for(i=0;i<iters;i++) a=_mm_mulhrs_epi16(a,wrot(&k)); return ib_sig128(a); }
__attribute__((target("ssse3"))) static uint64_t k_pmulhrsw_tp(unsigned long long iters){ __m128i a=_mm_set1_epi16(0x0102),
    b=_mm_set1_epi16(0x0304),c=_mm_set1_epi16(0x0506),d=_mm_set1_epi16(0x0708); int k=0;
    unsigned long long i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_mulhrs_epi16(a,w); b=_mm_mulhrs_epi16(b,w); c=_mm_mulhrs_epi16(c,w); d=_mm_mulhrs_epi16(d,w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
__attribute__((target("ssse3"))) static uint64_t k_pabsw(unsigned long long iters){ __m128i a=_mm_set1_epi16(-7); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_abs_epi16(_mm_xor_si128(a,wrot(&k)));
    return ib_sig128(a); }
__attribute__((target("ssse3"))) static uint64_t k_pabsw_tp(unsigned long long iters){ __m128i a=_mm_set1_epi16(-7),
    b=_mm_set1_epi16(-9),c=_mm_set1_epi16(-13),d=_mm_set1_epi16(-17); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_abs_epi16(_mm_xor_si128(a,w)); b=_mm_abs_epi16(_mm_xor_si128(b,w));
        c=_mm_abs_epi16(_mm_xor_si128(c,w)); d=_mm_abs_epi16(_mm_xor_si128(d,w)); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
__attribute__((target("ssse3"))) static uint64_t k_palignr(unsigned long long iters){ __m128i a=_mm_set1_epi32(1); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_alignr_epi8(a,wrot(&k),5); return ib_sig128(a); }
__attribute__((target("ssse3"))) static uint64_t k_palignr_tp(unsigned long long iters){ __m128i a=_mm_set1_epi32(1),
    b=_mm_set1_epi32(2),c=_mm_set1_epi32(3),d=_mm_set1_epi32(4); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_alignr_epi8(a,w,5); b=_mm_alignr_epi8(b,w,5); c=_mm_alignr_epi8(c,w,5); d=_mm_alignr_epi8(d,w,5); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
/* ---- SSE4.1(target="sse4.1") ---- */
__attribute__((target("sse4.1"))) static uint64_t k_pmulld(unsigned long long iters){ __m128i a=_mm_set1_epi32(3); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_mullo_epi32(a,wrot(&k)); return ib_sig128(a); }
__attribute__((target("sse4.1"))) static uint64_t k_pmulld_tp(unsigned long long iters){ __m128i a=_mm_set1_epi32(3),
    b=_mm_set1_epi32(5),c=_mm_set1_epi32(7),d=_mm_set1_epi32(9); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_mullo_epi32(a,w); b=_mm_mullo_epi32(b,w); c=_mm_mullo_epi32(c,w); d=_mm_mullo_epi32(d,w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
__attribute__((target("sse4.1"))) static uint64_t k_pmovsxwd(unsigned long long iters){ __m128i a=_mm_set1_epi16(-3); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_cvtepi16_epi32(_mm_xor_si128(a,wrot(&k)));
    return ib_sig128(a); }
__attribute__((target("sse4.1"))) static uint64_t k_pmovsxwd_tp(unsigned long long iters){ __m128i a=_mm_set1_epi16(-3),
    b=_mm_set1_epi16(3),c=_mm_set1_epi16(-300),d=_mm_set1_epi16(300); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_cvtepi16_epi32(_mm_xor_si128(a,w)); b=_mm_cvtepi16_epi32(_mm_xor_si128(b,w));
        c=_mm_cvtepi16_epi32(_mm_xor_si128(c,w)); d=_mm_cvtepi16_epi32(_mm_xor_si128(d,w)); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
__attribute__((target("sse4.1"))) static uint64_t k_pblendw(unsigned long long iters){ __m128i a=_mm_set1_epi32(1); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_blend_epi16(a,wrot(&k),0x3c); return ib_sig128(a); }
__attribute__((target("sse4.1"))) static uint64_t k_pblendw_tp(unsigned long long iters){ __m128i a=_mm_set1_epi32(1),
    b=_mm_set1_epi32(2),c=_mm_set1_epi32(3),d=_mm_set1_epi32(4); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_blend_epi16(a,w,0x3c); b=_mm_blend_epi16(b,w,0x3c); c=_mm_blend_epi16(c,w,0x3c); d=_mm_blend_epi16(d,w,0x3c); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
__attribute__((target("sse4.1"))) static uint64_t k_mpsadbw(unsigned long long iters){ __m128i a=_mm_set1_epi16(0x0102); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_mpsadbw_epu8(a,wrot(&k),3); return ib_sig128(a); }
__attribute__((target("sse4.1"))) static uint64_t k_mpsadbw_tp(unsigned long long iters){ __m128i a=_mm_set1_epi16(0x0102),
    b=_mm_set1_epi16(0x0304),c=_mm_set1_epi16(0x0506),d=_mm_set1_epi16(0x0708); int k=0;
    unsigned long long i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_mpsadbw_epu8(a,w,3); b=_mm_mpsadbw_epu8(b,w,3); c=_mm_mpsadbw_epu8(c,w,3); d=_mm_mpsadbw_epu8(d,w,3); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
__attribute__((target("sse4.1"))) static uint64_t k_phminposuw(unsigned long long iters){ __m128i a=_mm_set1_epi16(0x0102); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_minpos_epu16(_mm_xor_si128(a,wrot(&k)));
    return ib_sig128(a); }
__attribute__((target("sse4.1"))) static uint64_t k_phminposuw_tp(unsigned long long iters){ __m128i a=_mm_set1_epi16(0x0102),
    b=_mm_set1_epi16(0x0a02),c=_mm_set1_epi16(0x0a0b),d=_mm_set1_epi16(0xffff); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_minpos_epu16(_mm_xor_si128(a,w)); b=_mm_minpos_epu16(_mm_xor_si128(b,w));
        c=_mm_minpos_epu16(_mm_xor_si128(c,w)); d=_mm_minpos_epu16(_mm_xor_si128(d,w)); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }
__attribute__((target("sse4.1"))) static uint64_t k_roundps(unsigned long long iters){ __m128 a=_mm_set1_ps(1.5f); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_round_ps(_mm_castsi128_ps(_mm_xor_si128(_mm_castps_si128(a),wrot(&k))),0x00);
    return ib_sig128(_mm_castps_si128(a)); }
__attribute__((target("sse4.1"))) static uint64_t k_roundps_tp(unsigned long long iters){ __m128 a=_mm_set1_ps(1.5f),
    b=_mm_set1_ps(2.5f),c=_mm_set1_ps(3.5f),d=_mm_set1_ps(4.5f); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_round_ps(_mm_castsi128_ps(_mm_xor_si128(_mm_castps_si128(a),w)),0x00);
        b=_mm_round_ps(_mm_castsi128_ps(_mm_xor_si128(_mm_castps_si128(b),w)),0x00);
        c=_mm_round_ps(_mm_castsi128_ps(_mm_xor_si128(_mm_castps_si128(c),w)),0x00);
        d=_mm_round_ps(_mm_castsi128_ps(_mm_xor_si128(_mm_castps_si128(d),w)),0x00); }
    return ib_sig128(_mm_castps_si128(a))^ib_sig128(_mm_castps_si128(b))^
           ib_sig128(_mm_castps_si128(c))^ib_sig128(_mm_castps_si128(d)); }
/* ---- SSE4.2(target="sse4.2") ---- */
__attribute__((target("sse4.2"))) static uint64_t k_pcmpeqq(unsigned long long iters){ __m128i a=_mm_set1_epi64x(1); int k=0;
    unsigned long long i; for(i=0;i<iters;i++) a=_mm_cmpeq_epi64(a,wrot(&k)); return ib_sig128(a); }
__attribute__((target("sse4.2"))) static uint64_t k_pcmpeqq_tp(unsigned long long iters){ __m128i a=_mm_set1_epi64x(1),
    b=_mm_set1_epi64x(2),c=_mm_set1_epi64x(3),d=_mm_set1_epi64x(4); int k=0; unsigned long long i;
    for(i=0;i<iters;i++){ __m128i w=wrot(&k);
        a=_mm_cmpeq_epi64(a,w); b=_mm_cmpeq_epi64(b,w); c=_mm_cmpeq_epi64(c,w); d=_mm_cmpeq_epi64(d,w); }
    return ib_sig128(a)^ib_sig128(b)^ib_sig128(c)^ib_sig128(d); }

/* ============ R4_SEM 语义对拍(不计时; rows 取自 insn_probe.c R4_SEM, 结果折 64 位签名) ============
 * 折叠: acc=(acc<<7)|(acc>>57); acc^=sig128(FN(a,k)) —— 与 legacy 同式, 逐位跨机可比。 */
__attribute__((target("ssse3"))) static uint64_t k_pshufb_sem(unsigned long long it)
{
    (void)it;
    static const unsigned long long rows[][4] = {
        {0x100f0e0d0c0b0a09ULL, 0x0807060504030201ULL, 0x0f0e0d0c0b0a0908ULL, 0x0706050403020100ULL},
        {0x0f0e0d0c0b0a0908ULL, 0xffefd0c0b0a09080ULL, 0x8f8e8d8c8b8a8988ULL, 0x8786858483828180ULL},
        {0x0001020304050607ULL, 0xf8e0d0c0b0a09080ULL, 0x403f2e0d7c1b9a18ULL, 0x0706850403820180ULL},
        {0x8081828384858687ULL, 0x88898a8b8c8d8e8fULL, 0x7f7f7f7f7f7f7f7fULL, 0x1f1f1f1f1f1f1f1fULL},
        {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0x0f0f0f0f0f0f0f0fULL, 0x0f0f0f0f0f0f0f0fULL},
        {0x55aa55aa55aa55aaULL, 0xaaaaaaaaaaaaaaaaULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL},
        {0x0000000000000000ULL, 0x0000000000000000ULL, 0x8080808080808080ULL, 0x8080808080808080ULL},
    };
    unsigned i, np = (unsigned)(sizeof(rows) / sizeof(rows[0]));
    uint64_t acc = 0;
    for (i = 0; i < np; i++) {
        __m128i a = _mm_set_epi64x((long long)rows[i][0], (long long)rows[i][1]);
        __m128i k = _mm_set_epi64x((long long)rows[i][2], (long long)rows[i][3]);
        acc = (acc << 7) | (acc >> 57); acc ^= ib_sig128(_mm_shuffle_epi8(a, k));
    }
    return acc;
}
__attribute__((target("ssse3"))) static uint64_t k_pmaddubsw_sem(unsigned long long it)
{
    (void)it;
    static const unsigned long long rows[][4] = {
        {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0x7f7f7f7f7f7f7f7fULL, 0x7f7f7f7f7f7f7f7fULL},
        {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0x8080808080808080ULL, 0x8080808080808080ULL},
        {0x8080808080808080ULL, 0x8080808080808080ULL, 0x8080808080808080ULL, 0x8080808080808080ULL},
        {0x0101010101010101ULL, 0x0101010101010101ULL, 0x7f7f7f7f7f7f7f7fULL, 0x7f7f7f7f7f7f7f7fULL},
        {0x8090a0b0c0d0e0ffULL, 0x01020304050607ffULL, 0x0102030405060780ULL, 0x81828384858687ffULL},
        {0x8080808080808080ULL, 0x8080808080808080ULL, 0x8181818181818181ULL, 0x8181818181818181ULL},
        {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL},
        {0x0000000000000000ULL, 0x0000000000000000ULL, 0x8080808080808080ULL, 0x8080808080808080ULL},
    };
    unsigned i, np = (unsigned)(sizeof(rows) / sizeof(rows[0]));
    uint64_t acc = 0;
    for (i = 0; i < np; i++) {
        __m128i a = _mm_set_epi64x((long long)rows[i][0], (long long)rows[i][1]);
        __m128i k = _mm_set_epi64x((long long)rows[i][2], (long long)rows[i][3]);
        acc = (acc << 7) | (acc >> 57); acc ^= ib_sig128(_mm_maddubs_epi16(a, k));
    }
    return acc;
}
__attribute__((target("ssse3"))) static uint64_t k_pmulhrsw_sem(unsigned long long it)
{
    (void)it;
    static const unsigned long long rows[][4] = {
        {0x8000800080008000ULL, 0x8000800080008000ULL, 0x8000800080008000ULL, 0x8000800080008000ULL},
        {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL},
        {0x4000400040004000ULL, 0x4000400040004000ULL, 0x4000400040004000ULL, 0x4000400040004000ULL},
        {0x7fff80000001ffffULL, 0x7fff800040000001ULL, 0xabcd4000ffff8000ULL, 0x000280004000ffffULL},
        {0x7fff7fff7fff7fffULL, 0x7fff7fff7fff7fffULL, 0x7fff7fff7fff7fffULL, 0x7fff7fff7fff7fffULL},
        {0x0001000100010001ULL, 0x0001000100010001ULL, 0x7fff7fff7fff7fffULL, 0x7fff7fff7fff7fffULL},
        {0x8000800080008000ULL, 0x8000800080008000ULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL},
    };
    unsigned i, np = (unsigned)(sizeof(rows) / sizeof(rows[0]));
    uint64_t acc = 0;
    for (i = 0; i < np; i++) {
        __m128i a = _mm_set_epi64x((long long)rows[i][0], (long long)rows[i][1]);
        __m128i k = _mm_set_epi64x((long long)rows[i][2], (long long)rows[i][3]);
        acc = (acc << 7) | (acc >> 57); acc ^= ib_sig128(_mm_mulhrs_epi16(a, k));
    }
    return acc;
}
__attribute__((target("ssse3"))) static uint64_t k_pabsb_sem(unsigned long long it)
{
    (void)it;
    static const unsigned long long rows[][4] = {
        {0x8080808080808080ULL, 0x8080808080808080ULL, 0ULL, 0ULL},
        {0x7f7f7f7f7f7f7f7fULL, 0x7f7f7f7f7f7f7f7fULL, 0ULL, 0ULL},
        {0xfffe01807f80feffULL, 0x010280ff7f80fe01ULL, 0ULL, 0ULL},
        {0x0000000000000000ULL, 0x0000000000000000ULL, 0ULL, 0ULL},
        {0x55aa55aa55aa55aaULL, 0xaaaaaaaaaaaaaaaaULL, 0ULL, 0ULL},
    };
    unsigned i, np = (unsigned)(sizeof(rows) / sizeof(rows[0]));
    uint64_t acc = 0;
    for (i = 0; i < np; i++) {
        __m128i a = _mm_set_epi64x((long long)rows[i][0], (long long)rows[i][1]);
        acc = (acc << 7) | (acc >> 57); acc ^= ib_sig128(_mm_abs_epi8(a));
    }
    return acc;
}
__attribute__((target("ssse3"))) static uint64_t k_phaddsw_sem(unsigned long long it)
{
    (void)it;
    static const unsigned long long rows[][4] = {
        {0x7fff7fff7fff7fffULL, 0x7fff7fff7fff7fffULL, 0x0001000100010001ULL, 0x0001000100010001ULL},
        {0x8000800080008000ULL, 0x8000800080008000ULL, 0xffff0001ffff0001ULL, 0xffff0001ffff0001ULL},
        {0x0102030405060708ULL, 0x090a0b0c0d0e0f10ULL, 0x4000c000ffff7fffULL, 0x0001ffff80000000ULL},
        {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0x8000800080008000ULL, 0x8000800080008000ULL},
    };
    unsigned i, np = (unsigned)(sizeof(rows) / sizeof(rows[0]));
    uint64_t acc = 0;
    for (i = 0; i < np; i++) {
        __m128i a = _mm_set_epi64x((long long)rows[i][0], (long long)rows[i][1]);
        __m128i k = _mm_set_epi64x((long long)rows[i][2], (long long)rows[i][3]);
        acc = (acc << 7) | (acc >> 57); acc ^= ib_sig128(_mm_hadds_epi16(a, k));
    }
    return acc;
}

/* ---------------- 用例表(名字首段=ISA 段, 见头注释; 访存族 bpop=16/8/4 折算 MB/s) ----
 * 顺序: 访存族/算术族各按 legacy 源排列, ISA 由名字前缀分辨(与输出顺序无关)。 */
static const ib_case g_cases[] = {
    { "sse_movups_ld",   NULL,     k_movups,        k_movups_tp,        0, NULL, 16 },
    { "sse_movaps_ld",   NULL,     k_movaps,        k_movaps_tp,        0, NULL, 16 },
    { "sse_movaps_st",   NULL,     k_movaps_st,     k_movaps_st_tp,     0, NULL, 16 },
    { "sse_movss",       NULL,     k_movss,         k_movss_tp,         0, NULL, 4  },
    { "sse2_movsd",      NULL,     k_movsd,         k_movsd_tp,         0, NULL, 8  },
    { "sse2_movdqa",     NULL,     k_movdqa,        k_movdqa_tp,        0, NULL, 16 },
    { "sse2_movdqu",     NULL,     k_movdqu,        k_movdqu_tp,        0, NULL, 16 },
    { "sse2_movq",       NULL,     k_movq,          k_movq_tp,          0, NULL, 8  },
    { "sse_mulss",       NULL,     k_mulss,         k_mulss_tp,         0, NULL, 0 },
    { "sse_addss",       NULL,     k_addss,         k_addss_tp,         0, NULL, 0 },
    { "sse_subss",       NULL,     k_subss,         k_subss_tp,         0, NULL, 0 },
    { "sse_shufps",      NULL,     k_shufps,        k_shufps_tp,        0, NULL, 0 },
    { "sse_xorps",       NULL,     k_xorps,         k_xorps_tp,         0, NULL, 0 },
    { "sse2_pcmpeqd",    NULL,     k_pcmpeqd,       k_pcmpeqd_tp,       0, NULL, 0 },
    { "sse2_paddd",      NULL,     k_paddd,         k_paddd_tp,         0, NULL, 0,
      k_paddd_b8 },
    { "sse2_paddw",      NULL,     k_paddw,         k_paddw_tp,         0, NULL, 0 },
    { "sse2_pmaddwd",    NULL,     k_pmaddwd,       k_pmaddwd_tp,       0, NULL, 0 },
    { "sse2_addpd",      NULL,     k_addpd,         k_addpd_tp,         0, NULL, 0 },
    { "sse2_mulpd",      NULL,     k_mulpd,         k_mulpd_tp,         0, NULL, 0 },
    { "sse2_addsd",      NULL,     k_addsd,         k_addsd_tp,         0, NULL, 0 },
    { "sse2_divsd",      NULL,     k_divsd,         k_divsd_tp,         0, NULL, 0 },
    { "sse2_cvttpd2dq",  NULL,     k_cvttpd2dq,     k_cvttpd2dq_tp,     0, NULL, 0 },
    { "sse3_haddpd",     "sse3",   k_haddpd,        k_haddpd_tp,        0, NULL, 0 },
    { "sse3_addsubpd",   "sse3",   k_addsubpd,      k_addsubpd_tp,      0, NULL, 0 },
    { "ssse3_lddqu",     "ssse3",  k_lddqu,         k_lddqu_tp,         0, NULL, 16 },
    { "ssse3_pshufb",    "ssse3",  k_pshufb,        k_pshufb_tp,        0, NULL, 0 },
    { "ssse3_pmaddubsw", "ssse3",  k_pmaddubsw,     k_pmaddubsw_tp,     0, NULL, 0 },
    { "ssse3_pmulhrsw",  "ssse3",  k_pmulhrsw,      k_pmulhrsw_tp,      0, NULL, 0 },
    { "ssse3_pabsw",     "ssse3",  k_pabsw,         k_pabsw_tp,         0, NULL, 0 },
    { "ssse3_palignr",   "ssse3",  k_palignr,       k_palignr_tp,       0, NULL, 0 },
    { "sse41_pmulld",    "sse4.1", k_pmulld,        k_pmulld_tp,        0, NULL, 0 },
    { "sse41_pmovsxwd",  "sse4.1", k_pmovsxwd,      k_pmovsxwd_tp,      0, NULL, 0 },
    { "sse41_pblendw",   "sse4.1", k_pblendw,       k_pblendw_tp,       0, NULL, 0 },
    { "sse41_mpsadbw",   "sse4.1", k_mpsadbw,       k_mpsadbw_tp,       0, NULL, 0 },
    { "sse41_phminposuw","sse4.1", k_phminposuw,    k_phminposuw_tp,    0, NULL, 0 },
    { "sse41_roundps",   "sse4.1", k_roundps,       k_roundps_tp,       0, NULL, 0 },
    { "sse42_pcmpeqq",   "sse4.2", k_pcmpeqq,       k_pcmpeqq_tp,       0, NULL, 0 },
    { "ssse3_pshufb_sem",    "ssse3", 0, 0, k_pshufb_sem,    "r4s5", 0 },
    { "ssse3_pmaddubsw_sem", "ssse3", 0, 0, k_pmaddubsw_sem, "r4s5", 0 },
    { "ssse3_pmulhrsw_sem",  "ssse3", 0, 0, k_pmulhrsw_sem,  "r4s5", 0 },
    { "ssse3_pabsb_sem",     "ssse3", 0, 0, k_pabsb_sem,     "r4s5", 0 },
    { "ssse3_phaddsw_sem",   "ssse3", 0, 0, k_phaddsw_sem,   "r4s5", 0 },
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

