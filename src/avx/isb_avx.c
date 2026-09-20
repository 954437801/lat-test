/* isb_avx.c —— isbench 组3: AVX/AVX2/FMA (VEX 编码族) + ymm 语义对拍
 *
 * 迁移来源: hf_probe.c AVX/AVX2/FMA 段(名字对齐), sse_state_probe/ymm_upper/
 *           lsx_upper_zero 结论 -> 高半状态机研究留在 legacy; 本组以「每指令
 *           lat+tput + 256 位全宽签名语义对拍」承载翻译正确性验证。
 * 编码纪律(忠实真实 32 位 x86 应用负载的运行时分派内核): 全局不开 -mavx*, 每个用例函数
 * __attribute__((target("avx"/"avx2"/"fma"))) 单发 VEX; ymm 用后 vzeroupper 兜底
 * (SysV 调用约定)。
 * 防折叠纪律: 同 isb_sse.c(操作数轮转扰动; 纯访存用例 asm volatile + "r" 地址)。
 */
#include "ib_core.h"
#include "ib_buf.h"        /* KAT 输入推导 + 标志注入(IB_GETF) */
#include "isb_avx_kat.h"   /* KAT 真值表(采集后生成; 未取数时全 UNSET) */

static float    g_yf[128] __attribute__((aligned(64)));
static int32_t  g_yi[128] __attribute__((aligned(64)));
static uint64_t g_yo[64] __attribute__((aligned(64)));   /* ymm store 目标(32B 对齐块) */
#define NEXTK(k, n) ((k) = ((k) + 1) & ((n) - 1), (k))

/* 256 位扰动源(每轮 vmovdqu 一块; load 不在依赖链上) */
__attribute__((target("avx")))
static inline __m256i wrot256(int *k)
{
    return _mm256_load_si256((const __m256i *)&g_yi[NEXTK(*k, 16) << 3]);
}

/* ==================== AVX(128+256, target="avx") ==================== */
__attribute__((target("avx"))) static uint64_t k_vaddps_xmm(unsigned long long iters)
{
    __m128 a = _mm_set1_ps(1.0f); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) a = _mm_add_ps(a, _mm_castsi128_ps(_mm256_castsi256_si128(wrot256(&k))));
    return ib_sig128(_mm_castps_si128(a));
}
__attribute__((target("avx"))) static uint64_t k_vaddps_xmm_tp(unsigned long long iters)
{
    __m128 a = _mm_set1_ps(1.0f), b = _mm_set1_ps(1.5f), c = _mm_set1_ps(2.5f), d = _mm_set1_ps(3.5f);
    int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) { __m128 w = _mm_castsi128_ps(_mm256_castsi256_si128(wrot256(&k)));
        a = _mm_add_ps(a, w); b = _mm_add_ps(b, w); c = _mm_add_ps(c, w); d = _mm_add_ps(d, w); }
    return ib_sig128(_mm_castps_si128(a)) ^ ib_sig128(_mm_castps_si128(b)) ^
           ib_sig128(_mm_castps_si128(c)) ^ ib_sig128(_mm_castps_si128(d));
}
__attribute__((target("avx"))) static uint64_t k_vaddps_ymm(unsigned long long iters)
{
    __m256 a = _mm256_set1_ps(1.0f); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) a = _mm256_add_ps(a, _mm256_castsi256_ps(wrot256(&k)));
    return ib_sig256(_mm256_castps_si256(a));
}
__attribute__((target("avx"))) static uint64_t k_vaddps_ymm_tp(unsigned long long iters)
{
    __m256 a = _mm256_set1_ps(1.0f), b = _mm256_set1_ps(1.5f), c = _mm256_set1_ps(2.5f),
           d = _mm256_set1_ps(3.5f); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) { __m256 w = _mm256_castsi256_ps(wrot256(&k));
        a = _mm256_add_ps(a, w); b = _mm256_add_ps(b, w); c = _mm256_add_ps(c, w); d = _mm256_add_ps(d, w); }
    return ib_sig256(_mm256_castps_si256(a)) ^ ib_sig256(_mm256_castps_si256(b)) ^
           ib_sig256(_mm256_castps_si256(c)) ^ ib_sig256(_mm256_castps_si256(d));
}
__attribute__((target("avx"))) static uint64_t k_vmulps_ymm(unsigned long long iters)
{
    __m256 a = _mm256_set1_ps(1.0f); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) a = _mm256_mul_ps(a, _mm256_castsi256_ps(wrot256(&k)));
    return ib_sig256(_mm256_castps_si256(a));
}
__attribute__((target("avx"))) static uint64_t k_vmulps_ymm_tp(unsigned long long iters)
{
    __m256 a = _mm256_set1_ps(1.0f), b = _mm256_set1_ps(1.5f), c = _mm256_set1_ps(2.5f),
           d = _mm256_set1_ps(3.5f); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) { __m256 w = _mm256_castsi256_ps(wrot256(&k));
        a = _mm256_mul_ps(a, w); b = _mm256_mul_ps(b, w); c = _mm256_mul_ps(c, w); d = _mm256_mul_ps(d, w); }
    return ib_sig256(_mm256_castps_si256(a)) ^ ib_sig256(_mm256_castps_si256(b)) ^
           ib_sig256(_mm256_castps_si256(c)) ^ ib_sig256(_mm256_castps_si256(d));
}
/* 访存: vmovaps ymm 轮转 load(asm 钉死防最后化) */
__attribute__((target("avx"))) static uint64_t k_vmovaps_ymm(unsigned long long iters)
{
    __m256 s = _mm256_setzero_ps(); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) { const float *p = &g_yf[NEXTK(k, 16) << 3];
        __asm__ volatile("vmovaps (%1),%0" : "=x"(s) : "r"(p)); }
    return ib_sig256(_mm256_castps_si256(s));
}
__attribute__((target("avx"))) static uint64_t k_vmovaps_ymm_tp(unsigned long long iters)
{
    __m256 s0 = _mm256_setzero_ps(), s1 = _mm256_setzero_ps(), s2 = _mm256_setzero_ps(),
           s3 = _mm256_setzero_ps(); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) { const float *p0 = &g_yf[NEXTK(k, 16) << 3],
        *p1 = &g_yf[((NEXTK(k, 16) + 1) & 15) << 3], *p2 = &g_yf[((NEXTK(k, 16) + 4) & 15) << 3],
        *p3 = &g_yf[((NEXTK(k, 16) + 8) & 15) << 3];
        __asm__ volatile("vmovaps (%1),%0" : "=x"(s0) : "r"(p0));
        __asm__ volatile("vmovaps (%1),%0" : "=x"(s1) : "r"(p1));
        __asm__ volatile("vmovaps (%1),%0" : "=x"(s2) : "r"(p2));
        __asm__ volatile("vmovaps (%1),%0" : "=x"(s3) : "r"(p3)); }
    return ib_sig256(_mm256_castps_si256(s0)) ^ ib_sig256(_mm256_castps_si256(s1)) ^
           ib_sig256(_mm256_castps_si256(s2)) ^ ib_sig256(_mm256_castps_si256(s3));
}

/* ==================== AVX2(target="avx2") ==================== */
__attribute__((target("avx2"))) static uint64_t k_vpxor_ymm(unsigned long long iters)
{
    __m256i a = _mm256_set1_epi32(0x5a5a5a5a); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) a = _mm256_xor_si256(a, wrot256(&k));
    return ib_sig256(a);
}
__attribute__((target("avx2"))) static uint64_t k_vpxor_ymm_tp(unsigned long long iters)
{
    __m256i a = _mm256_set1_epi32(1), b = _mm256_set1_epi32(2), c = _mm256_set1_epi32(3),
            d = _mm256_set1_epi32(4); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) { __m256i w = wrot256(&k);
        a = _mm256_xor_si256(a, w); b = _mm256_xor_si256(b, w);
        c = _mm256_xor_si256(c, w); d = _mm256_xor_si256(d, w); }
    return ib_sig256(a) ^ ib_sig256(b) ^ ib_sig256(c) ^ ib_sig256(d);
}
__attribute__((target("avx2"))) static uint64_t k_vpaddd_ymm(unsigned long long iters)
{
    __m256i a = _mm256_set1_epi32(0x5a5a5a5a); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) a = _mm256_add_epi32(a, wrot256(&k));
    return ib_sig256(a);
}
__attribute__((target("avx2"))) static uint64_t k_vpaddd_ymm_tp(unsigned long long iters)
{
    __m256i a = _mm256_set1_epi32(1), b = _mm256_set1_epi32(2), c = _mm256_set1_epi32(3),
            d = _mm256_set1_epi32(4); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) { __m256i w = wrot256(&k);
        a = _mm256_add_epi32(a, w); b = _mm256_add_epi32(b, w);
        c = _mm256_add_epi32(c, w); d = _mm256_add_epi32(d, w); }
    return ib_sig256(a) ^ ib_sig256(b) ^ ib_sig256(c) ^ ib_sig256(d);
}
__attribute__((target("avx2"))) static uint64_t k_vpsrad_ymm(unsigned long long iters)
{
    __m256i a = _mm256_set1_epi32(-8); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) a = _mm256_srai_epi32(_mm256_xor_si256(a, wrot256(&k)), 1);
    return ib_sig256(a);
}
__attribute__((target("avx2"))) static uint64_t k_vpsrad_ymm_tp(unsigned long long iters)
{
    __m256i a = _mm256_set1_epi32(-8), b = _mm256_set1_epi32(-16), c = _mm256_set1_epi32(-32),
            d = _mm256_set1_epi32(-64); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) { __m256i w = wrot256(&k);
        a = _mm256_srai_epi32(_mm256_xor_si256(a, w), 1); b = _mm256_srai_epi32(_mm256_xor_si256(b, w), 1);
        c = _mm256_srai_epi32(_mm256_xor_si256(c, w), 1); d = _mm256_srai_epi32(_mm256_xor_si256(d, w), 1); }
    return ib_sig256(a) ^ ib_sig256(b) ^ ib_sig256(c) ^ ib_sig256(d);
}
__attribute__((target("avx2"))) static uint64_t k_vpmaddwd_ymm(unsigned long long iters)
{
    __m256i a = _mm256_set1_epi16(3); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) a = _mm256_madd_epi16(a, wrot256(&k));
    return ib_sig256(a);
}
__attribute__((target("avx2"))) static uint64_t k_vpmaddwd_ymm_tp(unsigned long long iters)
{
    __m256i a = _mm256_set1_epi16(3), b = _mm256_set1_epi16(5), c = _mm256_set1_epi16(7),
            d = _mm256_set1_epi16(9); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) { __m256i w = wrot256(&k);
        a = _mm256_madd_epi16(a, w); b = _mm256_madd_epi16(b, w);
        c = _mm256_madd_epi16(c, w); d = _mm256_madd_epi16(d, w); }
    return ib_sig256(a) ^ ib_sig256(b) ^ ib_sig256(c) ^ ib_sig256(d);
}
__attribute__((target("avx2"))) static uint64_t k_vpmulld_ymm(unsigned long long iters)
{
    __m256i a = _mm256_set1_epi32(3); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) a = _mm256_mullo_epi32(a, wrot256(&k));
    return ib_sig256(a);
}
__attribute__((target("avx2"))) static uint64_t k_vpmulld_ymm_tp(unsigned long long iters)
{
    __m256i a = _mm256_set1_epi32(3), b = _mm256_set1_epi32(5), c = _mm256_set1_epi32(7),
            d = _mm256_set1_epi32(9); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) { __m256i w = wrot256(&k);
        a = _mm256_mullo_epi32(a, w); b = _mm256_mullo_epi32(b, w);
        c = _mm256_mullo_epi32(c, w); d = _mm256_mullo_epi32(d, w); }
    return ib_sig256(a) ^ ib_sig256(b) ^ ib_sig256(c) ^ ib_sig256(d);
}
__attribute__((target("avx2"))) static uint64_t k_vpbroadcastd(unsigned long long iters)
{
    __m256i a = _mm256_setzero_si256(); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) a = _mm256_add_epi32(a, _mm256_set1_epi32(g_yi[NEXTK(k, 127)]));
    return ib_sig256(a);
}
__attribute__((target("avx2"))) static uint64_t k_vpbroadcastd_tp(unsigned long long iters)
{
    __m256i a = _mm256_setzero_si256(), b = _mm256_setzero_si256(), c = _mm256_setzero_si256(),
            d = _mm256_setzero_si256(); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) { int v = g_yi[NEXTK(k, 127)];
        a = _mm256_add_epi32(a, _mm256_set1_epi32(v));
        b = _mm256_add_epi32(b, _mm256_set1_epi32(v + 1));
        c = _mm256_add_epi32(c, _mm256_set1_epi32(v + 2));
        d = _mm256_add_epi32(d, _mm256_set1_epi32(v + 3)); }
    return ib_sig256(a) ^ ib_sig256(b) ^ ib_sig256(c) ^ ib_sig256(d);
}
__attribute__((target("avx2"))) static uint64_t k_vmovdqa_ymm(unsigned long long iters)
{
    __m256i s = _mm256_setzero_si256(); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) { const int32_t *p = &g_yi[NEXTK(k, 16) << 3];
        __asm__ volatile("vmovdqa (%1),%0" : "=x"(s) : "r"(p)); }
    return ib_sig256(s);
}
__attribute__((target("avx2"))) static uint64_t k_vmovdqa_ymm_tp(unsigned long long iters)
{
    __m256i s0 = _mm256_setzero_si256(), s1 = _mm256_setzero_si256(), s2 = _mm256_setzero_si256(),
            s3 = _mm256_setzero_si256(); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) { const int32_t *p0 = &g_yi[NEXTK(k, 16) << 3],
        *p1 = &g_yi[((NEXTK(k, 16) + 1) & 15) << 3], *p2 = &g_yi[((NEXTK(k, 16) + 4) & 15) << 3],
        *p3 = &g_yi[((NEXTK(k, 16) + 8) & 15) << 3];
        __asm__ volatile("vmovdqa (%1),%0" : "=x"(s0) : "r"(p0));
        __asm__ volatile("vmovdqa (%1),%0" : "=x"(s1) : "r"(p1));
        __asm__ volatile("vmovdqa (%1),%0" : "=x"(s2) : "r"(p2));
        __asm__ volatile("vmovdqa (%1),%0" : "=x"(s3) : "r"(p3)); }
    return ib_sig256(s0) ^ ib_sig256(s1) ^ ib_sig256(s2) ^ ib_sig256(s3);
}

/* ==================== FMA(target="fma") ==================== */
__attribute__((target("fma"))) static uint64_t k_vfmadd213ps(unsigned long long iters)
{
    __m256 a = _mm256_set1_ps(1.0f), c = _mm256_setzero_ps(); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) a = _mm256_fmadd_ps(a, _mm256_castsi256_ps(wrot256(&k)), c);
    return ib_sig256(_mm256_castps_si256(a));
}
__attribute__((target("fma"))) static uint64_t k_vfmadd213ps_tp(unsigned long long iters)
{
    __m256 a = _mm256_set1_ps(1.0f), b = _mm256_set1_ps(1.5f), c0 = _mm256_set1_ps(2.5f),
           d = _mm256_set1_ps(3.5f), c = _mm256_setzero_ps(); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) { __m256 w = _mm256_castsi256_ps(wrot256(&k));
        a = _mm256_fmadd_ps(a, w, c); b = _mm256_fmadd_ps(b, w, c);
        c0 = _mm256_fmadd_ps(c0, w, c); d = _mm256_fmadd_ps(d, w, c); }
    return ib_sig256(_mm256_castps_si256(a)) ^ ib_sig256(_mm256_castps_si256(b)) ^
           ib_sig256(_mm256_castps_si256(c0)) ^ ib_sig256(_mm256_castps_si256(d));
}

/* ==================== 自 vec 组迁入的 7 条 VEX 形态(归位: avx = 全部 VEX 编码) ==================== */
__attribute__((target("avx"))) static uint64_t k_vmovdqu(unsigned long long iters){ __m256i s=_mm256_setzero_si256(); int k=0;
    unsigned long long i; for(i=0;i<iters;i++){ const int32_t *p=&g_yi[NEXTK(k,16)<<3];
        __asm__ volatile("vmovdqu (%1),%0" : "=x"(s) : "r"(p)); }
    return ib_sig256(s); }
__attribute__((target("avx"))) static uint64_t k_vmovdqu_tp(unsigned long long iters){ __m256i s0=_mm256_setzero_si256(),s1=s0,s2=s0,s3=s0; int k=0;
    unsigned long long i; for(i=0;i<iters;i++){ int j=NEXTK(k,16); const int32_t *p0=&g_yi[j<<3],
        *p1=&g_yi[((j+1)&15)<<3], *p2=&g_yi[((j+4)&15)<<3], *p3=&g_yi[((j+8)&15)<<3];
        __asm__ volatile("vmovdqu (%1),%0" : "=x"(s0) : "r"(p0));
        __asm__ volatile("vmovdqu (%1),%0" : "=x"(s1) : "r"(p1));
        __asm__ volatile("vmovdqu (%1),%0" : "=x"(s2) : "r"(p2));
        __asm__ volatile("vmovdqu (%1),%0" : "=x"(s3) : "r"(p3)); }
    return ib_sig256(s0)^ib_sig256(s1)^ib_sig256(s2)^ib_sig256(s3); }
__attribute__((target("avx"))) static uint64_t k_vptest_tp(unsigned long long iters)
{
    __m256i a = _mm256_set1_epi32(0x0f0f0f0f); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) { __m256i w = wrot256(&k);
        __asm__ volatile("vptest %1,%0" : : "x"(a), "x"(w) : "cc");
        __asm__ volatile("vptest %1,%0" : : "x"(a), "x"(w) : "cc");
        __asm__ volatile("vptest %1,%0" : : "x"(a), "x"(w) : "cc");
        __asm__ volatile("vptest %1,%0" : : "x"(a), "x"(w) : "cc"); }
    return ib_sig256(a);
}
__attribute__((target("avx"))) static uint64_t k_vinsertf128(unsigned long long iters)
{
    __m256 a = _mm256_set1_ps(1.5f); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) { __m256 w = _mm256_castsi256_ps(wrot256(&k));
        a = _mm256_insertf128_ps(_mm256_xor_ps(a, w), _mm256_castps256_ps128(w), 1); }
    return ib_sig256(_mm256_castps_si256(a));
}
__attribute__((target("avx"))) static uint64_t k_vinsertf128_tp(unsigned long long iters)
{
    __m256 a = _mm256_set1_ps(1.5f), b = _mm256_set1_ps(2.5f),
           c = _mm256_set1_ps(0.25f), d = _mm256_set1_ps(7.75f);
    int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) { __m256 w = _mm256_castsi256_ps(wrot256(&k));
        a = _mm256_insertf128_ps(_mm256_xor_ps(a, w), _mm256_castps256_ps128(w), 1);
        b = _mm256_insertf128_ps(_mm256_xor_ps(b, w), _mm256_castps256_ps128(w), 1);
        c = _mm256_insertf128_ps(_mm256_xor_ps(c, w), _mm256_castps256_ps128(w), 1);
        d = _mm256_insertf128_ps(_mm256_xor_ps(d, w), _mm256_castps256_ps128(w), 1); }
    return ib_sig256(_mm256_castps_si256(a)) ^ ib_sig256(_mm256_castps_si256(b)) ^
           ib_sig256(_mm256_castps_si256(c)) ^ ib_sig256(_mm256_castps_si256(d));
}
#define YSHIFT(name, EXPR)                                                            \
__attribute__((target("avx2"))) static uint64_t k_##name(unsigned long long iters){ \
    __m256i a=_mm256_set1_epi32(0x5a5a5a5a); int k=0;                                \
    unsigned long long i; for(i=0;i<iters;i++){ __m256i w=wrot256(&k); a=EXPR; }     \
    return ib_sig256(a); }                                                            \
__attribute__((target("avx2"))) static uint64_t k_##name##_tp(unsigned long long iters){ \
    __m256i a=_mm256_set1_epi32(0x5a5a5a5a), b=_mm256_set1_epi32(0x3c3c3c3c),        \
           c=_mm256_set1_epi32(0x0f0f0f0f), d=_mm256_set1_epi32(0x77777777);         \
    int k=0; unsigned long long i;                                                    \
    for(i=0;i<iters;i++){ __m256i w=wrot256(&k); a=EXPR; b=EXPR; c=EXPR; d=EXPR; }   \
    return ib_sig256(a)^ib_sig256(b)^ib_sig256(c)^ib_sig256(d); }
YSHIFT(vpsllq, _mm256_xor_si256(_mm256_slli_epi64(a, 11), w))
YSHIFT(vpsrlq, _mm256_xor_si256(_mm256_srli_epi64(a, 7), w))
YSHIFT(vpsrlw, _mm256_xor_si256(_mm256_srli_epi16(a, 3), w))
#undef YSHIFT
__attribute__((target("avx2"))) static uint64_t k_vpaddq(unsigned long long iters)
{
    __m256i a = _mm256_set1_epi64x(1); int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) a = _mm256_add_epi64(a, wrot256(&k));
    return ib_sig256(a);
}
__attribute__((target("avx2"))) static uint64_t k_vpaddq_tp(unsigned long long iters)
{
    __m256i a = _mm256_set1_epi64x(1), b = _mm256_set1_epi64x(2),
            c = _mm256_set1_epi64x(3), d = _mm256_set1_epi64x(4);
    int k = 0; unsigned long long i;
    for (i = 0; i < iters; i++) { __m256i w = wrot256(&k);
        a = _mm256_add_epi64(a, w); b = _mm256_add_epi64(b, w);
        c = _mm256_add_epi64(c, w); d = _mm256_add_epi64(d, w); }
    return ib_sig256(a) ^ ib_sig256(b) ^ ib_sig256(c) ^ ib_sig256(d);
}

/* ==================== KAT 探针(每词干一条; 128/256 位逐字上表) ====================
 * 输入由词干哈希重导: 甲=(i0,i1,i2,i3) = 256 位。位/整数族直接用位形; 浮点族
 * 由哈希整数精确构造有限 float(af_f), 不拿哈希位形直当浮点(NaN/Inf 尾数跨机不必同)。
 * 128 位形态只用 i0,i1(i2/i3=0), 输出高两字置 0; 256 位形态用 i0..i3, 输出 o0..o3。
 * vptest 只写标志 -> o0..o3=0, outf 只取 CF/ZF(0x041)。 */
#define A0(sn, kk)  IB_KIN8(sn, kk, 0, uint64_t)
#define A1(sn, kk)  IB_KIN8(sn, kk, 1, uint64_t)
#define A2(sn, kk)  IB_KIN8(sn, kk, 2, uint64_t)
#define A3(sn, kk)  IB_KIN8(sn, kk, 3, uint64_t)
#define ARB(x, n)   (((x) >> (n)) | ((x) << (64 - (n))))
#define AVIN(sn, kk)   _mm256_set_epi64x((long long)A3(sn,kk),(long long)A2(sn,kk),(long long)A1(sn,kk),(long long)A0(sn,kk))
#define AVINB(sn, kk)  _mm256_set_epi64x((long long)ARB(A0(sn,kk),13),(long long)ARB(A3(sn,kk),7),(long long)ARB(A2(sn,kk),29),(long long)ARB(A1(sn,kk),11))
#define AIN(sn, kk)    (g->i0=A0(sn,kk),g->i1=A1(sn,kk),g->i2=A2(sn,kk),g->i3=A3(sn,kk),g->inf=0)
#define AOUT(r)  do { uint64_t q_[4]; _mm256_storeu_si256((__m256i *)q_, (r)); \
    g->o0=q_[0]; g->o1=q_[1]; g->o2=q_[2]; g->o3=q_[3]; g->outf=0; } while (0)
#define AOUT128(r) do { union { __m128i v_; uint64_t q[2]; } u_; u_.v_ = (r); \
    g->o0=u_.q[0]; g->o1=u_.q[1]; g->o2=0; g->o3=0; g->outf=0; } while (0)

static uint64_t g_ymk[4] __attribute__((aligned(32)));   /* KAT 访存源(256 位) */

static float af_f(uint64_t u, int part)
{
    int32_t v = part ? (int32_t)(uint32_t)(u >> 32) : (int32_t)(uint32_t)u;
    return (float)v / (float)(part ? 8 : 4);
}
#define AVF8(u0,u1,u2,u3) _mm256_set_ps(af_f(u3,1),af_f(u3,0),af_f(u2,1),af_f(u2,0), \
                                        af_f(u1,1),af_f(u1,0),af_f(u0,1),af_f(u0,0))
#define AVF4(u0,u1) _mm_set_ps(af_f(u1,1),af_f(u1,0),af_f(u0,1),af_f(u0,0))

#define AK_BIN256(sn, TGT, EXPR) __attribute__((target(TGT))) \
static void k_##sn##_kat(int kk, ib_kv *g) { \
    __m256i a = AVIN(#sn,kk), b = AVINB(#sn,kk); AIN(#sn,kk); AOUT(EXPR); }
#define AK_UN256(sn, TGT, EXPR) __attribute__((target(TGT))) \
static void k_##sn##_kat(int kk, ib_kv *g) { \
    __m256i a = AVIN(#sn,kk); AIN(#sn,kk); AOUT(EXPR); }
#define AK_MOV256(sn, TGT, EXPR) __attribute__((target(TGT))) \
static void k_##sn##_kat(int kk, ib_kv *g) { \
    g_ymk[0]=A0(#sn,kk); g_ymk[1]=A1(#sn,kk); g_ymk[2]=A2(#sn,kk); g_ymk[3]=A3(#sn,kk); \
    AIN(#sn,kk); AOUT(EXPR); }

/* ---- 128 位形态 ---- */
__attribute__((target("avx"))) static void k_vaddps_xmm_kat(int kk, ib_kv *g)
{
    __m128 a = AVF4(A0("vaddps_xmm",kk), A1("vaddps_xmm",kk));
    __m128 b = AVF4(A1("vaddps_xmm",kk), ARB(A0("vaddps_xmm",kk),13));
    g->i0=A0("vaddps_xmm",kk); g->i1=A1("vaddps_xmm",kk); g->i2=0; g->i3=0; g->inf=0;
    AOUT128(_mm_castps_si128(_mm_add_ps(a, b)));
}

/* ---- 访存族(256 位) ---- */
AK_MOV256(vmovaps_ymm, "avx",  _mm256_load_si256((const __m256i *)g_ymk))
AK_MOV256(vmovdqa_ymm, "avx2", _mm256_load_si256((const __m256i *)g_ymk))
AK_MOV256(vmovdqu,     "avx",  _mm256_loadu_si256((const __m256i *)g_ymk))

/* ---- 整数/位运算(256 位) ---- */
AK_BIN256(vpxor_ymm,   "avx2", _mm256_xor_si256(a, b))
AK_BIN256(vpaddd_ymm,  "avx2", _mm256_add_epi32(a, b))
AK_BIN256(vpaddd256_sem, "avx2", _mm256_add_epi32(a, b))
AK_BIN256(vpmaddwd_ymm, "avx2", _mm256_madd_epi16(a, b))
AK_BIN256(vpmulld_ymm, "avx2", _mm256_mullo_epi32(a, b))
AK_BIN256(vpshufb256_sem, "avx2", _mm256_shuffle_epi8(a, b))
AK_BIN256(vpaddq,      "avx2", _mm256_add_epi64(a, b))
AK_UN256(vpsrad_ymm,   "avx2", _mm256_srai_epi32(a, 1))
AK_UN256(vpsllq,       "avx2", _mm256_slli_epi64(a, 11))
AK_UN256(vpsrlq,       "avx2", _mm256_srli_epi64(a, 7))
AK_UN256(vpsrlw,       "avx2", _mm256_srli_epi16(a, 3))
__attribute__((target("avx2"))) static void k_vpbroadcastd_kat(int kk, ib_kv *g)
{
    int32_t v = (int32_t)(uint32_t)A0("vpbroadcastd", kk);
    AIN("vpbroadcastd", kk);
    AOUT(_mm256_set1_epi32(v));
}

/* ---- 浮点族(256 位, 有限值构造) ---- */
__attribute__((target("avx"))) static void k_vaddps_ymm_kat(int kk, ib_kv *g)
{
    __m256 a = AVF8(A0("vaddps_ymm",kk),A1("vaddps_ymm",kk),A2("vaddps_ymm",kk),A3("vaddps_ymm",kk));
    __m256 b = AVF8(A1("vaddps_ymm",kk),A2("vaddps_ymm",kk),A3("vaddps_ymm",kk),ARB(A0("vaddps_ymm",kk),13));
    AIN("vaddps_ymm", kk);
    AOUT(_mm256_castps_si256(_mm256_add_ps(a, b)));
}
__attribute__((target("avx"))) static void k_vmulps_ymm_kat(int kk, ib_kv *g)
{
    __m256 a = AVF8(A0("vmulps_ymm",kk),A1("vmulps_ymm",kk),A2("vmulps_ymm",kk),A3("vmulps_ymm",kk));
    __m256 b = AVF8(A1("vmulps_ymm",kk),A2("vmulps_ymm",kk),A3("vmulps_ymm",kk),ARB(A0("vmulps_ymm",kk),13));
    AIN("vmulps_ymm", kk);
    AOUT(_mm256_castps_si256(_mm256_mul_ps(a, b)));
}
__attribute__((target("fma"))) static void k_vfmadd213ps_kat(int kk, ib_kv *g)
{
    __m256 a = AVF8(A0("vfmadd213ps",kk),A1("vfmadd213ps",kk),A2("vfmadd213ps",kk),A3("vfmadd213ps",kk));
    __m256 b = AVF8(A1("vfmadd213ps",kk),A2("vfmadd213ps",kk),A3("vfmadd213ps",kk),ARB(A0("vfmadd213ps",kk),13));
    __m256 c = _mm256_set1_ps(0.125f);
    AIN("vfmadd213ps", kk);
    AOUT(_mm256_castps_si256(_mm256_fmadd_ps(a, b, c)));
}
__attribute__((target("fma"))) static void k_vfmadd213ps_sem_kat(int kk, ib_kv *g)
{
    __m256 a = AVF8(A0("vfmadd213ps_sem",kk),A1("vfmadd213ps_sem",kk),A2("vfmadd213ps_sem",kk),A3("vfmadd213ps_sem",kk));
    __m256 b = AVF8(A1("vfmadd213ps_sem",kk),A2("vfmadd213ps_sem",kk),A3("vfmadd213ps_sem",kk),ARB(A0("vfmadd213ps_sem",kk),13));
    __m256 c = _mm256_set1_ps(0.125f);
    AIN("vfmadd213ps_sem", kk);
    AOUT(_mm256_castps_si256(_mm256_fmadd_ps(a, b, c)));
}

/* ---- 跨寄存器/只写标志 ---- */
__attribute__((target("avx"))) static void k_vinsertf128_kat(int kk, ib_kv *g)
{
    __m256 a = _mm256_castsi256_ps(AVIN("vinsertf128", kk));
    __m256 b = _mm256_castsi256_ps(AVINB("vinsertf128", kk));
    AIN("vinsertf128", kk);
    AOUT(_mm256_castps_si256(_mm256_insertf128_ps(a, _mm256_castps256_ps128(b), 1)));
}
__attribute__((target("avx"))) static void k_vptest_kat(int kk, ib_kv *g)
{
    __m256i a = AVIN("vptest", kk), b = AVINB("vptest", kk);
    uintptr_t fl = 0;
    AIN("vptest", kk);
    __asm__ volatile("vptest %2,%1\n\t" IB_GETF
                    : [fl] "=&r"(fl) : "x"(a), "x"(b) : "cc", "memory");
    g->o0=0; g->o1=0; g->o2=0; g->o3=0; g->outf = (uint64_t)fl & 0x041ULL;
}

/* ---------------- 用例表(名字首段=ISA 段: avx/avx2/fma; 原名保留为后段) -------- */
static const ib_case g_cases[] = {
    { "avx_vaddps_xmm", "avx", k_vaddps_xmm, k_vaddps_xmm_tp, 0, NULL, 0, NULL, 0,
      k_vaddps_xmm_kat, IB_KAT_vaddps_xmm, "vaddps_xmm" },
    { "avx_vaddps_ymm", "avx", k_vaddps_ymm, k_vaddps_ymm_tp, 0, NULL, 0, NULL, 0,
      k_vaddps_ymm_kat, IB_KAT_vaddps_ymm, "vaddps_ymm" },
    { "avx_vmulps_ymm", "avx", k_vmulps_ymm, k_vmulps_ymm_tp, 0, NULL, 0, NULL, 0,
      k_vmulps_ymm_kat, IB_KAT_vmulps_ymm, "vmulps_ymm" },
    { "avx_vmovaps_ymm", "avx", k_vmovaps_ymm, k_vmovaps_ymm_tp, 0, NULL, 32, NULL, 0,
      k_vmovaps_ymm_kat, IB_KAT_vmovaps_ymm, "vmovaps_ymm" },
    { "avx2_vpxor_ymm", "avx2", k_vpxor_ymm, k_vpxor_ymm_tp, 0, NULL, 0, NULL, 0,
      k_vpxor_ymm_kat, IB_KAT_vpxor_ymm, "vpxor_ymm" },
    { "avx2_vpaddd_ymm", "avx2", k_vpaddd_ymm, k_vpaddd_ymm_tp, 0, NULL, 0, NULL, 0,
      k_vpaddd_ymm_kat, IB_KAT_vpaddd_ymm, "vpaddd_ymm" },
    { "avx2_vpsrad_ymm", "avx2", k_vpsrad_ymm, k_vpsrad_ymm_tp, 0, NULL, 0, NULL, 0,
      k_vpsrad_ymm_kat, IB_KAT_vpsrad_ymm, "vpsrad_ymm" },
    { "avx2_vpmaddwd_ymm", "avx2", k_vpmaddwd_ymm, k_vpmaddwd_ymm_tp, 0, NULL, 0, NULL, 0,
      k_vpmaddwd_ymm_kat, IB_KAT_vpmaddwd_ymm, "vpmaddwd_ymm" },
    { "avx2_vpmulld_ymm", "avx2", k_vpmulld_ymm, k_vpmulld_ymm_tp, 0, NULL, 0, NULL, 0,
      k_vpmulld_ymm_kat, IB_KAT_vpmulld_ymm, "vpmulld_ymm" },
    { "avx2_vpbroadcastd", "avx2", k_vpbroadcastd, k_vpbroadcastd_tp, 0, NULL, 0, NULL, 0,
      k_vpbroadcastd_kat, IB_KAT_vpbroadcastd, "vpbroadcastd" },
    { "avx2_vmovdqa_ymm", "avx2", k_vmovdqa_ymm, k_vmovdqa_ymm_tp, 0, NULL, 32, NULL, 0,
      k_vmovdqa_ymm_kat, IB_KAT_vmovdqa_ymm, "vmovdqa_ymm" },
    { "fma_vfmadd213ps", "fma", k_vfmadd213ps, k_vfmadd213ps_tp, 0, NULL, 0, NULL, 0,
      k_vfmadd213ps_kat, IB_KAT_vfmadd213ps, "vfmadd213ps" },
    { "avx2_vpaddd256_sem", "avx2", 0, 0, 0, NULL, 0, NULL, 0,
      k_vpaddd256_sem_kat, IB_KAT_vpaddd256_sem, "vpaddd256_sem" },
    { "avx2_vpshufb256_sem", "avx2", 0, 0, 0, NULL, 0, NULL, 0,
      k_vpshufb256_sem_kat, IB_KAT_vpshufb256_sem, "vpshufb256_sem" },
    { "fma_vfmadd213ps_sem", "fma", 0, 0, 0, NULL, 0, NULL, 0,
      k_vfmadd213ps_sem_kat, IB_KAT_vfmadd213ps_sem, "vfmadd213ps_sem" },
    { "avx_vmovdqu", "avx", k_vmovdqu, k_vmovdqu_tp, 0, NULL, 32, NULL, 0,
      k_vmovdqu_kat, IB_KAT_vmovdqu, "vmovdqu" },
    { "avx_vptest", "avx", NULL, k_vptest_tp, 0, NULL, 0, NULL, 0,
      k_vptest_kat, IB_KAT_vptest, "vptest" },
    { "avx_vinsertf128", "avx", k_vinsertf128, k_vinsertf128_tp, 0, NULL, 0, NULL, 0,
      k_vinsertf128_kat, IB_KAT_vinsertf128, "vinsertf128" },
    { "avx2_vpsllq", "avx2", k_vpsllq, k_vpsllq_tp, 0, NULL, 0, NULL, 0,
      k_vpsllq_kat, IB_KAT_vpsllq, "vpsllq" },
    { "avx2_vpsrlq", "avx2", k_vpsrlq, k_vpsrlq_tp, 0, NULL, 0, NULL, 0,
      k_vpsrlq_kat, IB_KAT_vpsrlq, "vpsrlq" },
    { "avx2_vpsrlw", "avx2", k_vpsrlw, k_vpsrlw_tp, 0, NULL, 0, NULL, 0,
      k_vpsrlw_kat, IB_KAT_vpsrlw, "vpsrlw" },
    { "avx2_vpaddq", "avx2", k_vpaddq, k_vpaddq_tp, 0, NULL, 0, NULL, 0,
      k_vpaddq_kat, IB_KAT_vpaddq, "vpaddq" },
};
#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

int main(int argc, char **argv)
{
    int i;
    volatile float *vf = g_yf;      /* volatile 写 + asm 引用: 内容对编译器不可知 */
    volatile int32_t *vi = g_yi;
    volatile uint64_t *vo = g_yo;
    for (i = 0; i < 128; i++) { vf[i] = 1.0f + (float)(i % 97); vi[i] = i * 2654435761u + 1; }
    for (i = 0; i < 64; i++) vo[i] = 0x9e3779b97f4a7c15ULL * (uint64_t)(i + 1);
    __asm__ volatile("" : "+m"(g_yf[0]), "+m"(g_yi[0]), "+m"(g_yo[0]) : : "memory");
    ib_init(argc, argv);
    ib_hdr("avx", NCASES);
    ib_run_cases("avx", g_cases, NCASES);
    return 0;
}
