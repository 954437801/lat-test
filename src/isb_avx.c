/* isb_avx.c —— isbench 组3: AVX/AVX2/FMA (VEX 编码族) + ymm 语义对拍
 *
 * 迁移来源: hf_probe.c AVX/AVX2/FMA 段(名字对齐), sse_state_probe/ymm_upper/
 *           lsx_upper_zero 结论 -> 高半状态机研究留在 legacy; 本组以「每指令
 *           lat+tput + 256 位全宽签名语义对拍」承载翻译正确性验证。
 * 编码纪律(忠实 libcef 运行时分派内核): 全局不开 -mavx*, 每个用例函数
 * __attribute__((target("avx"/"avx2"/"fma"))) 单发 VEX; ymm 用后 vzeroupper 兜底
 * (SysV 调用约定)。
 * 防折叠纪律: 同 isb_sse.c(操作数轮转扰动; 纯访存用例 asm volatile + "r" 地址)。
 */
#include "ib.h"

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

/* ==================== sem: 256 位确定性输入->全宽签名对拍(翻译正确性) ==================== */
__attribute__((target("avx2"))) static uint64_t k_vpaddd256_sem(unsigned long long it)
{
    (void)it;
    const int32_t *src = g_yi, *add = g_yi + 64;
    uint64_t acc = 0; int r;
    for (r = 0; r < 8; r++) {
        __m256i a = _mm256_loadu_si256((const __m256i *)&src[(r * 8) & 63]);
        __m256i b = _mm256_loadu_si256((const __m256i *)&add[((r * 8) + 4) & 63]);
        acc = (acc << 7) | (acc >> 57); acc ^= ib_sig256(_mm256_add_epi32(a, b));
    }
    return acc;
}
__attribute__((target("avx2"))) static uint64_t k_vpshufb256_sem(unsigned long long it)
{
    (void)it;
    const int32_t *src = g_yi, *msk = g_yi + 64;
    uint64_t acc = 0; int r;
    for (r = 0; r < 8; r++) {
        __m256i a = _mm256_loadu_si256((const __m256i *)&src[(r * 8) & 63]);
        __m256i m = _mm256_loadu_si256((const __m256i *)&msk[((r * 8) + 4) & 63]);
        acc = (acc << 7) | (acc >> 57); acc ^= ib_sig256(_mm256_shuffle_epi8(a, m));
    }
    return acc;
}
__attribute__((target("fma"))) static uint64_t k_vfmadd213ps_sem(unsigned long long it)
{
    (void)it;
    const float *a0 = g_yf, *b0 = g_yf + 64;
    uint64_t acc = 0; int r;
    for (r = 0; r < 8; r++) {
        __m256 a = _mm256_loadu_ps(&a0[(r * 8) & 63]);
        __m256 b = _mm256_loadu_ps(&b0[((r * 8) + 4) & 63]);
        __m256 c = _mm256_set1_ps((float)(r + 1) * 0.5f);
        acc = (acc << 7) | (acc >> 57); acc ^= ib_sig256(_mm256_castps_si256(_mm256_fmadd_ps(a, b, c)));
    }
    return acc;
}

/* ---------------- 用例表(名字首段=ISA 段: avx/avx2/fma; 原名保留为后段) -------- */
static const ib_case g_cases[] = {
    { "avx_vaddps_xmm",    "avx",  k_vaddps_xmm,    k_vaddps_xmm_tp,    0, NULL, 0 },
    { "avx_vaddps_ymm",    "avx",  k_vaddps_ymm,    k_vaddps_ymm_tp,    0, NULL, 0 },
    { "avx_vmulps_ymm",    "avx",  k_vmulps_ymm,    k_vmulps_ymm_tp,    0, NULL, 0 },
    { "avx_vmovaps_ymm",   "avx",  k_vmovaps_ymm,   k_vmovaps_ymm_tp,   0, NULL, 32 },
    { "avx2_vpxor_ymm",    "avx2", k_vpxor_ymm,     k_vpxor_ymm_tp,     0, NULL, 0 },
    { "avx2_vpaddd_ymm",   "avx2", k_vpaddd_ymm,    k_vpaddd_ymm_tp,    0, NULL, 0 },
    { "avx2_vpsrad_ymm",   "avx2", k_vpsrad_ymm,    k_vpsrad_ymm_tp,    0, NULL, 0 },
    { "avx2_vpmaddwd_ymm", "avx2", k_vpmaddwd_ymm,  k_vpmaddwd_ymm_tp,  0, NULL, 0 },
    { "avx2_vpmulld_ymm",  "avx2", k_vpmulld_ymm,   k_vpmulld_ymm_tp,   0, NULL, 0 },
    { "avx2_vpbroadcastd", "avx2", k_vpbroadcastd,  k_vpbroadcastd_tp,  0, NULL, 0 },
    { "avx2_vmovdqa_ymm",  "avx2", k_vmovdqa_ymm,   k_vmovdqa_ymm_tp,   0, NULL, 32 },
    { "fma_vfmadd213ps",   "fma",  k_vfmadd213ps,   k_vfmadd213ps_tp,   0, NULL, 0 },
    { "avx2_vpaddd256_sem",   "avx2", 0, 0, k_vpaddd256_sem,   "sem256", 0 },
    { "avx2_vpshufb256_sem",  "avx2", 0, 0, k_vpshufb256_sem,  "sem256", 0 },
    { "fma_vfmadd213ps_sem", "fma",  0, 0, k_vfmadd213ps_sem, "sem256", 0 },
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
