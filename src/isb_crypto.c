/* isb_crypto.c —— isbench 组4: AES-NI / PCLMUL / SHA 加密族
 *
 * 迁移来源: aes_kat.c 全量(FIPS-197 KAT keygen/enc/dec + 依赖链 + 8 链吞吐 +
 *           ECB 块负载), insn_probe.c aesenc/aesdec/pclmulqdq/sha256rnds2 段。
 * 输出契约: kat 三例走 ib_kat(PASS/FAIL + detail); 其余 lat/tput 双内核;
 *           ECB 每「op」= 256 块×16B 一轮, bpop=4096 -> v2=MB/s 与 legacy
 *           ECB_MBPS 同口径直接可比。
 * 编码纪律: target("aes"/"pclmul"/"sha") 单启 -> legacy 66 0F 38 编码
 *           (忠实 32 位 libcef); 密钥经全局 g_rk 运行时展开, 链不可闭式折叠。
 */
#include "ib.h"

/* FIPS-197 例: key=000102..0f, pt=001122..ff, ct(enc 结果) */
static const unsigned char KAT_KEY[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const unsigned char KAT_PT[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};
static const unsigned char KAT_CT[16] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
};
static __m128i g_rk[11];                 /* 运行时展开: 编译器不可常数化 */
static unsigned char g_out[16];
static unsigned char g_ecb[256 * 16];    /* 4 KiB ECB 结果缓冲(每次调用全量覆盖写) */
static unsigned char g_ecb_src[256 * 16];  /* ECB 只读明文源(KAT_PT 铺满, 与结果区分离) */

__attribute__((target("aes"))) static __m128i key_expand_step(__m128i key, __m128i gen)
{
    gen = _mm_shuffle_epi32(gen, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, gen);
}
__attribute__((target("aes"))) static void aes128_expand(const unsigned char *key)
{
    __m128i k = _mm_loadu_si128((const __m128i *)key);
    g_rk[0] = k;
    g_rk[1] = k = key_expand_step(k, _mm_aeskeygenassist_si128(k, 0x01));
    g_rk[2] = k = key_expand_step(k, _mm_aeskeygenassist_si128(k, 0x02));
    g_rk[3] = k = key_expand_step(k, _mm_aeskeygenassist_si128(k, 0x04));
    g_rk[4] = k = key_expand_step(k, _mm_aeskeygenassist_si128(k, 0x08));
    g_rk[5] = k = key_expand_step(k, _mm_aeskeygenassist_si128(k, 0x10));
    g_rk[6] = k = key_expand_step(k, _mm_aeskeygenassist_si128(k, 0x20));
    g_rk[7] = k = key_expand_step(k, _mm_aeskeygenassist_si128(k, 0x40));
    g_rk[8] = k = key_expand_step(k, _mm_aeskeygenassist_si128(k, 0x80));
    g_rk[9] = k = key_expand_step(k, _mm_aeskeygenassist_si128(k, 0x1b));
    g_rk[10] = k = key_expand_step(k, _mm_aeskeygenassist_si128(k, 0x36));
}
__attribute__((target("aes"))) static void aes128_expand_dec(void)
{
    int i;
    for (i = 1; i < 10; i++)
        g_rk[i] = _mm_aesimc_si128(g_rk[i]);
}
static uint64_t sig_mem(const void *p, int n)
{
    const unsigned char *b = (const unsigned char *)p;
    uint64_t h = 1469598103934665603ULL;   /* FNV-1a(内存摘要, 与缓冲内容绑定) */
    int i;
    for (i = 0; i < n; i++) {
        h ^= b[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* ==================== FIPS-197 KAT(自检: 展开/加密/解密) ==================== */
__attribute__((target("aes"))) static uint64_t kat_keygen(unsigned long long it)
{
    (void)it;
    aes128_expand(KAT_KEY);
    _mm_storeu_si128((__m128i *)g_out, g_rk[1]);
    /* FIPS-197 AES-128 round key[1] = d6aa74fd d2af72fa daa678f1 d6ab76fe */
    return !memcmp(g_out, "\xd6\xaa\x74\xfd\xd2\xaf\x72\xfa\xda\xa6\x78\xf1\xd6\xab\x76\xfe", 16);
}
__attribute__((target("aes"))) static uint64_t kat_enc(unsigned long long it)
{
    __m128i x;
    int i;
    (void)it;
    aes128_expand(KAT_KEY);
    x = _mm_xor_si128(_mm_loadu_si128((const __m128i *)KAT_PT), g_rk[0]);
    for (i = 1; i < 10; i++)
        x = _mm_aesenc_si128(x, g_rk[i]);
    x = _mm_aesenclast_si128(x, g_rk[10]);
    _mm_storeu_si128((__m128i *)g_out, x);
    return !memcmp(g_out, KAT_CT, 16);
}
__attribute__((target("aes"))) static uint64_t kat_dec(unsigned long long it)
{
    __m128i x;
    int i;
    (void)it;
    aes128_expand(KAT_KEY);
    aes128_expand_dec();
    x = _mm_xor_si128(_mm_loadu_si128((const __m128i *)KAT_CT), g_rk[10]);
    for (i = 9; i > 0; i--)
        x = _mm_aesdec_si128(x, g_rk[i]);
    x = _mm_aesdeclast_si128(x, g_rk[0]);
    _mm_storeu_si128((__m128i *)g_out, x);
    return !memcmp(g_out, KAT_PT, 16);
}

/* ==================== AESENC/AESDEC 依赖链(延迟) ==================== */
__attribute__((target("aes"))) static uint64_t k_aesenc(unsigned long long iters)
{
    __m128i x = _mm_loadu_si128((const __m128i *)KAT_PT);
    unsigned long long i;
    for (i = 0; i < iters; i++) x = _mm_aesenc_si128(x, g_rk[1]);
    return ib_sig128(x);
}
__attribute__((target("aes"))) static uint64_t k_aesenc_tp(unsigned long long iters)
{
    __m128i a[8];
    unsigned long long i;
    int j;
    for (j = 0; j < 8; j++)
        a[j] = _mm_add_epi32(_mm_loadu_si128((const __m128i *)KAT_PT), _mm_set1_epi32(j));
    for (i = 0; i < iters; i++)
        for (j = 0; j < 8; j++)
            a[j] = _mm_aesenc_si128(a[j], g_rk[3]);
    {
        __m128i s = _mm_setzero_si128();
        for (j = 0; j < 8; j++) s = _mm_xor_si128(s, a[j]);
        return ib_sig128(s);
    }
}
__attribute__((target("aes"))) static uint64_t k_aesdec(unsigned long long iters)
{
    __m128i x = _mm_loadu_si128((const __m128i *)KAT_CT);
    unsigned long long i;
    for (i = 0; i < iters; i++) x = _mm_aesdec_si128(x, g_rk[1]);
    return ib_sig128(x);
}
__attribute__((target("aes"))) static uint64_t k_aesdec_tp(unsigned long long iters)
{
    __m128i a[8];
    unsigned long long i;
    int j;
    for (j = 0; j < 8; j++)
        a[j] = _mm_add_epi32(_mm_loadu_si128((const __m128i *)KAT_CT), _mm_set1_epi32(j));
    for (i = 0; i < iters; i++)
        for (j = 0; j < 8; j++)
            a[j] = _mm_aesdec_si128(a[j], g_rk[3]);
    {
        __m128i s = _mm_setzero_si128();
        for (j = 0; j < 8; j++) s = _mm_xor_si128(s, a[j]);
        return ib_sig128(s);
    }
}

/* ==================== ECB-128 真实块负载(256 块=4KiB/轮; bpop=4096) ====================
 * 输入 = g_ecb_src[b] ^ tw(p): 轮序扰动 tw 依赖 p, 编译器不能把加密不变式外提出
 * p 循环(否则 tput 工作量不随 iters 增长 -> 假数据); 密文覆盖写 g_ecb 且不读回
 * (无跨轮链) -> 结果区终点只依赖末轮 -> 窗口后固定 4096 调用的签名确定可复现。 */
__attribute__((target("aes"))) static uint64_t k_ecb128(unsigned long long iters)
{
    unsigned long long p, b;
    int r;
    for (p = 0; p < iters; p++) {
        uint32_t w = (uint32_t)(p * 2654435761u + 0x9e3779b9u);
        __m128i tw = _mm_set1_epi32((int)w);
        for (b = 0; b < 256; b++) {
            __m128i x = _mm_loadu_si128((const __m128i *)(g_ecb_src + b * 16));
            x = _mm_xor_si128(x, tw);
            x = _mm_xor_si128(x, g_rk[0]);
            for (r = 1; r < 10; r++)
                x = _mm_aesenc_si128(x, g_rk[r]);
            x = _mm_aesenclast_si128(x, g_rk[10]);
            _mm_storeu_si128((__m128i *)(g_ecb + b * 16), x);
        }
    }
    return sig_mem(g_ecb, 4096);
}

/* ==================== PCLMULQDQ(target="pclmul") ==================== */
__attribute__((target("pclmul"))) static uint64_t k_pclmulqdq(unsigned long long iters)
{
    __m128i x = _mm_set_epi64x(0x123456789abcULL, 0xdeadbeefcafeULL);
    __m128i k = _mm_set_epi64x(1, 0x87ULL);
    unsigned long long i;
    for (i = 0; i < iters; i++) x = _mm_clmulepi64_si128(x, k, 0x00);
    return ib_sig128(x);
}
__attribute__((target("pclmul"))) static uint64_t k_pclmulqdq_tp(unsigned long long iters)
{
    __m128i a = _mm_set_epi64x(0x123456789abcULL, 0xdeadbeefcafeULL),
            b = _mm_set_epi64x(0x13579bdf02468aceULL, 0x1020304050607080ULL),
            c = _mm_set_epi64x(0x0f0e0d0c0b0a0908ULL, 0x1122334455667788ULL),
            d = _mm_set_epi64x(0x7f7e7d7c7b7a7978ULL, 0x8877665544332211ULL);
    __m128i k = _mm_set_epi64x(1, 0x87ULL);
    unsigned long long i;
    for (i = 0; i < iters; i++) {
        a = _mm_clmulepi64_si128(a, k, 0x00); b = _mm_clmulepi64_si128(b, k, 0x00);
        c = _mm_clmulepi64_si128(c, k, 0x00); d = _mm_clmulepi64_si128(d, k, 0x00);
    }
    return ib_sig128(a) ^ ib_sig128(b) ^ ib_sig128(c) ^ ib_sig128(d);
}

/* ==================== SHA256RNDS2(target="sha", 隐含 XMM0 传 W) ==================== */
__attribute__((target("sha"))) static uint64_t k_sha256rnds2(unsigned long long iters)
{
    __m128i abcd = _mm_set_epi64x(0x6a09e667bb67ae85ULL, 0x3c6ef372a54ff53aULL);
    __m128i efgh = _mm_set_epi64x(0x5be0cd191f83d9abULL, 0x9b5f011380deb1ULL);
    __m128i msg = _mm_set_epi64x(0x11111111ULL, 0x22222222ULL);
    unsigned long long i;
    for (i = 0; i < iters; i++) abcd = _mm_sha256rnds2_epu32(abcd, efgh, msg);
    return ib_sig128(abcd);
}
__attribute__((target("sha"))) static uint64_t k_sha256rnds2_tp(unsigned long long iters)
{
    __m128i a = _mm_set_epi64x(0x6a09e667bb67ae85ULL, 0x3c6ef372a54ff53aULL);
    __m128i b = _mm_set_epi64x(0xbb67ae856a09e667ULL, 0xa54ff53a3c6ef372ULL);
    __m128i c = _mm_set_epi64x(0x3c6ef372bb67ae85ULL, 0x510e527fade682d1ULL);
    __m128i d = _mm_set_epi64x(0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL);
    __m128i e = _mm_set_epi64x(0x5be0cd191f83d9abULL, 0x9b5f011380deb1ULL);
    __m128i msg = _mm_set_epi64x(0x11111111ULL, 0x22222222ULL);
    unsigned long long i;
    for (i = 0; i < iters; i++) {
        a = _mm_sha256rnds2_epu32(a, e, msg);
        b = _mm_sha256rnds2_epu32(b, e, msg);
        c = _mm_sha256rnds2_epu32(c, e, msg);
        d = _mm_sha256rnds2_epu32(d, e, msg);
    }
    return ib_sig128(a) ^ ib_sig128(b) ^ ib_sig128(c) ^ ib_sig128(d);
}

/* ---------------- KAT 运行器(信号保护同 ib_case_sem 模式) ---------------- */
static void run_kat(const char *grp, const char *name, ib_fn f)
{
    ib_sig_nr = 0;
    ib_intest = 1;
    if (IB_SIGSETJMP(ib_jb) == 0) {
        int ok = (int)f(1);
        ib_intest = 0;
        ib_kat(grp, name, ok ? "PASS" : "FAIL", "fips197");
        return;
    }
    ib_intest = 0;
    ib_crash(grp, name, "kat", (int)ib_sig_nr);
}

/* ---------------- 用例表(名字首段=ISA 段; aesenc/aesdec/pclmulqdq/sha256rnds2
 * 原名首段即 ISA 不叠加, 仅 ecb128 补 aes_ 前缀) ---------------- */
static const ib_case g_cases[] = {
    { "aesenc",      "aes",    k_aesenc,       k_aesenc_tp,      0, NULL, 0 },
    { "aesdec",      "aes",    k_aesdec,       k_aesdec_tp,      0, NULL, 0 },
    { "aes_ecb128",  "aes",    0,              k_ecb128,         0, NULL, 4096 },
    { "pclmulqdq",   "pclmul", k_pclmulqdq,    k_pclmulqdq_tp,   0, NULL, 0 },
    { "sha256rnds2", "sha",    k_sha256rnds2,  k_sha256rnds2_tp, 0, NULL, 0 },
};
#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

int main(int argc, char **argv)
{
    int i;
    for (i = 0; i < 256; i++) memcpy(g_ecb_src + i * 16, KAT_PT, 16);
    ib_init(argc, argv);
    ib_hdr("crypto", NCASES);
    run_kat("crypto", "aes128_keygen_kat", kat_keygen);
    run_kat("crypto", "aes128_enc_kat", kat_enc);
    run_kat("crypto", "aes128_dec_kat", kat_dec);
    ib_run_cases("crypto", g_cases, NCASES);
    return 0;
}
