/* isb_crypto.c —— isbench 组4: AES-NI / PCLMUL / SHA 加密族
 *
 * 迁移来源: aes_kat.c(FIPS-197 KAT keygen/enc/dec + 依赖链 + 8 链吞吐),
 *           insn_probe.c aesenc/aesdec/pclmulqdq/sha256rnds2 段。
 * 去重(功能测试标准 §5.1): aes_ecb128 块负载已删 —— 它与 ossl 探针的 aes-128-ecb
 *           观测面重叠且 ossl 是真实库实现, 库级 ECB 归 ossl; 本组只留“单指令”延迟/吞吐。
 * 输出契约: kat 三例走 ib_kat(PASS/FAIL + detail); 其余 lat/tput 双内核。
 * 编码纪律: target("aes"/"pclmul"/"sha") 单启 -> legacy 66 0F 38 编码
 *           (忠实 32 位 libcef); 密钥经全局 g_rk 运行时展开, 链不可闭式折叠。
 */
#include "ib_core.h"
#include "ib_buf.h"          /* KAT 输入推导(IB_KIN8) */
#include "isb_crypto_kat.h"  /* KAT 真值表(采集后生成; 未取数时全 UNSET) */

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
/* ---------------- KAT 探针(每词干一条) ----------------
 * 口径: 输入由词干哈希重导; a = (i0,i1), b = (i1, rotl(i0,13)) —— 与 vec/sse
 * 的 VIN/VIN2 同构但独立各写一遍。128 位输出 -> o0,o1; 整数/SIMD 族不碰
 * EFLAGS -> outf = 0。sha256rnds2 吃三个操作数(隐含 XMM0 传 msg), 只余 4 个
 * 输入字, 故 msg 由 abcd^efgh 导出(abcd=(i0,i1), efgh=(i2,i3))。 */
#define RB64(x, n)    (((x) >> (n)) | ((x) << (64 - (n))))
#define CR_A(sn, kk)  _mm_set_epi64x((long long)IB_KIN8(sn, kk, 1, uint64_t), \
                                     (long long)IB_KIN8(sn, kk, 0, uint64_t))
#define CR_B(sn, kk)  _mm_set_epi64x((long long)RB64(IB_KIN8(sn, kk, 0, uint64_t), 13), \
                                     (long long)IB_KIN8(sn, kk, 1, uint64_t))
#define CR_IN(sn, kk)  (g->i0 = IB_KIN8(sn, kk, 0, uint64_t), \
                        g->i1 = IB_KIN8(sn, kk, 1, uint64_t), g->inf = 0)
#define CR_OUT(r)  do { union { __m128i v_; uint64_t q[2]; } u_; u_.v_ = (r); \
                        g->o0 = u_.q[0]; g->o1 = u_.q[1]; g->outf = 0; } while (0)

__attribute__((target("aes"))) static void k_aesenc_kat(int kk, ib_kv *g)
{
    __m128i a = CR_A("aesenc", kk), b = CR_B("aesenc", kk);
    CR_IN("aesenc", kk);
    CR_OUT(_mm_aesenc_si128(a, b));
}
__attribute__((target("aes"))) static void k_aesdec_kat(int kk, ib_kv *g)
{
    __m128i a = CR_A("aesdec", kk), b = CR_B("aesdec", kk);
    CR_IN("aesdec", kk);
    CR_OUT(_mm_aesdec_si128(a, b));
}
__attribute__((target("pclmul"))) static void k_pclmulqdq_kat(int kk, ib_kv *g)
{
    __m128i a = CR_A("pclmulqdq", kk), b = CR_B("pclmulqdq", kk);
    CR_IN("pclmulqdq", kk);
    CR_OUT(_mm_clmulepi64_si128(a, b, 0x00));
}
__attribute__((target("sha"))) static void k_sha256rnds2_kat(int kk, ib_kv *g)
{
    __m128i abcd = _mm_set_epi64x((long long)IB_KIN8("sha256rnds2", kk, 1, uint64_t),
                                  (long long)IB_KIN8("sha256rnds2", kk, 0, uint64_t));
    __m128i efgh = _mm_set_epi64x((long long)IB_KIN8("sha256rnds2", kk, 3, uint64_t),
                                  (long long)IB_KIN8("sha256rnds2", kk, 2, uint64_t));
    __m128i msg = _mm_xor_si128(abcd, efgh);
    g->i0 = IB_KIN8("sha256rnds2", kk, 0, uint64_t);
    g->i1 = IB_KIN8("sha256rnds2", kk, 1, uint64_t);
    g->i2 = IB_KIN8("sha256rnds2", kk, 2, uint64_t);
    g->i3 = IB_KIN8("sha256rnds2", kk, 3, uint64_t);
    g->inf = 0;
    CR_OUT(_mm_sha256rnds2_epu32(abcd, efgh, msg));
}

static const ib_case g_cases[] = {
    { "aesenc", "aes", k_aesenc, k_aesenc_tp, 0, NULL, 0, NULL, 0,
      k_aesenc_kat, IB_KAT_aesenc, "aesenc" },
    { "aesdec", "aes", k_aesdec, k_aesdec_tp, 0, NULL, 0, NULL, 0,
      k_aesdec_kat, IB_KAT_aesdec, "aesdec" },
    { "pclmulqdq", "pclmul", k_pclmulqdq, k_pclmulqdq_tp, 0, NULL, 0, NULL, 0,
      k_pclmulqdq_kat, IB_KAT_pclmulqdq, "pclmulqdq" },
    { "sha256rnds2", "sha", k_sha256rnds2, k_sha256rnds2_tp, 0, NULL, 0, NULL, 0,
      k_sha256rnds2_kat, IB_KAT_sha256rnds2, "sha256rnds2" },
};
#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

int main(int argc, char **argv)
{
    ib_init(argc, argv);
    ib_hdr("crypto", NCASES);
    run_kat("crypto", "aes128_keygen_kat", kat_keygen);
    run_kat("crypto", "aes128_enc_kat", kat_enc);
    run_kat("crypto", "aes128_dec_kat", kat_dec);
    ib_run_cases("crypto", g_cases, NCASES);
    return 0;
}
