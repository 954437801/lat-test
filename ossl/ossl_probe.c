/*
 * ossl_probe.c —— 独立 openssl 测速探针(与 src/ 指令探针无关, 不 include ib.h)
 *
 * 静态链接同形态 libcrypto.a(EVP 接口), 测各加密/摘要算法在固定块尺寸下的
 * encrypt/digest 吞吐。同一 ELF 在 box31 原生直跑、box22 经 LATX 全翻译,
 * 即 "LATX 翻译 x86 openssl 加密实现" 的性能。
 *
 * stdout 契约(3 行, 与 bench 29 列协议区分):
 *   行1 注释: "# ossl_ver=<OPENSSL_VERSION_TEXT>"
 *   行2 表头: 纯度量列名 CSV, 列名 = <EVP名'-'->'_'>_<块尺寸>, 如 aes_128_cbc_8192
 *   行3 值行: 各列 MB/s(2 位小数); 测量失败列 '-'
 * 不可用算法(探测失败)整组不出列; 库为 3.x 时 sm4-gcm 自动纳入。
 *
 * 计时纪律: 只用 clock_gettime(CLOCK_MONOTONIC) 定时长窗口, 禁 rdtsc
 * (LATX 伪造 rdtsc 会使 openssl speed 类基准失真)。
 *
 * argv: [--time S] [--sizes 16,64,...] [--algo 前缀]
 */
#define _POSIX_C_SOURCE 200809L   /* clock_gettime/strsep 声明 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

#define MAX_CANDS 64
#define MAX_SIZES 32

struct cand {
    const char *name;   /* EVP 名, 如 "aes-128-cbc" */
    const EVP_CIPHER *ci;
    const EVP_MD *md;
    int is_md;          /* 1=摘要, 0=对称加密 */
};

static const char *ciph_names[] = {
    "aes-128-ecb", "aes-128-cbc", "aes-128-ctr", "aes-128-gcm",
    "aes-192-ecb", "aes-192-cbc", "aes-192-ctr", "aes-192-gcm",
    "aes-256-ecb", "aes-256-cbc", "aes-256-ctr", "aes-256-gcm",
    "sm4-ecb", "sm4-cbc", "sm4-ctr", "sm4-gcm", "chacha20",
};
static const char *md_names[] = { "sha1", "sha256", "sha512", "sm3" };

static size_t g_sizes[MAX_SIZES];
static int g_nsizes = 0;
static double g_secs = 0.5;
static const char *g_algo_pref = NULL;
static int g_dbg_err = 0;   /* 环境变量 OSSL_PROBE_ERR=1 时 fail 路径打印 ERR 栈 */

static uint8_t g_in[16384 + 64] __attribute__((aligned(64)));
static uint8_t g_out[16384 + 512] __attribute__((aligned(64)));
static uint8_t g_key[32];
static uint8_t g_iv[16];

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* 列名: EVP 名 '-'→'_' + '_' + 尺寸, 写入 dst(静态缓冲足够) */
static void colname(char *dst, size_t dn, const char *evp, size_t sz)
{
    size_t i = 0;
    for (; *evp && i + 1 < dn; evp++) {
        char c = *evp == '-' ? '_' : *evp;
        dst[i++] = c;
    }
    snprintf(dst + i, dn - i, "_%zu", sz);
}

/* 一次定时长窗口测 encrypt 吞吐(MB/s); 失败返回 -1 */
static double measure_cipher(const EVP_CIPHER *ci, size_t sz)
{
    EVP_CIPHER_CTX *ctx = NULL;
    double t0, el;
    int outl, finl = 0;
    int ivl = EVP_CIPHER_iv_length(ci);
    const uint8_t *ivp = ivl > 0 ? g_iv : NULL;
    unsigned long it = 0;

    ERR_clear_error();
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1.0;
    if (EVP_CipherInit_ex(ctx, ci, NULL, g_key, ivp, 1) != 1)
        goto fail;
    if (EVP_CIPHER_mode(ci) == EVP_CIPH_GCM_MODE &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1)
        goto fail;
    /* 预热 ~0.15s(不计时), 使翻译/JIT/库内部一次性初始化落在窗外 */
    t0 = now_s();
    while (now_s() - t0 < 0.15) {
        if (EVP_EncryptUpdate(ctx, g_out, &outl, g_in, (int)sz) != 1)
            goto fail;
    }
    /* 正式窗口: Init 已在计时外, 循环整块 Update */
    t0 = now_s();
    while (1) {
        if (EVP_EncryptUpdate(ctx, g_out, &outl, g_in, (int)sz) != 1)
            goto fail;
        it++;
        el = now_s() - t0;
        if (el >= g_secs && it >= 2)
            break;
    }
    (void)EVP_EncryptFinal_ex(ctx, g_out, &finl);
    EVP_CIPHER_CTX_free(ctx);
    return (double)it * (double)sz / el / 1e6;

fail:
    if (g_dbg_err)
        ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);
    return -1.0;
}

/* 一次定时长窗口测 digest 吞吐(MB/s); 失败返回 -1 */
static double measure_md(const EVP_MD *md, size_t sz)
{
    EVP_MD_CTX *ctx = NULL;
    double t0, el;
    unsigned int mdsz = 0;
    unsigned long it = 0;

    ERR_clear_error();
    ctx = EVP_MD_CTX_new();
    if (!ctx)
        return -1.0;
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1)
        goto fail;
    t0 = now_s();
    while (now_s() - t0 < 0.15) {
        if (EVP_DigestUpdate(ctx, g_in, sz) != 1)
            goto fail;
    }
    t0 = now_s();
    while (1) {
        if (EVP_DigestUpdate(ctx, g_in, sz) != 1)
            goto fail;
        it++;
        el = now_s() - t0;
        if (el >= g_secs && it >= 2)
            break;
    }
    (void)EVP_DigestFinal_ex(ctx, g_out, &mdsz);
    EVP_MD_CTX_free(ctx);
    return (double)it * (double)sz / el / 1e6;

fail:
    if (g_dbg_err)
        ERR_print_errors_fp(stderr);
    EVP_MD_CTX_free(ctx);
    return -1.0;
}

int main(int argc, char **argv)
{
    struct cand cands[MAX_CANDS];
    int nc = 0, i, j;
    char cn[64];

    if (getenv("OSSL_PROBE_ERR"))
        g_dbg_err = 1;
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--time") && i + 1 < argc)
            g_secs = atof(argv[++i]);
        else if (!strcmp(argv[i], "--sizes") && i + 1 < argc) {
            char *p = argv[++i], *tok, *save = NULL;
            g_nsizes = 0;
            while ((tok = strtok_r(p, ",", &save)) != NULL &&
                   g_nsizes < MAX_SIZES) {
                g_sizes[g_nsizes++] = (size_t)atol(tok);
                p = NULL;
            }
        }
        else if (!strcmp(argv[i], "--algo") && i + 1 < argc)
            g_algo_pref = argv[++i];
        else {
            fprintf(stderr, "usage: %s [--time S] [--sizes 16,64,...] [--algo 前缀]\n",
                    argv[0]);
            return 2;
        }
    }
    if (g_nsizes == 0) {
        static const size_t def[] = { 16, 64, 256, 1024, 8192, 16384 };
        g_nsizes = (int)(sizeof(def) / sizeof(def[0]));
        for (i = 0; i < g_nsizes; i++)
            g_sizes[i] = def[i];
    }

    /* 确定性填充: 明文轮转字节; 密钥/IV 固定 */
    for (i = 0; i < (int)sizeof(g_in); i++)
        g_in[i] = (uint8_t)(i * 7 + 3);
    for (i = 0; i < (int)sizeof(g_key); i++)
        g_key[i] = (uint8_t)(0xa5 ^ (i * 13));
    for (i = 0; i < (int)sizeof(g_iv); i++)
        g_iv[i] = (uint8_t)(0x5c ^ (i * 29));

    /* 候选枚举(动态探测): cipher 组 + digest 组 */
    for (i = 0; i < (int)(sizeof(ciph_names) / sizeof(ciph_names[0])); i++) {
        const EVP_CIPHER *ci = EVP_get_cipherbyname(ciph_names[i]);
        if (!ci)
            continue;                       /* 库无此算法: 整组不出列 */
        if (g_algo_pref && strncmp(ciph_names[i], g_algo_pref, strlen(g_algo_pref)))
            continue;
        cands[nc].name = ciph_names[i];
        cands[nc].ci = ci;
        cands[nc].md = NULL;
        cands[nc].is_md = 0;
        nc++;
    }
    for (i = 0; i < (int)(sizeof(md_names) / sizeof(md_names[0])); i++) {
        const EVP_MD *md = EVP_get_digestbyname(md_names[i]);
        if (!md)
            continue;
        if (g_algo_pref && strncmp(md_names[i], g_algo_pref, strlen(g_algo_pref)))
            continue;
        cands[nc].name = md_names[i];
        cands[nc].ci = NULL;
        cands[nc].md = md;
        cands[nc].is_md = 1;
        nc++;
    }
    if (nc == 0) {
        fprintf(stderr, "no usable algorithm\n");
        return 1;
    }

    printf("# ossl_ver=%s\n", OPENSSL_VERSION_TEXT);

    /* 表头行: 纯度量列 */
    for (i = 0; i < nc; i++) {
        for (j = 0; j < g_nsizes; j++) {
            colname(cn, sizeof(cn), cands[i].name, g_sizes[j]);
            printf("%s%s", i || j ? "," : "", cn);
        }
    }
    printf("\n");
    /* 值行 */
    for (i = 0; i < nc; i++) {
        for (j = 0; j < g_nsizes; j++) {
            double v = cands[i].is_md
                ? measure_md(cands[i].md, g_sizes[j])
                : measure_cipher(cands[i].ci, g_sizes[j]);
            printf("%s%s", i || j ? "," : "",
                   v >= 0 ? "" : "-");
            if (v >= 0)
                printf("%.2f", v);
        }
    }
    printf("\n");
    return 0;
}
