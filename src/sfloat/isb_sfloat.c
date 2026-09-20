/* isb_sfloat.c —— isbench 组: 软浮点(SoftFloat-3e)延迟与正确性(自包含独立探针)
 *
 * 被测库 = vendored 的 berkeley-softfloat-3e(third_party/softfloat-3e), 三宽度:
 *   f64(float64_t) / f80(extF80, extFloat80_t, 80 位扩展) / f128(float128_t)。对每条原语
 *   add/sub/mul/div/sqrt 测单依赖链延迟(lat); 另加 sf_f80_sin / sf_f128_sin 两条仅测速
 *   用例(用 SoftFloat 原语做 11 阶 Horner sin 多项式, 无真值, 只测"软浮点 sin 有多慢")。
 *
 * 为什么是"独立探针"而不复用 ib_core.h(与 cfloat/cint 同纪律):
 *   ib_core.h/ib_buf.h 无条件含 <x86intrin.h>、__m128i/__m256i、pushfq/popfq、
 *   __attribute__((target("avx")))、cpuid 汇编 —— 即便本组一个都不调用, loongarch64
 *   交叉编译器也会因类型/内建在该架构不存在而编译失败。本组要出 loongarch64 原生静态
 *   二进制(作 LoongArch 本机基线, 与 x86-under-LATX 对照), 故自带计时与 data/func/dbg
 *   三协议输出, 只 include 纯宏的 ib_fields.h 保证列名/状态串与全仓单一口径不漂移。
 *
 * 正确性(verify_sfloat): 对 8 个固定槽(见 isb_sfloat_slots.h)重算 SoftFloat 结果,
 *   与真值表 src/sfloat/isb_sfloat_kat.h 逐字符 memcmp -> OK/KATFAIL。真值口径:
 *     f64 <- 真 x86 SSE double; f80 <- 真 x86 x87 long double(80); f128 <- GCC __float128
 *     (libgcc soft-fp 独立第二软实现, 非硬件真值)。真值在真 x86 采集后固化, 任何形态/
 *     机器只重算 got 再比对 -> 机器无关、可复现。--debug 再吐 dbg 段(in/gold/got 位)。
 *
 * 选项: --iters(默认 200000; f128 慢)、--only(前缀匹配)、--debug。其余忽略。
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ib_fields.h"          /* 只有宏: 列名/中文名/记录类型/状态/占位 */
#include "platform.h"           /* SoftFloat 可移植配置(INT128 按 __SIZEOF_INT128__ 门控) */
#include "softfloat.h"          /* SoftFloat-3e 公共 API 与类型 */
#include "isb_sfloat_slots.h"   /* 8 槽固定输入(与真值生成器共用) */
#include "isb_sfloat_kat.h"     /* 8 槽真值表(生成物, 请勿手改) */

/* 空 asm 内存屏障(编译器可移植): 阻断把计时循环并进前后。 */
#define SF_BARRIER() __asm__ __volatile__("" ::: "memory")

/* 单调时钟整数纳秒(与全仓 ib_now 同口径: 全整数, 不引浮点入计时路径)。 */
static uint64_t sf_now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

/* 结果位按整型折叠成签名(FNV-1a over sizeof(T) 字节): 只用整数, 绝不做浮点->整型转换
 * (LATX 上浮转整有死循环坑), 且让返回值真依赖 acc 以防整条链被消除。 */
static uint64_t sf_fold(const void *p, int n)
{
    const unsigned char *b = (const unsigned char *)p;
    uint64_t h = 14695981039346656037ULL;
    int i;
    for (i = 0; i < n; i++) {
        h ^= b[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* 由 double 字面量构造各宽度种子/操作数(数值在三宽度上逐位一致)。 */
static float64_t sf_d64(double d)
{
    union { double d; uint64_t u; } s;
    s.d = d;
    return (float64_t){ s.u };
}
static extFloat80_t sf_e80(double d) { return f64_to_extF80(sf_d64(d)); }
static float128_t   sf_q128(double d) { return f64_to_f128(sf_d64(d)); }

/* ---- 测速: 二元原语, 串行依赖链 acc = FN(acc, b), 跑 iters 次 ----
 * b 由 volatile 播种 1.0 读入局部: 值编译期不可见 -> 防常量折叠/循环消除; 取 1.0 使
 * mul/div 链恒等、add/sub 链只在 ±iters 整数域漂移 -> 全程规格化数, 不落 denormal/inf。 */
#define SF_LAT_f64(tag, op, FN)                                             \
static uint64_t lat_##tag##_##op(unsigned long long iters)                  \
{                                                                           \
    volatile double vseed = 1.0;                                            \
    double d = vseed;                                                       \
    float64_t acc = sf_d64(d), b = sf_d64(d);                               \
    unsigned long long i;                                                   \
    for (i = 0; i < iters; i++)                                             \
        acc = FN(acc, b);                                                   \
    SF_BARRIER();                                                           \
    return sf_fold(&acc, (int)sizeof acc);                                  \
}
#define SF_LAT_f80(tag, op, FN)                                             \
static uint64_t lat_##tag##_##op(unsigned long long iters)                  \
{                                                                           \
    volatile double vseed = 1.0;                                            \
    double d = vseed;                                                       \
    extFloat80_t acc = sf_e80(d), b = sf_e80(d);                            \
    unsigned long long i;                                                   \
    for (i = 0; i < iters; i++)                                             \
        acc = FN(acc, b);                                                   \
    SF_BARRIER();                                                           \
    return sf_fold(&acc, (int)sizeof acc);                                  \
}
#define SF_LAT_f128(tag, op, FN)                                            \
static uint64_t lat_##tag##_##op(unsigned long long iters)                  \
{                                                                           \
    volatile double vseed = 1.0;                                            \
    double d = vseed;                                                       \
    float128_t acc = sf_q128(d), b = sf_q128(d);                            \
    unsigned long long i;                                                   \
    for (i = 0; i < iters; i++)                                             \
        acc = FN(acc, b);                                                   \
    SF_BARRIER();                                                           \
    return sf_fold(&acc, (int)sizeof acc);                                  \
}
/* ---- 测速: 一元原语(sqrt), 串行依赖链 acc = FN(acc); 种子 1.0 -> sqrt(1)=1 恒稳 ---- */
#define SF_LAT1_f64(tag, op, FN)                                            \
static uint64_t lat_##tag##_##op(unsigned long long iters)                  \
{                                                                           \
    volatile double vseed = 1.0;                                            \
    float64_t acc = sf_d64(vseed);                                          \
    unsigned long long i;                                                   \
    for (i = 0; i < iters; i++)                                             \
        acc = FN(acc);                                                      \
    SF_BARRIER();                                                           \
    return sf_fold(&acc, (int)sizeof acc);                                  \
}
#define SF_LAT1_f80(tag, op, FN)                                            \
static uint64_t lat_##tag##_##op(unsigned long long iters)                  \
{                                                                           \
    volatile double vseed = 1.0;                                            \
    extFloat80_t acc = sf_e80(vseed);                                       \
    unsigned long long i;                                                   \
    for (i = 0; i < iters; i++)                                             \
        acc = FN(acc);                                                      \
    SF_BARRIER();                                                           \
    return sf_fold(&acc, (int)sizeof acc);                                  \
}
#define SF_LAT1_f128(tag, op, FN)                                           \
static uint64_t lat_##tag##_##op(unsigned long long iters)                  \
{                                                                           \
    volatile double vseed = 1.0;                                            \
    float128_t acc = sf_q128(vseed);                                        \
    unsigned long long i;                                                   \
    for (i = 0; i < iters; i++)                                             \
        acc = FN(acc);                                                      \
    SF_BARRIER();                                                           \
    return sf_fold(&acc, (int)sizeof acc);                                  \
}

/* sin 的 11 阶 Taylor 系数: sin(x) ≈ x*(1 - x²/6 + x⁴/120 - x⁶/5040 + x⁸/362880
 * - x¹⁰/39916800)。在 |x|≲2 上尾项 ~1e-6, 够一条"每步等价成本"的软浮点多项式。 */
static const double sf_sin_c1 = -1.0 / 6.0;
static const double sf_sin_c2 =  1.0 / 120.0;
static const double sf_sin_c3 = -1.0 / 5040.0;
static const double sf_sin_c4 =  1.0 / 362880.0;
static const double sf_sin_c5 = -1.0 / 39916800.0;

/* ---- 测速: sin 多项式(Horner 11 阶), 仅测速不校验 ----
 * 迭代映射 acc <- 2*P(acc) 在 x≈1.895 有稳定不动点(2 sin 的不动点, 导数≈-0.65):
 * acc 全程停在 ~1.89~1.90, 规格化、非零、非退化, 测到的就是"一条软浮点 sin 链"的延迟。 */
#define SF_LAT_SIN_f80(tag, op)                                             \
static uint64_t lat_##tag##_##op(unsigned long long iters)                  \
{                                                                           \
    extFloat80_t c0 = sf_e80(1.0),  c1 = sf_e80(sf_sin_c1), c2 = sf_e80(sf_sin_c2); \
    extFloat80_t c3 = sf_e80(sf_sin_c3), c4 = sf_e80(sf_sin_c4), c5 = sf_e80(sf_sin_c5); \
    extFloat80_t two = sf_e80(2.0), acc = sf_e80(1.9);                      \
    unsigned long long i;                                                   \
    for (i = 0; i < iters; i++) {                                          \
        extFloat80_t x = acc, x2 = extF80_mul(x, x), p;                     \
        p = c5;                                                             \
        p = extF80_add(extF80_mul(p, x2), c4);                              \
        p = extF80_add(extF80_mul(p, x2), c3);                              \
        p = extF80_add(extF80_mul(p, x2), c2);                              \
        p = extF80_add(extF80_mul(p, x2), c1);                              \
        p = extF80_add(extF80_mul(p, x2), c0);                              \
        acc = extF80_mul(extF80_mul(x, p), two);                            \
    }                                                                       \
    SF_BARRIER();                                                           \
    return sf_fold(&acc, (int)sizeof acc);                                  \
}
#define SF_LAT_SIN_f128(tag, op)                                            \
static uint64_t lat_##tag##_##op(unsigned long long iters)                  \
{                                                                           \
    float128_t c0 = sf_q128(1.0), c1 = sf_q128(sf_sin_c1), c2 = sf_q128(sf_sin_c2); \
    float128_t c3 = sf_q128(sf_sin_c3), c4 = sf_q128(sf_sin_c4), c5 = sf_q128(sf_sin_c5); \
    float128_t two = sf_q128(2.0), acc = sf_q128(1.9);                      \
    unsigned long long i;                                                   \
    for (i = 0; i < iters; i++) {                                          \
        float128_t x = acc, x2 = f128_mul(x, x), p;                         \
        p = c5;                                                             \
        p = f128_add(f128_mul(p, x2), c4);                                  \
        p = f128_add(f128_mul(p, x2), c3);                                  \
        p = f128_add(f128_mul(p, x2), c2);                                  \
        p = f128_add(f128_mul(p, x2), c1);                                  \
        p = f128_add(f128_mul(p, x2), c0);                                  \
        acc = f128_mul(f128_mul(x, p), two);                                \
    }                                                                       \
    SF_BARRIER();                                                           \
    return sf_fold(&acc, (int)sizeof acc);                                  \
}

/* ---- 正确性: 逐槽算 got(字符串格式与真值表逐字符一致) ---- */
#define SF_GOT_f64(tag, op, FN)                                             \
static void got_##tag##_##op(int k, char *o, size_t n)                      \
{                                                                           \
    float64_t a = sf_d64(sf_slot_a[k]), b = sf_d64(sf_slot_b[k]);           \
    float64_t r = FN(a, b);                                                 \
    snprintf(o, n, "%016llx", (unsigned long long)r.v);                     \
}
#define SF_GOT1_f64(tag, op, FN)                                            \
static void got_##tag##_##op(int k, char *o, size_t n)                      \
{                                                                           \
    float64_t a = sf_d64(sf_slot_a[k]);                                     \
    float64_t r = FN(a);                                                    \
    snprintf(o, n, "%016llx", (unsigned long long)r.v);                     \
}
#define SF_GOT_f80(tag, op, FN)                                             \
static void got_##tag##_##op(int k, char *o, size_t n)                      \
{                                                                           \
    extFloat80_t r = FN(sf_e80(sf_slot_a[k]), sf_e80(sf_slot_b[k]));        \
    snprintf(o, n, "%04x_%016llx",                                          \
             (unsigned)r.signExp, (unsigned long long)r.signif);            \
}
#define SF_GOT1_f80(tag, op, FN)                                            \
static void got_##tag##_##op(int k, char *o, size_t n)                      \
{                                                                           \
    extFloat80_t r = FN(sf_e80(sf_slot_a[k]));                              \
    snprintf(o, n, "%04x_%016llx",                                          \
             (unsigned)r.signExp, (unsigned long long)r.signif);            \
}
#define SF_GOT_f128(tag, op, FN)                                            \
static void got_##tag##_##op(int k, char *o, size_t n)                      \
{                                                                           \
    float128_t r = FN(sf_q128(sf_slot_a[k]), sf_q128(sf_slot_b[k]));        \
    snprintf(o, n, "%016llx_%016llx",                                       \
             (unsigned long long)r.v[1], (unsigned long long)r.v[0]);       \
}
#define SF_GOT1_f128(tag, op, FN)                                           \
static void got_##tag##_##op(int k, char *o, size_t n)                      \
{                                                                           \
    float128_t r = FN(sf_q128(sf_slot_a[k]));                               \
    snprintf(o, n, "%016llx_%016llx",                                       \
             (unsigned long long)r.v[1], (unsigned long long)r.v[0]);       \
}

/* ---- 实例化: 15 原语(测速+校验) ---- */
SF_LAT_f64(sf_f64, add, f64_add)
SF_LAT_f64(sf_f64, sub, f64_sub)
SF_LAT_f64(sf_f64, mul, f64_mul)
SF_LAT_f64(sf_f64, div, f64_div)
SF_LAT1_f64(sf_f64, sqrt, f64_sqrt)
SF_LAT_f80(sf_f80, add, extF80_add)
SF_LAT_f80(sf_f80, sub, extF80_sub)
SF_LAT_f80(sf_f80, mul, extF80_mul)
SF_LAT_f80(sf_f80, div, extF80_div)
SF_LAT1_f80(sf_f80, sqrt, extF80_sqrt)
SF_LAT_f128(sf_f128, add, f128_add)
SF_LAT_f128(sf_f128, sub, f128_sub)
SF_LAT_f128(sf_f128, mul, f128_mul)
SF_LAT_f128(sf_f128, div, f128_div)
SF_LAT1_f128(sf_f128, sqrt, f128_sqrt)

SF_GOT_f64(sf_f64, add, f64_add)
SF_GOT_f64(sf_f64, sub, f64_sub)
SF_GOT_f64(sf_f64, mul, f64_mul)
SF_GOT_f64(sf_f64, div, f64_div)
SF_GOT1_f64(sf_f64, sqrt, f64_sqrt)
SF_GOT_f80(sf_f80, add, extF80_add)
SF_GOT_f80(sf_f80, sub, extF80_sub)
SF_GOT_f80(sf_f80, mul, extF80_mul)
SF_GOT_f80(sf_f80, div, extF80_div)
SF_GOT1_f80(sf_f80, sqrt, extF80_sqrt)
SF_GOT_f128(sf_f128, add, f128_add)
SF_GOT_f128(sf_f128, sub, f128_sub)
SF_GOT_f128(sf_f128, mul, f128_mul)
SF_GOT_f128(sf_f128, div, f128_div)
SF_GOT1_f128(sf_f128, sqrt, f128_sqrt)

/* ---- 实例化: 2 超越(仅测速) ---- */
SF_LAT_SIN_f80(sf_f80, sin)
SF_LAT_SIN_f128(sf_f128, sin)

struct sf_case {
    const char *name;
    uint64_t (*lat)(unsigned long long iters);
    const char *const *gold;                 /* NULL = 仅测速(无真值) */
    void (*got)(int k, char *o, size_t n);
};
static const struct sf_case g_cases[] = {
    { "sf_f64_add",  lat_sf_f64_add,  gold_sf_f64_add,  got_sf_f64_add  },
    { "sf_f64_sub",  lat_sf_f64_sub,  gold_sf_f64_sub,  got_sf_f64_sub  },
    { "sf_f64_mul",  lat_sf_f64_mul,  gold_sf_f64_mul,  got_sf_f64_mul  },
    { "sf_f64_div",  lat_sf_f64_div,  gold_sf_f64_div,  got_sf_f64_div  },
    { "sf_f64_sqrt", lat_sf_f64_sqrt, gold_sf_f64_sqrt, got_sf_f64_sqrt },
    { "sf_f80_add",  lat_sf_f80_add,  gold_sf_f80_add,  got_sf_f80_add  },
    { "sf_f80_sub",  lat_sf_f80_sub,  gold_sf_f80_sub,  got_sf_f80_sub  },
    { "sf_f80_mul",  lat_sf_f80_mul,  gold_sf_f80_mul,  got_sf_f80_mul  },
    { "sf_f80_div",  lat_sf_f80_div,  gold_sf_f80_div,  got_sf_f80_div  },
    { "sf_f80_sqrt", lat_sf_f80_sqrt, gold_sf_f80_sqrt, got_sf_f80_sqrt },
    { "sf_f128_add",  lat_sf_f128_add,  gold_sf_f128_add,  got_sf_f128_add  },
    { "sf_f128_sub",  lat_sf_f128_sub,  gold_sf_f128_sub,  got_sf_f128_sub  },
    { "sf_f128_mul",  lat_sf_f128_mul,  gold_sf_f128_mul,  got_sf_f128_mul  },
    { "sf_f128_div",  lat_sf_f128_div,  gold_sf_f128_div,  got_sf_f128_div  },
    { "sf_f128_sqrt", lat_sf_f128_sqrt, gold_sf_f128_sqrt, got_sf_f128_sqrt },
    { "sf_f80_sin",   lat_sf_f80_sin,   NULL, NULL },
    { "sf_f128_sin",  lat_sf_f128_sin,  NULL, NULL },
};
#define SF_NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

/* --only 前缀匹配(逗号分隔多前缀); 无 --only = 全跑。 */
static int name_ok(const char *only, const char *name)
{
    size_t nl;
    if (!only || !*only)
        return 1;
    nl = strlen(name);
    while (*only) {
        const char *c = strchr(only, ',');
        size_t pl = c ? (size_t)(c - only) : strlen(only);
        if (pl && pl <= nl && !memcmp(only, name, pl))
            return 1;
        if (!c)
            break;
        only = c + 1;
    }
    return 0;
}

/* ==== BEGIN fn=sf_kat ==== */
/* 逐槽重算 SoftFloat 结果并与真值表 memcmp; 全 8 槽一致返回 IB_V_TRUE, 否则 IB_V_FALSE。 */
static const char *sf_kat(const struct sf_case *c)
{
    int k;
    char got[48];
    if (!c->gold || !c->got)
        return IB_V_NONE;
    for (k = 0; k < SF_KAT_N; k++) {
        c->got(k, got, sizeof got);
        if (strcmp(got, c->gold[k]) != 0)
            return IB_V_FALSE;
    }
    return IB_V_TRUE;
}
/* ==== END fn=sf_kat ==== */

int main(int argc, char **argv)
{
    const char *abi = "x86_64", *os = "linux", *only = NULL;
    unsigned long long iters = 200000;   /* 软浮点默认可小些(f128 慢) */
    int i, ok = 0, tot = 0, do_debug = 0;
    char bitsbuf[8];
    const char *bits;
    struct { const char *name; const char *val; } feats[SF_NCASES];
    int nf = 0;

#ifdef __i386__
    abi = "i386";
#elif defined(__loongarch64)
    abi = "loongarch64";
#endif
#ifdef _WIN32
    os = "windows";
#endif
    snprintf(bitsbuf, sizeof bitsbuf, "%d", (int)(sizeof(void *) * 8));
    bits = bitsbuf;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--iters") && i + 1 < argc) {
            iters = strtoull(argv[++i], NULL, 0);
            if (!iters)
                iters = 200000;
        } else if (!strncmp(argv[i], "--only=", 7)) {
            only = argv[i] + 7;
        } else if (!strcmp(argv[i], "--only") && i + 1 < argc) {
            only = argv[++i];
        } else if (!strcmp(argv[i], "--debug")) {
            do_debug = 1;
        }
        /* 其余选项(--time/--no-xx/--reps)本组无吞吐/8链, 一律忽略。 */
    }

    /* 固化软浮点环境: round-to-nearest-even + 80 位扩展精度 + 帧后检测下溢(与硬件口径一致)。
     * 必须在任何运算前设置。 */
    softfloat_roundingMode    = softfloat_round_near_even;
    softfloat_detectTininess  = softfloat_tininess_afterRounding;
    extF80_roundingPrecision  = 80;

    /* 不入库的环境事实(首列 info, 解析器不认, 仅原始日志可见)。 */
    printf("info,env,abi=%s,lib=berkeley-softfloat-3e,round=near_even,extF80_prec=80\n", abi);

    printf(IB_REC_FIELD "," IB_WIDE_FIELD "\n");
    printf(IB_REC_LABEL "," IB_WIDE_LABEL "\n");

    for (i = 0; i < SF_NCASES; i++) {
        const struct sf_case *c = &g_cases[i];
        uint64_t t0, el, ns_int, frac;
        char nsbuf[40];

        if (!name_ok(only, c->name))
            continue;
        tot++;

        t0 = sf_now();
        (void)c->lat(iters);
        el = sf_now() - t0;
        /* 平均纳秒 -> 全整数两位小数(先除后取余, 不做浮点): el/iters . (el%iters)*100/iters */
        ns_int = iters ? el / iters : el;
        frac = iters ? (el % iters) * 100ULL / iters : 0;
        snprintf(nsbuf, sizeof nsbuf, "%llu.%02llu",
                 (unsigned long long)ns_int, (unsigned long long)frac);

        /* 性能行: 只填 latency; 其余列 "-"(本组无吞吐/8链/环境自描述)。 */
        printf(IB_REC_DATA ",%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
               "sfloat", abi, os, bits, IB_V_NONE, c->name,
               IB_ST_OK, nsbuf,
               IB_V_NONE, IB_V_NONE, IB_V_NONE,       /* throughput_status/ops_s/mb_s */
               IB_V_NONE, IB_V_NONE,                  /* block8_status/ns */
               IB_V_NONE, IB_V_NONE, IB_V_NONE);      /* diag_status/value/unit */
        ok++;

        feats[nf].name = c->name;
        feats[nf].val = sf_kat(c);
        nf++;
    }

    /* 功能段(func): 一组一行, 列 = 本组每个功能(用例名), 值 true/false/-。整段连续吐,
     * 列名现读现建 -> verify_sfloat。 */
    if (nf) {
        printf(IB_REC_FIELD "," IB_FUNC_FIELD);
        for (i = 0; i < nf; i++)
            printf(",%s", feats[i].name);
        printf("\n");
        printf(IB_REC_LABEL "," IB_FUNC_LABEL);
        for (i = 0; i < nf; i++)
            printf(",%s", feats[i].name);
        printf("\n");
        printf(IB_REC_FUNC ",sfloat,%s", abi);
        for (i = 0; i < nf; i++)
            printf(",%s", feats[i].val);
        printf("\n");
    }

    /* 详细段(dbg, 仅 --debug): 逐 (用例, 真值槽 kk) 一条 src=exp + 一条 src=got。
     * i0/i1 = 输入位(double 位型), o0 = 结果位(各宽度规范串), 与真值/实测并排。 */
    if (do_debug) {
        int ci, k, have = 0;
        for (ci = 0; ci < SF_NCASES; ci++)
            if (g_cases[ci].gold && name_ok(only, g_cases[ci].name))
                have = 1;
        if (have) {
            printf(IB_REC_FIELD "," IB_DBG_FIELD "\n");
            printf(IB_REC_LABEL "," IB_DBG_LABEL "\n");
            for (ci = 0; ci < SF_NCASES; ci++) {
                const struct sf_case *c = &g_cases[ci];
                if (!c->gold || !name_ok(only, c->name))
                    continue;
                for (k = 0; k < SF_KAT_N; k++) {
                    union { double d; uint64_t u; } ua, ub;
                    char inA[20], inB[20], got[48];
                    ua.d = sf_slot_a[k];
                    ub.d = sf_slot_b[k];
                    snprintf(inA, sizeof inA, "%016llx", (unsigned long long)ua.u);
                    snprintf(inB, sizeof inB, "%016llx", (unsigned long long)ub.u);
                    c->got(k, got, sizeof got);
                    printf(IB_REC_DBG ",sfloat,%s,%s,sf,%d,%s,%s,-,-,-,%s,-,-,-,-,exp\n",
                           abi, c->name, k, inA, inB, c->gold[k]);
                    printf(IB_REC_DBG ",sfloat,%s,%s,sf,%d,%s,%s,-,-,-,%s,-,-,-,-,got\n",
                           abi, c->name, k, inA, inB, got);
                }
            }
        }
    }

    /* 组尾行: 组名 + 通过/总数(解析侧只取组名做 done 对账)。 */
    printf(IB_REC_GROUP ",sfloat,%d,%d\n", ok, tot);
    return 0;
}
