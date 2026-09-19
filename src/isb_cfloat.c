/* isb_cfloat.c —— isbench 组: C 数据类型算术延迟(自包含独立探针)
 *
 * 本意: 测一段 C 程序的"普通运算"(加/减/乘/除)在编译后, 落到不同数据位宽类型上
 * 的实际速度。四档统一用 C 通用类型名(不写任何内联汇编, 让编译器自己挑指令):
 *   float=32、double=64、long double=80(x86 上即 128 位存储、80 位有效的 x87 扩展,
 *   LoongArch 上 long double=128)、__float128=128(x86/LoongArch 均 libgcc 软浮点)。
 * 四类型 x {add,sub,mul,div} = 16 个 lat 用例, cname = f32_add ... f128_div。
 *
 * 为什么是"独立探针"而不复用 ib_core.h:
 *   ib_core.h/ib_buf.h 无条件含 <x86intrin.h>、__m128i/__m256i、pushfq/popfq、
 *   __attribute__((target("avx")))、cpuid 汇编 —— 即便本组一个都不调用, loongarch64
 *   交叉编译器也会因类型/内建在该架构不存在而编译失败。本组要出 loongarch64 原生
 *   静态二进制(作 LoongArch 本机基线, 与 x86-under-LATX 对照), 故自带计时与输出,
 *   只 include 纯宏、可移植的 ib_fields.h 保证列名/状态串与全仓单一口径不漂移。
 *
 * 只测 lat: 无 throughput、无功能测试(不建 verify_cfloat)、无 8 指令块、无 sem。
 * 输出走全仓 data 协议(rec=field/label/data/group), 由 isbench.py 现读现建入库到
 * 同库独立表 bench_cfloat。
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>          /* strtoull */
#include <string.h>          /* strlen/strchr/memcmp */
#include <time.h>

#include "ib_fields.h"          /* 只有宏: 列名/中文名/记录类型/状态/占位 */

/* 空 asm 内存屏障(编译器可移植: 各 gcc 目标都接受 ""), 阻断把计时循环并进前后。 */
#define CF_BARRIER() __asm__ __volatile__("" ::: "memory")

/* 单调时钟整数纳秒(与 ib_now 同口径: 全整数, 不引浮点入计时路径)。 */
static uint64_t cf_now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

/* 结果位按整型折叠成签名(FNV-1a over sizeof(T) 字节): 只用整数, 绝不做浮点->整型
 * 转换(LATX 上 fistp/浮转整有死循环坑), 且让返回值真依赖 acc 以防整条链被消除。 */
static uint64_t cf_fold(const void *p, int n)
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

/* 生成一条 lat 用例: acc 依赖链 acc = acc <op> b, 跑 iters 次取平均纳秒。
 *   - b 从 volatile 播种一次读入局部: 值编译期不可见 -> 防常量折叠/循环消除;
 *     取 1.0 使 mul/div 链恒等(a*1.0/a/1.0=a 仍是全宽运算, -fno-fast-math 下不被
 *     化简), add/sub 链只在 ±iters 整数域漂移 -> 全程规格化数, 不落入 denormal/inf
 *     (避免次正规慢路径污染"稳态延迟"这一被测对象)。
 *   - acc 是循环携带的串行浮点依赖, 无法向量化/闭式化 -> 测到的就是单条指令延迟。
 * tag: f32/f64/f80/f128; TYPE: C 类型名。 */
#define CF_LAT(TYPE, tag, op, EXPR)                                         \
static uint64_t lat_##tag##_##op(unsigned long long iters)                  \
{                                                                           \
    volatile TYPE vseed = (TYPE)1.0;                                        \
    TYPE b = vseed;                                                         \
    TYPE acc = vseed;                                                       \
    unsigned long long i;                                                   \
    for (i = 0; i < iters; i++)                                             \
        acc = (EXPR);                                                       \
    CF_BARRIER();                                                           \
    return cf_fold(&acc, (int)sizeof acc);                                  \
}

/* ---- 16 用例: 4 类型 x 4 运算 ---- */
CF_LAT(float,        f32,  add, acc + b)
CF_LAT(float,        f32,  sub, acc - b)
CF_LAT(float,        f32,  mul, acc * b)
CF_LAT(float,        f32,  div, acc / b)
CF_LAT(double,       f64,  add, acc + b)
CF_LAT(double,       f64,  sub, acc - b)
CF_LAT(double,       f64,  mul, acc * b)
CF_LAT(double,       f64,  div, acc / b)
CF_LAT(long double,  f80,  add, acc + b)
CF_LAT(long double,  f80,  sub, acc - b)
CF_LAT(long double,  f80,  mul, acc * b)
CF_LAT(long double,  f80,  div, acc / b)
CF_LAT(__float128,   f128, add, acc + b)
CF_LAT(__float128,   f128, sub, acc - b)
CF_LAT(__float128,   f128, mul, acc * b)
CF_LAT(__float128,   f128, div, acc / b)

struct cf_case {
    const char *name;
    uint64_t (*lat)(unsigned long long iters);
};
static const struct cf_case g_cases[] = {
    { "f32_add",  lat_f32_add  }, { "f32_sub",  lat_f32_sub  },
    { "f32_mul",  lat_f32_mul  }, { "f32_div",  lat_f32_div  },
    { "f64_add",  lat_f64_add  }, { "f64_sub",  lat_f64_sub  },
    { "f64_mul",  lat_f64_mul  }, { "f64_div",  lat_f64_div  },
    { "f80_add",  lat_f80_add  }, { "f80_sub",  lat_f80_sub  },
    { "f80_mul",  lat_f80_mul  }, { "f80_div",  lat_f80_div  },
    { "f128_add", lat_f128_add }, { "f128_sub", lat_f128_sub },
    { "f128_mul", lat_f128_mul }, { "f128_div", lat_f128_div },
};
#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

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

int main(int argc, char **argv)
{
    const char *abi = "x86_64", *os = "linux";
    unsigned long long iters = 200000;   /* 仅 lat, 默认 20 万次(软浮点 128 位也不慢爆) */
    const char *only = NULL;
    const char *bits;
    int i, ok = 0, tot = 0;
    char nsbuf[40];

#ifdef __i386__
    abi = "i386";
#elif defined(__loongarch64)
    abi = "loongarch64";
#endif
    {
        static char bb[8];
        snprintf(bb, sizeof bb, "%d", (int)(sizeof(void *) * 8));
        bits = bb;
    }
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--iters") && i + 1 < argc) {
            iters = strtoull(argv[++i], NULL, 0);
            if (!iters)
                iters = 200000;
        } else if (!strncmp(argv[i], "--only=", 7)) {
            only = argv[i] + 7;
        } else if (!strcmp(argv[i], "--only") && i + 1 < argc) {
            only = argv[++i];
        }
        /* 其余选项(--time / --debug / --no-xx / --reps)本组无吞吐与功能, 一律忽略。 */
    }

    /* 表头: field/label 必须同列序, 与全仓宽表列名一致(单一来源 ib_fields.h)。 */
    printf(IB_REC_FIELD "," IB_WIDE_FIELD "\n");
    printf(IB_REC_LABEL "," IB_WIDE_LABEL "\n");

    for (i = 0; i < NCASES; i++) {
        const struct cf_case *c = &g_cases[i];
        uint64_t t0, el, ns_int, frac;
        if (!name_ok(only, c->name))
            continue;
        tot++;
        t0 = cf_now();
        (void)c->lat(iters);
        el = cf_now() - t0;
        /* 平均纳秒 -> 全整数两位小数(先除后取余, 不做浮点): el/iters . (el%iters)*100/iters */
        ns_int = iters ? el / iters : el;
        frac = iters ? (el % iters) * 100ULL / iters : 0;
        snprintf(nsbuf, sizeof nsbuf, "%llu.%02llu",
                 (unsigned long long)ns_int, (unsigned long long)frac);
        /* 性能行: 只填 latency; window_sec/throughput/block8/diag 全 "-"(未测/不适用)。 */
        printf(IB_REC_DATA ",%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
               "cfloat", abi, os, bits, IB_V_NONE, c->name,
               IB_ST_OK, nsbuf,
               IB_V_NONE, IB_V_NONE, IB_V_NONE,        /* throughput_status/ops_s/mb_s */
               IB_V_NONE, IB_V_NONE,                   /* block8_status/ns */
               IB_V_NONE, IB_V_NONE, IB_V_NONE);       /* diag_status/value/unit */
        ok++;
    }
    /* 组尾行: 组名 + 通过/总数(解析侧只取组名做 done 对账)。 */
    printf(IB_REC_GROUP ",cfloat,%d,%d\n", ok, tot);
    return 0;
}
