/* isb_cint.c —— isbench 组: C 整数类型算术延迟(自包含独立探针)
 *
 * 与 isb_cfloat.c 同构(参考其设计), 只是把"浮点类型"换成"整数类型":
 *   测一段 C 程序的普通整数运算(加/减/乘/除)编译后, 落到不同位宽整数类型上的实际
 *   速度。统一用 C 通用无符号类型名(不写任何内联汇编, 让编译器自己挑指令):
 *   uint8_t=8、uint16_t=16、uint32_t=32、uint64_t=64、unsigned __int128=128。
 *   类型 x {add,sub,mul,div}: 支持 __int128 的形态(64 位)= 20 用例(i8_add ... i128_div);
 *   i386 无 __int128, 自动降到 16 用例。
 *
 * 为什么用无符号: 有符号整数的 add/sub/mul 溢出是 UB(编译器可假设不发生并据此化简,
 *   破坏"这条指令真的执行了"的测量前提), 而无符号溢出是良好定义的模 2^N 回绕 —— 依赖
 *   链 acc = acc <op> b 全程合法、编译器无法把循环折叠掉。除数 b 恒非零(volatile 播种
 *   1), 不会 #DE。窄类型(8/16)在 C 里会被整型提升成 int 再截断回本宽 —— 这正是要如实
 *   测出的"编译后真实指令"事实(与 cfloat 测软/硬浮点是同一类边界暴露), 不做掩饰。
 *
 * 为什么是"独立探针"而不复用 ib_core.h: 与 cfloat 同一理由 —— ib_core.h/ib_buf.h 含
 *   x86 专有件(<x86intrin.h>、__m128i、pushfq、target("avx")、cpuid 汇编), loongarch64
 *   交叉编译器即便不调用也会因类型不存在而编译失败。本组要出 loongarch64 原生静态二进制
 *   作本机基线, 故自带计时与输出, 只 include 纯宏、可移植的 ib_fields.h 保证列名与全仓
 *   单一口径不漂移。
 *
 * 只测 lat: 无 throughput、无功能测试(不建 verify_cint)、无 8 指令块、无 sem。
 * 形态: i386/x64 Linux + loongarch64 原生基线 + i386/x64 Windows(.exe, mingw 静态链,
 *   clock_gettime 由 winpthreads 提供 shim, 故链接需 -lpthread; 本组输出全为整数
 *   %llu/%d/%s, 无 %L, 不依赖 __USE_MINGW_ANSI_STDIO)。
 * 输出走全仓 data 协议(rec=field/label/data/group), 由 isbench.py 现读现建入库到
 * 同库独立表 bench_cint。
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>          /* strtoull */
#include <string.h>          /* strlen/strchr/memcmp */
#include <time.h>

#include "ib_fields.h"          /* 只有宏: 列名/中文名/记录类型/状态/占位 */

/* 空 asm 内存屏障(编译器可移植: 各 gcc 目标都接受 ""), 阻断把计时循环并进前后。 */
#define CI_BARRIER() __asm__ __volatile__("" ::: "memory")

/* 单调时钟整数纳秒(与 ib_now/cf_now 同口径: 全整数, 不引浮点入计时路径)。 */
static uint64_t ci_now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

/* 结果位按整型折叠成签名(FNV-1a over sizeof(T) 字节): 只用整数, 且让返回值真依赖
 * acc 以防整条链被消除。 */
static uint64_t ci_fold(const void *p, int n)
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
 *   - b 是 volatile(每轮真做一次内存读): 关键 —— 整数是可结合的, 若 b 为普通不变
 *     局部, GCC 会把 `acc=acc+b` 的计数循环强度折叠成 `acc+=b*iters`(闭式), 循环消失、
 *     测不到真加法(cfloat 的浮点因不可结合不会有此问题, 整数必须显式阻断)。volatile
 *     使操作数每轮不可知 -> SCEV 不能闭式; load 不在 acc 串行关键链上, 稳态延迟仍由
 *     目标运算主导。mul/div 用 b=1: 值恒不漂移(1*1/1/1), 但 b 是 volatile 未知量,
 *     整型恒等化简(x*1->x)用不上 -> 每轮真执行一次乘/除。全程无符号、无 UB、除数非零。
 * TYPE: 无符号整型名(uint8_t 等); tag: i8/i16/i32/i64。 */
#define CI_LAT(TYPE, tag, op, EXPR)                                           \
static uint64_t lat_##tag##_##op(unsigned long long iters)                   \
{                                                                             \
    volatile TYPE b = (TYPE)1;                                               \
    TYPE acc = b;                                                            \
    unsigned long long i;                                                    \
    for (i = 0; i < iters; i++)                                             \
        acc = (EXPR);                                                        \
    CI_BARRIER();                                                            \
    return ci_fold(&acc, (int)sizeof acc);                                   \
}

/* ---- 16 用例: 4 无符号整型 x 4 运算 ---- */
CI_LAT(uint8_t,  i8,  add, (uint8_t)(acc + b))
CI_LAT(uint8_t,  i8,  sub, (uint8_t)(acc - b))
CI_LAT(uint8_t,  i8,  mul, (uint8_t)(acc * b))
CI_LAT(uint8_t,  i8,  div, (uint8_t)(acc / b))
CI_LAT(uint16_t, i16, add, (uint16_t)(acc + b))
CI_LAT(uint16_t, i16, sub, (uint16_t)(acc - b))
CI_LAT(uint16_t, i16, mul, (uint16_t)(acc * b))
CI_LAT(uint16_t, i16, div, (uint16_t)(acc / b))
CI_LAT(uint32_t, i32, add, acc + b)
CI_LAT(uint32_t, i32, sub, acc - b)
CI_LAT(uint32_t, i32, mul, acc * b)
CI_LAT(uint32_t, i32, div, acc / b)
CI_LAT(uint64_t, i64, add, acc + b)
CI_LAT(uint64_t, i64, sub, acc - b)
CI_LAT(uint64_t, i64, mul, acc * b)
CI_LAT(uint64_t, i64, div, acc / b)

/* 128 位整数: GCC 扩展 unsigned __int128, 仅在有 TImode 支持的 64 位目标可用
 * (x86_64 / loongarch64; i386 无)。add 走 adc 双 64 位序列, mul/div 走 libgcc 软件
 * 例程(__multi3/__udivti3) —— 与 cfloat 的 f128 对偶, 测"宽到软件实现"的代价。
 * 用 __SIZEOF_INT128__ 宏门控: 缺此类型的形态(i386)整块不参与编译, 该形态自然只 16 条。 */
#ifdef __SIZEOF_INT128__
CI_LAT(unsigned __int128, i128, add, acc + b)
CI_LAT(unsigned __int128, i128, sub, acc - b)
CI_LAT(unsigned __int128, i128, mul, acc * b)
CI_LAT(unsigned __int128, i128, div, acc / b)
#endif

struct ci_case {
    const char *name;
    uint64_t (*lat)(unsigned long long iters);
};
static const struct ci_case g_cases[] = {
    { "i8_add",  lat_i8_add  }, { "i8_sub",  lat_i8_sub  },
    { "i8_mul",  lat_i8_mul  }, { "i8_div",  lat_i8_div  },
    { "i16_add", lat_i16_add }, { "i16_sub", lat_i16_sub },
    { "i16_mul", lat_i16_mul }, { "i16_div", lat_i16_div },
    { "i32_add", lat_i32_add }, { "i32_sub", lat_i32_sub },
    { "i32_mul", lat_i32_mul }, { "i32_div", lat_i32_div },
    { "i64_add", lat_i64_add }, { "i64_sub", lat_i64_sub },
    { "i64_mul", lat_i64_mul }, { "i64_div", lat_i64_div },
#ifdef __SIZEOF_INT128__
    { "i128_add", lat_i128_add }, { "i128_sub", lat_i128_sub },
    { "i128_mul", lat_i128_mul }, { "i128_div", lat_i128_div },
#endif
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
    unsigned long long iters = 200000;   /* 仅 lat, 整数很快, 默认 20 万次 */
    const char *only = NULL;
    const char *bits;
    int i, ok = 0, tot = 0;
    char nsbuf[40];

#ifdef __i386__
    abi = "i386";
#elif defined(__loongarch64)
    abi = "loongarch64";
#endif
#ifdef _WIN32
    /* mingw 形态(i686/x86_64-w64-mingw32)必须把 os 报成 windows, 与 build.sh 的
     * *_windows 形态对齐; 否则入库的 os 列会错报 linux, 与真 linux ELF 行混在一起。 */
    os = "windows";
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
        const struct ci_case *c = &g_cases[i];
        uint64_t t0, el, ns_int, frac;
        if (!name_ok(only, c->name))
            continue;
        tot++;
        t0 = ci_now();
        (void)c->lat(iters);
        el = ci_now() - t0;
        /* 平均纳秒 -> 全整数两位小数(先除后取余, 不做浮点): el/iters . (el%iters)*100/iters */
        ns_int = iters ? el / iters : el;
        frac = iters ? (el % iters) * 100ULL / iters : 0;
        snprintf(nsbuf, sizeof nsbuf, "%llu.%02llu",
                 (unsigned long long)ns_int, (unsigned long long)frac);
        /* 性能行: 只填 latency; window_sec/throughput/block8/diag 全 "-"(未测/不适用)。 */
        printf(IB_REC_DATA ",%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
               "cint", abi, os, bits, IB_V_NONE, c->name,
               IB_ST_OK, nsbuf,
               IB_V_NONE, IB_V_NONE, IB_V_NONE,        /* throughput_status/ops_s/mb_s */
               IB_V_NONE, IB_V_NONE,                   /* block8_status/ns */
               IB_V_NONE, IB_V_NONE, IB_V_NONE);       /* diag_status/value/unit */
        ok++;
    }
    /* 组尾行: 组名 + 通过/总数(解析侧只取组名做 done 对账)。 */
    printf(IB_REC_GROUP ",cint,%d,%d\n", ok, tot);
    return 0;
}
