/* isb_cpuid.c —— isbench 组5: CPUID 能力清单 + 探测开销
 *
 * 由两段早期探针合并而来: 冷启动首次/稳态 cpuid 开销、能力清单。
 * 冷启动首次 cpuid 必须在任何 cpuid 之前测(含翻译器/运行库冷初始化摊分);
 * 能力位判定复用 ib_cpu_ok(ib.h, GNU asm cpuid, mingw/Linux 通用)。
 */
#include "ib_core.h"

static const char *g_caps[] = {
    "sse", "sse2", "sse3", "ssse3", "sse4.1", "sse4.2", "popcnt", "movbe",
    "aes", "pclmul", "avx", "avx2", "fma", "bmi1", "bmi2", "sha", "abm"
};
#define NCAPS ((int)(sizeof(g_caps) / sizeof(g_caps[0])))

/* 稳态 cpuid 开销: 4 leaf 轮转(leaf0/1/7/0x80000001), acc 折叠防代数化简
 * 注: leaf1 EBX[31:24] = 初始 APIC ID, 多核/构建机2 下进程落不同 vCPU 即变
 * (实测同机连跑 sig 每次不同) -> 屏蔽该段, 否则 cpuid lat 签名不可复现;
 * 特性位全部保留, 跨机(真机 vs wine/LATX)差异仍会如实反映到签名。 */
static uint64_t k_cpuid_lat(unsigned long long iters)
{
    static const unsigned leafs[4] = { 0, 1, 7, 0x80000001u };
    unsigned a = 0, b = 0, c = 0, d = 0;
    uint64_t acc = 0;
    int li = 0;
    unsigned long long i;
    for (i = 0; i < iters; i++) {
        unsigned lf = leafs[li++ & 3];
        ib_cpuid(lf, 0, &a, &b, &c, &d);
        if (lf == 1)
            b &= 0x00ffffffu;    /* 去掉初始 APIC ID 段(见上注释) */
        acc = (acc << 7) | (acc >> 57);
        acc ^= (uint64_t)a ^ ((uint64_t)b << 16) ^ ((uint64_t)c << 32) ^ ((uint64_t)d << 48);
    }
    return acc;
}

static const ib_case g_cases[] = {
    { "cpuid", NULL, k_cpuid_lat, 0, 0, NULL, 0 },
};
#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

int main(int argc, char **argv)
{
    int i;
    char nb[64], dt[64];
    ib_init(argc, argv);
    ib_hdr("cpuid", NCASES);   /* 表头必须是 stdout 首行(单表 CSV 协议) */

    /* 冷启动首次 cpuid(进程内第一个 cpuid; 翻译器初始化摊分在内) */
    {
        unsigned a, b, c, d;
        uint64_t t0 = ib_now();
        ib_cpuid(0, 0, &a, &b, &c, &d);
        snprintf(nb, sizeof nb, "%.1f", (double)(ib_now() - t0));
        snprintf(dt, sizeof dt, "leaf0max=%u", a);
        ib_out("cpuid", "first_call", "diag", "OK", nb, "ns", "-", "-", "-", dt);
    }
    /* 能力清单(各 bit 存在性; 与用例表 cap 门控同一判定) */
    for (i = 0; i < NCAPS; i++)
        ib_diag("cpuid", g_caps[i], "OK", ib_cpu_ok(g_caps[i]) ? 1.0 : 0.0,
                "present", "-");
    /* 稳态 cpuid 开销(经框架 warmup 后计时) */
    ib_run_cases("cpuid", g_cases, NCASES);
    return 0;
}
