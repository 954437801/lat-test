/* ib_core.h —— isbench 最小公共层(所有 isb_*.c 必须 include 的唯一头)
 *
 * 职责: 运行参数 + 计时 + 信号兜底 + CPUID + 宽行输出 + ib_case 运行器 + KAT 比对。
 * 不含: 缓冲区/种子/内核模板(需要时 include "ib_buf.h")。
 */
#ifndef ISB_IB_CORE_H
#define ISB_IB_CORE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <time.h>
#include <x86intrin.h>
#include "ib_fields.h"

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#define IB_SIGSETJMP(e)   setjmp(e)
#define IB_SIGLONGJMP(e,v) longjmp(e, v)
typedef jmp_buf ib_jmp_t;
#else
#include <unistd.h>
#define IB_SIGSETJMP(e)   sigsetjmp(e, 1)
#define IB_SIGLONGJMP(e,v) siglongjmp(e, v)
typedef sigjmp_buf ib_jmp_t;
#endif

/* 用例内核的迭代计数与本机字长:
 *   内核形参(ib_fn)与循环计数器统一取"本机字长" —— i386=32 / x64、loongarch64=64。
 *   若取 64 位, i386 上每轮要多一条 `add $1,%eax; adc $0,%edx`(进位对), 在旗标写昂贵
 *   的 i386 路径上会把整轮延迟钉在脚手架地板(实测 3.91ns)上, 被测指令的真实延迟
 *   被淹没(见 src/cint 的实测与报告 §17)。测量/累加算术(ops/total_iters/it_max
 *   等)仍留 64 位。 */
typedef uintptr_t ib_uw;
#define IB_UW_MAX ((unsigned long long)(ib_uw)-1)

/* ==================== 运行参数 ==================== */
extern int g_tput_ms;
extern unsigned long long g_lat_iters;
extern int g_do_lat, g_do_tput, g_do_sem, g_do_b8;
extern int g_verify;
extern int g_debug;
extern const char *g_only;
extern const char *g_abi, *g_os;
static int g_list_cases;   /* --list: 只列用例(名字+能力门控), 不跑测试 */
static int g_gen_gold;     /* --gen-gold: 采集态(忽略表, 逐槽吐 got 供收割) */

/* ==================== 计时 ==================== */
/* 返回单调时钟的整数纳秒。刻意不用 double: 一是 i386 上 double 往返走 x87/ST(0),
 * 二是 LATX 翻译层对浮点互转代价高 —— 计时/控制流(累加、比较、循环条件)全用整数。 */
static inline uint64_t ib_now(void)
{
#ifdef _WIN32
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    /* QPC 计数 -> 纳秒: 先除再取余, 避免 c*1e9 溢出; 全整数运算 */
    return (uint64_t)(c.QuadPart / f.QuadPart) * 1000000000ULL
         + (uint64_t)(c.QuadPart % f.QuadPart) * 1000000000ULL
           / (uint64_t)f.QuadPart;
#else
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
#endif
}

#define IB_BARRIER() asm volatile("" ::: "memory")

/* ==================== 签名聚合 ==================== */
static inline uint64_t ib_sig128(__m128i v)
{
    uint64_t h[2];
    _mm_storeu_si128((__m128i *)h, v);
    return h[0] ^ h[1];
}
__attribute__((target("avx"))) static inline uint64_t ib_sig256(__m256i v)
{
    uint64_t h[4];
    _mm256_storeu_si256((__m256i *)h, v);
    return h[0] ^ h[1] ^ h[2] ^ h[3];
}

/* ==================== 宽行输出 ====================
 * 行 key = case(指令); lat/tput/sem/kat/diag 各测试方式在同一行的列中。
 * 两种模式:
 *   行缓冲(ib_row_mode=1): ib_lat/ib_tput/ib_sem/ib_unsup 只写结果槽,
 *     由 ib_run_case 在 case 尾调 ib_flush() 输出 1 行宽 CSV;
 *   立即(直接调用场景: crypto KAT / cpuid,timer 的 diag 等): 写槽后立即 flush。 */
enum { WV_LAT_ST, WV_LAT_NS, WV_LAT_SIG, WV_TPUT_ST, WV_TPUT_OPS,
       WV_TPUT_MBS, WV_TPUT_SIG, WV_B8_ST, WV_B8_NS, WV_B8_SIG,
       WV_SEM_ST, WV_SEM_SIG, WV_SEM_TAG,
       WV_KAT_ST, WV_KAT_DET, WV_DIAG_ST, WV_DIAG_V, WV_DIAG_U, WV_DIAG_DET,
       WV_LAT_ITERS };
#define IB_WV_N (WV_LAT_ITERS + 1)
static char ib_wv[IB_WV_N][40];
static char ib_wgrp[24], ib_wcase[48];
static int ib_row_mode = 0;

static void ib_wreset(void)
{
    int i;
    ib_wgrp[0] = ib_wcase[0] = '\0';
    for (i = 0; i < IB_WV_N; i++)
        ib_wv[i][0] = '\0';
}
static void ib_wset(int idx, const char *v)
{
    snprintf(ib_wv[idx], sizeof ib_wv[idx], "%s", v && *v ? v : IB_V_NONE);
}
static const char *ib_wget(int idx)
{
    return ib_wv[idx][0] ? ib_wv[idx] : IB_V_NONE;
}

/* ==================== 功能段(func) 与 详细段(dbg) ====================
 * 一次 exec 的输出分三段, 每段自成一整块(field/label 起头):
 *   性能段 data 行  每"功能"一行, 只放指标+状态(IB_WIDE_FIELD);
 *   功能段 func 行  一组一行, 列 = 该组每个功能, 值 true/false/-(IB_FUNC_FIELD);
 *   详细段 dbg 行   逐 (用例, 真值槽) 的 in/gold/got 明细, 仅 --debug 时才吐。
 * 功能段与详细段都在组尾一次性吐出 —— 段的 field 行必须整段连续, 插在 data 行中间
 * 会把后续 data 行按错列解析(解析侧是按 field 行分段的)。
 * 单行的功能判定: 有 kat 看 kat(OK/PASS=true, FAIL/KATFAIL/CRASH=false); 否则有
 * diag 看 diag(diag_status==OK); 两者都无 = "-"(不进本组功能表)。 */
#define IB_FUNC_MAX 512
static char ib_fname[IB_FUNC_MAX][48];
static char ib_fval[IB_FUNC_MAX][6];
static int ib_fcnt;
static char *ib_dbg_buf;
static size_t ib_dbg_len, ib_dbg_cap;

static const char *ib_func_verdict(void)
{
    const char *k = ib_wv[WV_KAT_ST];

    if (k[0]) {
        if (!strcmp(k, IB_ST_OK) || !strcmp(k, IB_ST_PASS))
            return IB_V_TRUE;
        if (!strcmp(k, IB_ST_FAIL) || !strcmp(k, IB_ST_KATFAIL) ||
            !strcmp(k, IB_ST_CRASH) || !strcmp(k, IB_ST_INMISMATCH))
            return IB_V_FALSE;
        return IB_V_NONE;
    }
    if (ib_wv[WV_DIAG_ST][0])
        return strcmp(ib_wv[WV_DIAG_ST], IB_ST_OK) ? IB_V_FALSE : IB_V_TRUE;
    return IB_V_NONE;
}
static void ib_func_add(const char *name, const char *val)
{
    int i;

    if (!name || !*name)
        return;
    for (i = 0; i < ib_fcnt; i++) {
        if (!strcmp(ib_fname[i], name)) {
            snprintf(ib_fval[i], sizeof ib_fval[i], "%s", val);
            return;
        }
    }
    if (ib_fcnt >= IB_FUNC_MAX)
        return;                    /* 满了就丢, 不崩主流程 */
    snprintf(ib_fname[ib_fcnt], sizeof ib_fname[0], "%s", name);
    snprintf(ib_fval[ib_fcnt], sizeof ib_fval[0], "%s", val);
    ib_fcnt++;
}
static void ib_func_emit(const char *grp)
{
    int i;

    if (!ib_fcnt)
        return;
    printf(IB_REC_FIELD "," IB_FUNC_FIELD);
    for (i = 0; i < ib_fcnt; i++)
        printf(",%s", ib_fname[i]);
    printf("\n");
    printf(IB_REC_LABEL "," IB_FUNC_LABEL);
    for (i = 0; i < ib_fcnt; i++)
        printf(",%s", ib_fname[i]);
    printf("\n");
    printf(IB_REC_FUNC ",%s,%s", grp, g_abi);
    for (i = 0; i < ib_fcnt; i++)
        printf(",%s", ib_fval[i]);
    printf("\n");
    fflush(stdout);
}
static void ib_dbg_put(const char *line)
{
    size_t n = strlen(line);

    if (ib_dbg_len + n + 1 > ib_dbg_cap) {
        size_t nc = ib_dbg_cap ? ib_dbg_cap * 2 : 8192;
        char *p;

        while (nc < ib_dbg_len + n + 1)
            nc *= 2;
        p = (char *)realloc(ib_dbg_buf, nc);
        if (!p)
            return;                /* OOM: 丢明细, 不崩主流程 */
        ib_dbg_buf = p;
        ib_dbg_cap = nc;
    }
    memcpy(ib_dbg_buf + ib_dbg_len, line, n);
    ib_dbg_len += n;
}
static void ib_dbg_emit(const char *field, const char *label)
{
    if (!g_debug || !ib_dbg_len)
        return;
    printf("%s,%s\n", IB_REC_FIELD, field);
    printf("%s,%s\n", IB_REC_LABEL, label);
    fwrite(ib_dbg_buf, 1, ib_dbg_len, stdout);
    ib_dbg_len = 0;
    fflush(stdout);
}

/* 本用例是否有任何一个"数据指标"被实际记录(latency/throughput/block8/diag 至少一列非空)。
 * 关掉 --no-lat/--no-tput/--no-b8 后, 某用例可能一列数据都没跑 -> ib_flush 不再吐它的
 * data 行(不删列, 只是"没测的用例不输出")。有状态但无值也算测过: ib_lat/ib_unsup 会写
 * *_ST(HOSTUNSUPPORTED/CRASH 也非空), 故仍会输出。KAT/sem 不占数据列, 其判定走 func 段。 */
static int ib_data_has_metric(void)
{
    static const int metric[] = { WV_LAT_ST, WV_LAT_NS, WV_TPUT_ST, WV_TPUT_OPS,
                                  WV_TPUT_MBS, WV_B8_ST, WV_B8_NS,
                                  WV_DIAG_ST, WV_DIAG_V, WV_DIAG_U };
    unsigned i;
    for (i = 0; i < sizeof metric / sizeof metric[0]; i++)
        if (ib_wv[metric[i]][0] != '\0')
            return 1;
    return 0;
}

/* 性能段 field/label 表头是否已打: 延后到确有第一条数据行时打一次(见 ib_flush)。
 * 若本次 --no-lat/--no-tput/--no-b8 把一个数据指标都没留下, 整个 data 段(含表头)
 * 一行都不输出。列不删: 有数据时仍是固定全列。 */
static int ib_data_hdr_done = 0;

static void ib_flush(void)
{
    ib_func_add(ib_wcase, ib_func_verdict());
    if (!ib_data_has_metric()) {   /* 一个数据指标都没跑: 跳过本用例的 data 行 */
        ib_wreset();
        return;
    }
    if (!ib_data_hdr_done) {       /* 首条数据行前补打性能段表头(列保留, 全列) */
        printf(IB_REC_FIELD "," IB_WIDE_FIELD "\n");
        printf(IB_REC_LABEL "," IB_WIDE_LABEL "\n");
        ib_data_hdr_done = 1;
    }
    printf(IB_REC_DATA ",%s,%s,%s,%d,%.3f,%s,"
           "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
           ib_wgrp[0] ? ib_wgrp : IB_V_NONE, g_abi, g_os,
           (int)(sizeof(void *) * 8), (double)g_tput_ms / 1000.0,
           ib_wcase[0] ? ib_wcase : IB_V_NONE,
           ib_wget(WV_LAT_ST), ib_wget(WV_LAT_NS),
           ib_wget(WV_TPUT_ST), ib_wget(WV_TPUT_OPS), ib_wget(WV_TPUT_MBS),
           ib_wget(WV_B8_ST), ib_wget(WV_B8_NS),
           ib_wget(WV_DIAG_ST), ib_wget(WV_DIAG_V), ib_wget(WV_DIAG_U));
    ib_wreset();
}

void ib_flush_always(void) { ib_flush(); }

void ib_lat(const char *grp, const char *name, const char *st, double ns,
            uint64_t sig, const char *detail)
{
    (void)detail;
    snprintf(ib_wgrp, sizeof ib_wgrp, "%s", grp ? grp : "");
    snprintf(ib_wcase, sizeof ib_wcase, "%s", name ? name : "");
    ib_wset(WV_LAT_ST, st);
    snprintf(ib_wv[WV_LAT_NS], sizeof ib_wv[WV_LAT_NS], "%.2f", ns);
    snprintf(ib_wv[WV_LAT_SIG], sizeof ib_wv[WV_LAT_SIG], "%016llx",
             (unsigned long long)sig);
}
void ib_tput(const char *grp, const char *name, const char *st,
             double v1, const char *u1, double v2, const char *u2,
             uint64_t sig, const char *detail)
{
    (void)u1; (void)u2; (void)detail;
    snprintf(ib_wgrp, sizeof ib_wgrp, "%s", grp ? grp : "");
    snprintf(ib_wcase, sizeof ib_wcase, "%s", name ? name : "");
    ib_wset(WV_TPUT_ST, st);
    snprintf(ib_wv[WV_TPUT_OPS], sizeof ib_wv[WV_TPUT_OPS], "%.2f", v1);
    if (v2 > 0)
        snprintf(ib_wv[WV_TPUT_MBS], sizeof ib_wv[WV_TPUT_MBS], "%.2f", v2);
    else
        ib_wv[WV_TPUT_MBS][0] = '\0';
    snprintf(ib_wv[WV_TPUT_SIG], sizeof ib_wv[WV_TPUT_SIG], "%016llx",
             (unsigned long long)sig);
}
void ib_b8(const char *grp, const char *name, const char *st,
           double ns, uint64_t sig, const char *detail)
{
    (void)detail;
    snprintf(ib_wgrp, sizeof ib_wgrp, "%s", grp ? grp : "");
    snprintf(ib_wcase, sizeof ib_wcase, "%s", name ? name : "");
    ib_wset(WV_B8_ST, st);
    snprintf(ib_wv[WV_B8_NS], sizeof ib_wv[WV_B8_NS], "%.2f", ns);
    snprintf(ib_wv[WV_B8_SIG], sizeof ib_wv[WV_B8_SIG], "%016llx",
             (unsigned long long)sig);
}
void ib_sem(const char *grp, const char *name, const char *st,
            uint64_t sig, const char *detail)
{
    snprintf(ib_wgrp, sizeof ib_wgrp, "%s", grp ? grp : "");
    snprintf(ib_wcase, sizeof ib_wcase, "%s", name ? name : "");
    ib_wset(WV_SEM_ST, st);
    snprintf(ib_wv[WV_SEM_SIG], sizeof ib_wv[WV_SEM_SIG], "%016llx",
             (unsigned long long)sig);
    if (detail && *detail)
        snprintf(ib_wv[WV_SEM_TAG], sizeof ib_wv[WV_SEM_TAG], "%s", detail);
}
void ib_unsup(const char *grp, const char *name, const char *metric,
              const char *cap)
{
    int idx = !strcmp(metric, "tput") ? WV_TPUT_ST :
              !strcmp(metric, "block8") ? WV_B8_ST :
              !strcmp(metric, "sem")  ? WV_SEM_ST : WV_LAT_ST;
    (void)cap;
    snprintf(ib_wgrp, sizeof ib_wgrp, "%s", grp ? grp : "");
    snprintf(ib_wcase, sizeof ib_wcase, "%s", name ? name : "");
    ib_wset(idx, IB_ST_UNSUPPORTED);
}

void ib_out(const char *grp, const char *name, const char *metric, const char *st,
            const char *v1, const char *v1u, const char *v2, const char *v2u,
            const char *sig, const char *detail)
{
    (void)metric; (void)v2; (void)v2u; (void)sig;
    snprintf(ib_wgrp, sizeof ib_wgrp, "%s", grp ? grp : "");
    snprintf(ib_wcase, sizeof ib_wcase, "%s", name ? name : "");
    ib_wset(WV_DIAG_ST, st);
    ib_wset(WV_DIAG_V, v1);
    ib_wset(WV_DIAG_U, v1u);
    ib_wset(WV_DIAG_DET, detail);
    ib_flush();
}
void ib_kat(const char *grp, const char *name, const char *st,
            const char *detail)
{
    snprintf(ib_wgrp, sizeof ib_wgrp, "%s", grp ? grp : "");
    snprintf(ib_wcase, sizeof ib_wcase, "%s", name ? name : "");
    ib_wset(WV_KAT_ST, st);
    ib_wset(WV_KAT_DET, detail);
    if (!ib_row_mode)
        ib_flush();
}
void ib_diag(const char *grp, const char *name, const char *st,
             double v, const char *u, const char *detail)
{
    char a[40];
    snprintf(ib_wgrp, sizeof ib_wgrp, "%s", grp ? grp : "");
    snprintf(ib_wcase, sizeof ib_wcase, "%s", name ? name : "");
    ib_wset(WV_DIAG_ST, st);
    snprintf(a, sizeof a, "%.3f", v);
    ib_wset(WV_DIAG_V, a);
    ib_wset(WV_DIAG_U, u);
    ib_wset(WV_DIAG_DET, detail);
    ib_flush();
}
void ib_hdr(const char *grp, int ncases)
{
    (void)grp; (void)ncases;
    if (g_list_cases)
        return;      /* --list 只列用例, 不吐表头 */
    /* 性能段 field/label 不在此急打: 改由 ib_flush 在"确有第一条数据行"时打一次。
     * 这样 --no-lat --no-tput --no-b8(一个数据指标都没跑)时, 整个 data 段连表头都不输出。
     * 列不删: 只要有数据就是固定全列。func/dbg 段各自在 ib_done 打自己的表头。 */
    ib_data_hdr_done = 0;
    ib_wreset();
    ib_fcnt = 0;
    ib_dbg_len = 0;
}

/* 组尾行: 组名 + 通过/总数; 随后把本组的功能段(func)与详细段(dbg, 仅 --debug)整段
 * 吐出。组尾行不再按性能表列数补齐 —— 解析侧只从它取组名(ok/total 不入库)。 */
void ib_done(const char *grp, int ok, int tot)
{
    printf(IB_REC_GROUP ",%s,%d,%d\n", grp, ok, tot);
    ib_func_emit(grp);
    ib_dbg_emit(IB_DBG_FIELD, IB_DBG_LABEL);
}

/* ==================== 信号兜底 ==================== */
static ib_jmp_t ib_jb;
static volatile sig_atomic_t ib_intest = 0;
static volatile sig_atomic_t ib_sig_nr = 0;
#ifdef _WIN32
static const char *ib_cur_grp, *ib_cur_name, *ib_cur_metric;
static void ib_cur_set(const char *g, const char *n, const char *m)
{
    ib_cur_grp = g; ib_cur_name = n; ib_cur_metric = m;
}
#endif

static void ib_on_sig(int s)
{
    if (ib_intest) {
        ib_sig_nr = s;
        IB_SIGLONGJMP(ib_jb, 1);
    }
}

void ib_crash(const char *grp, const char *name, const char *metric, int sig_nr);

#ifdef _WIN32
static LONG WINAPI ib_veh(PEXCEPTION_POINTERS ep)
{
    unsigned code = ep->ExceptionRecord->ExceptionCode;
    int sig = 0;
    switch (code) {
    case EXCEPTION_ILLEGAL_INSTRUCTION: sig = 4; break;
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: sig = 11; break;
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_FLT_DIVIDE_BY_ZERO: sig = 8; break;
    default: return EXCEPTION_CONTINUE_SEARCH;
    }
    if (ib_intest && ib_cur_name) {
        ib_crash(ib_cur_grp ? ib_cur_grp : "?", ib_cur_name,
                 ib_cur_metric ? ib_cur_metric : "lat", sig);
        ib_flush_always();
        fflush(stdout);
        ExitProcess(2);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif

void ib_crash(const char *grp, const char *name, const char *metric, int sig_nr)
{
    int idx = !strcmp(metric, "tput") ? WV_TPUT_ST :
              !strcmp(metric, "block8") ? WV_B8_ST :
              !strcmp(metric, "sem")  ? WV_SEM_ST :
              !strcmp(metric, "kat")  ? WV_KAT_ST :
              !strcmp(metric, "diag") ? WV_DIAG_ST : WV_LAT_ST;
    snprintf(ib_wgrp, sizeof ib_wgrp, "%s", grp ? grp : "");
    snprintf(ib_wcase, sizeof ib_wcase, "%s", name ? name : "");
    ib_wset(idx, IB_ST_CRASH);
    if (!ib_row_mode)
        ib_flush();
}

#define IB_TRY(grp, name, metric, bad, BODY) do {                             \
        ib_cur_grp = (grp); ib_cur_name = (name); ib_cur_metric = (metric);   \
        ib_sig_nr = 0;                                                        \
        ib_intest = 1;                                                        \
        if (IB_SIGSETJMP(ib_jb) == 0) {                                       \
            BODY                                                              \
        } else {                                                              \
            ib_intest = 0;                                                    \
            ib_crash((grp), (name), (metric), (int)ib_sig_nr);                \
            (bad) = 1;                                                        \
        }                                                                     \
        ib_intest = 0;                                                        \
    } while (0)

/* ==================== CPUID 能力门控 ==================== */
static inline void ib_cpuid(unsigned leaf, unsigned subleaf,
                            unsigned *a, unsigned *b, unsigned *c, unsigned *d)
{
    unsigned ea = leaf, ec = subleaf;
    __asm__ volatile("cpuid"
                     : "+a"(ea), "=b"(*b), "+c"(ec), "=d"(*d));
    *a = ea;
    *c = ec;
}
static int ib_cpu_ok(const char *cap)
{
    unsigned a, b, c, d;
    if (!cap || !*cap)
        return 1;
    ib_cpuid(1, 0, &a, &b, &c, &d);
    if (!strcmp(cap, "sse"))    return (d >> 25) & 1u;
    if (!strcmp(cap, "sse2"))   return (d >> 26) & 1u;
    if (!strcmp(cap, "sse3"))   return (c >> 0) & 1u;
    if (!strcmp(cap, "pclmul")) return (c >> 1) & 1u;
    if (!strcmp(cap, "ssse3"))  return (c >> 9) & 1u;
    if (!strcmp(cap, "fma"))    return (c >> 12) & 1u;
    if (!strcmp(cap, "movbe"))  return (c >> 22) & 1u;
    if (!strcmp(cap, "sse4.1")) return (c >> 19) & 1u;
    if (!strcmp(cap, "sse4.2")) return (c >> 20) & 1u;
    if (!strcmp(cap, "popcnt")) return (c >> 23) & 1u;
    if (!strcmp(cap, "aes"))    return (c >> 25) & 1u;
    if (!strcmp(cap, "avx"))    return (c >> 28) & 1u;
    ib_cpuid(7, 0, &a, &b, &c, &d);
    if (!strcmp(cap, "bmi1"))   return (b >> 3) & 1u;
    if (!strcmp(cap, "avx2"))   return (b >> 5) & 1u;
    if (!strcmp(cap, "bmi2"))   return (b >> 8) & 1u;
    if (!strcmp(cap, "sha"))    return (b >> 29) & 1u;
    ib_cpuid(0x80000001u, 0, &a, &b, &c, &d);
    if (!strcmp(cap, "abm"))    return (c >> 5) & 1u;
    return 0;
}

/* ==================== 采集机守卫 ====================
 * 真值表只能由真 x86 硬件采集: 翻译层(LATX 下跑同一份 x86_64 ELF)的执行结果是翻译器
 * 产物, 把它当"真值"等于让被测者自出题。Linux 侧看 uname 机器名; Windows 侧 PE 只在
 * 真 x86 Windows 上跑(同 pmul 既有约定)。判不出来就不出表, 不出处来不明的表。 */
#ifndef _WIN32
#include <sys/utsname.h>
#endif
__attribute__((unused)) static int ib_gold_host_ok(void)
{
#ifdef _WIN32
    return 1;
#else
    struct utsname u;

    if (uname(&u) != 0)
        return 0;
    return strcmp(u.machine, "x86_64") == 0;
#endif
}

/* ==================== KAT 比对基础设施 ====================
 * 统一真值单元(KAT v2): 输入 4 字 + 入标志 + 输出 4 字 + 出标志, 覆盖
 * GPR 32/64、XMM 128、YMM 256、x87 80 位与 EFLAGS。
 * 判定口径: 只比输出 o0..o3 + outf —— in 存表仅用于错档核(表内输入 vs 现场生成
 * 输入), 不参与判定(输入本就由生成器确定性推出, 比它等于自己跟自己比)。 */
typedef struct {
    uint64_t i0, i1, i2, i3;   /* 输入 4 字 = 最多 256 位 */
    uint64_t inf;              /* 入标志(IB_KFL 掩码后值) */
    uint64_t o0, o1, o2, o3;   /* 输出 4 字 */
    uint64_t outf;             /* 出标志 */
} ib_kv;

#define IB_KV_IN_OFF   0       /* 输入字段起始下标(结构序固定) */
#define IB_KV_IN_N     5       /* 参与错档核的输入字数 = i0..i3 + inf */
#define IB_KV_OUT_OFF  5       /* 输出字段起始下标(本结构序固定, 改动=全仓重采) */
#define IB_KV_OUT_N    5       /* 参与判定的输出字数 = o0..o3 + outf */
#define IB_KAT_N       8
#define IB_KV_UNSET    { 0, 0, 0, 0, 0, IB_KV_MAGIC, IB_KV_MAGIC, IB_KV_MAGIC, IB_KV_MAGIC, 0 }
#define IB_KV_MAGIC    0xdeadbeefdeadbeefULL
#define IB_FLG_MASK    0x8d5ULL
#define IB_FLG_MASK_CFOF 0x801ULL
#define IB_FLG_MASK_LOGIC 0x8c5ULL
#define IB_FLG_MASK_SHIFT 0x0c5ULL
#define IB_FLG_MASK_SH1   0x8c5ULL
#define IB_FLG_MASK_ROT   0x0d5ULL
#define IB_FLG_MASK_SCAN  0x041ULL
#define IB_FLG_MASK_FCOM  0x045ULL
#define IB_FV(v)       (((v) & IB_FLG_MASK) | 0x2ULL)

typedef void (*ib_kat_fn)(int k, ib_kv *got);

/* ==================== 用例表(必须在 ib_kline 之前定义) ==================== */
typedef uint64_t (*ib_fn)(ib_uw iters);
typedef struct {
    const char *name;
    const char *cap;
    ib_fn lat;
    ib_fn tput;
    ib_fn sem;
    const char *tag;
    unsigned bpop;
    ib_fn b8;
    unsigned long long lits;
    ib_kat_fn kat;
    ib_kv kexp[IB_KAT_N];
    const char *stem;
} ib_case;

static const char *const ib_kfld[10] = { "i0", "i1", "i2", "i3", "inf",
                                         "o0", "o1", "o2", "o3", "outf" };

static void ib_kline(const char *grp, const ib_case *c, int k,
                     const ib_kv *v, const char *src)
{
    char line[320];

    if (!g_debug)
        return;      /* 详细明细只在 --debug 时才产; 否则整段 dbg 不出现 */
    snprintf(line, sizeof line,
             IB_REC_DBG ",%s,%s,%s,%s,%d,"
             "%016llx,%016llx,%016llx,%016llx,%016llx,"
             "%016llx,%016llx,%016llx,%016llx,%016llx,%s\n",
             grp, g_abi, c->name, c->stem ? c->stem : "-", k,
             (unsigned long long)v->i0, (unsigned long long)v->i1,
             (unsigned long long)v->i2, (unsigned long long)v->i3,
             (unsigned long long)v->inf,
             (unsigned long long)v->o0, (unsigned long long)v->o1,
             (unsigned long long)v->o2, (unsigned long long)v->o3,
             (unsigned long long)v->outf, src);
    ib_dbg_put(line);
}

static int ib_name_ok(const char *name)
{
    const char *c = g_only;
    size_t ln;
    if (!c)
        return 1;
    ln = strlen(name);
    do {
        size_t l = strcspn(c, ",");
        if (l && ln >= l && !strncmp(name, c, l))
            return 1;
        c += l;
    } while (*c++ == ',');
    return 0;
}

static int ib_case_lat(const char *grp, const ib_case *c)
{
    volatile unsigned long long it = g_lat_iters;
    if (c->lits && c->lits < it)
        it = c->lits;
#ifdef _WIN32
    ib_cur_set(grp, c->name, "lat");
#endif
    ib_sig_nr = 0;
    ib_intest = 1;
    if (IB_SIGSETJMP(ib_jb) == 0) {
        uint64_t s;
        uint64_t t0, el;        /* 时间量一律用整数纳秒 */
        int outer_loops = 100;  /* 外层 100 次取平均(总量不变: 每轮 = 总量/100) */
        unsigned long long total_iters = 0, it_max;

        it = it / outer_loops;   /* 内层次数 = 总量/100, 100 轮合计仍为 g_lat_iters 量级 */
        if (it == 0)
            it = 1;
        it_max = it * 4;         /* 自适应上限: 不超总量的 4 倍, 防慢用例拖长 */
        snprintf(ib_wv[WV_LAT_ITERS], sizeof ib_wv[WV_LAT_ITERS], "%llu", it);
        c->lat(1000);
        IB_BARRIER();
        c->lat(1000);
        IB_BARRIER();

        /* 自适应: 单轮太快(<1us)就加内层次数, 上限 it_max */
        t0 = ib_now();
        s = c->lat((ib_uw)it);
        el = ib_now() - t0;
        if (el < 1000) {                        /* 单轮 < 1us: 放大到目标 ~10us */
            it = it * 10000ULL / (el ? el : 1);
            if (it > it_max)
                it = it_max;
        }
        if (it > IB_UW_MAX)                     /* 内核形参是本机字长(i386=32 位) */
            it = IB_UW_MAX;                     /* 防 --iters 超 2^32 静默截断 */
        
        /* 外层循环: 跑 outer_loops 次取平均 */
        t0 = ib_now();
        for (int i = 0; i < outer_loops; i++) {
            s = c->lat((ib_uw)it);
            total_iters += it;
        }
        IB_BARRIER();
        el = ib_now() - t0;
        ib_intest = 0;
        if (el > 0)
            ib_lat(grp, c->name, IB_ST_OK,
                   (double)el / (double)total_iters, s, IB_V_NONE);
        else {
            /* 时钟精度不够: el=0, 仍输出但标记为 LOW_RES */
            fprintf(stderr, "# WARN: %s lat el=0 (it=%llu, loops=%d, clock_res?)\n", c->name, it, outer_loops);
            ib_lat(grp, c->name, "LOW_RES", 0.0, s, IB_V_NONE);
        }
        return 1;
    }
    ib_intest = 0;
    ib_crash(grp, c->name, "lat", (int)ib_sig_nr);
    return 0;
}

static int ib_case_tput(const char *grp, const ib_case *c)
{
    uint64_t window = (uint64_t)g_tput_ms * 1000000ULL;   /* 计时窗口: 毫秒 -> 纳秒 */
    unsigned bpop = c->bpop;
#ifdef _WIN32
    ib_cur_set(grp, c->name, "tput");
#endif
    ib_sig_nr = 0;
    ib_intest = 1;
    if (IB_SIGSETJMP(ib_jb) == 0) {
        int K;
        unsigned long long n = 0, ops;
        uint64_t sig = 0;
        uint64_t t0, t1, el = 0;
        t0 = ib_now();
        sig = c->tput(4096);
        IB_BARRIER();
        el = ib_now() - t0;
        /* 用 4096 次的实测耗时估 K: 目标单轮 ~30us(30000ns), 全整数 */
        if (el > 0)
            K = (int)(30000ULL * 4096ULL / el);
        else
            K = 1 << 16;
        if (K < 1024)
            K = 1024;
        if (K > (1 << 26))
            K = 1 << 26;
        el = 0;
        do {
            t1 = ib_now();
            sig = c->tput(K);
            el += ib_now() - t1;
            n++;
        } while (el < window);
        IB_BARRIER();
        sig = c->tput(4096);
        IB_BARRIER();
        ops = n * K;
        ib_intest = 0;
        if (el > 0 && ops > 0) {
            double op_s = (double)ops * 1e9 / (double)el;
            ib_tput(grp, c->name, IB_ST_OK, op_s, "ops/s",
                    bpop ? op_s * (double)bpop / 1e6 : 0.0,
                    bpop ? "MB/s" : IB_V_NONE, sig, IB_V_NONE);
        }
        return 1;
    }
    ib_intest = 0;
    ib_crash(grp, c->name, "tput", (int)ib_sig_nr);
    return 0;
}

static int ib_case_b8(const char *grp, const ib_case *c)
{
    uint64_t window = (uint64_t)g_tput_ms * 1000000ULL;   /* 计时窗口: 毫秒 -> 纳秒 */
#ifdef _WIN32
    ib_cur_set(grp, c->name, "block8");
#endif
    ib_sig_nr = 0;
    ib_intest = 1;
    if (IB_SIGSETJMP(ib_jb) == 0) {
        int K;
        unsigned long long n = 0;
        uint64_t sig = 0;
        uint64_t t0, t1, el = 0;
        t0 = ib_now();
        sig = c->b8(4096);
        IB_BARRIER();
        el = ib_now() - t0;
        if (el > 0)
            K = (int)(30000ULL * 4096ULL / el);
        else
            K = 1 << 16;
        if (K < 1024)
            K = 1024;
        if (K > (1 << 26))
            K = 1 << 26;
        el = 0;
        do {
            t1 = ib_now();
            sig = c->b8(K);
            el += ib_now() - t1;
            n++;
        } while (el < window);
        IB_BARRIER();
        sig = c->b8(4096);
        IB_BARRIER();
        ib_intest = 0;
        if (el > 0 && n * K > 0)
            ib_b8(grp, c->name, IB_ST_OK,
                  (double)el / (double)(n * K), sig, IB_V_NONE);
        return 1;
    }
    ib_intest = 0;
    ib_crash(grp, c->name, "block8", (int)ib_sig_nr);
    return 0;
}

static int ib_case_sem(const char *grp, const ib_case *c)
{
#ifdef _WIN32
    ib_cur_set(grp, c->name, "sem");
#endif
    ib_sig_nr = 0;
    ib_intest = 1;
    if (IB_SIGSETJMP(ib_jb) == 0) {
        uint64_t s = c->sem(1);
        ib_intest = 0;
        ib_sem(grp, c->name, IB_ST_OK, s, c->tag);
        return 1;
    }
    ib_intest = 0;
    ib_crash(grp, c->name, "sem", (int)ib_sig_nr);
    return 0;
}

static int ib_case_kat(const char *grp, const ib_case *c)
{
    int k, nok = 0, ncol = 0, nfail = 0, nmis = 0;
    char det[40];
    char mdet[40];
    det[0] = '\0';
    mdet[0] = '\0';
    if (!c->kat)
        return 1;
#ifdef _WIN32
    ib_cur_set(grp, c->name, "kat");
#endif
    ib_sig_nr = 0;
    ib_intest = 1;
    if (IB_SIGSETJMP(ib_jb) == 0) {
        ib_kv got;
        const uint64_t *pe;
        const uint64_t *pg;
        for (k = 0; k < IB_KAT_N; k++) {
            memset(&got, 0, sizeof got);
            c->kat(k, &got);
            if (g_gen_gold || c->kexp[k].o0 == IB_KV_MAGIC) {
                ncol++;
                ib_kline(grp, c, k, &got, "got");
                continue;
            }
            pe = (const uint64_t *)&c->kexp[k];
            pg = (const uint64_t *)&got;
            /* 错档核: 表内输入(i0..i3+inf)必须 == 现场生成输入 —— 防"A 档真值判
             * B 档"静默假绿。输入不参与判定(生成器确定性推出), 但一旦表里的输入
             * 与现场对不上, 说明表是别档/旧生成器采的, 该 case 判 INMISMATCH。 */
            if (memcmp(pe + IB_KV_IN_OFF, pg + IB_KV_IN_OFF,
                       IB_KV_IN_N * sizeof(uint64_t))) {
                if (nmis == 0) {
                    int f = IB_KV_IN_OFF;
                    int hi;
                    while (f < IB_KV_IN_OFF + IB_KV_IN_N && pe[f] == pg[f])
                        f++;
                    if (f >= IB_KV_IN_OFF + IB_KV_IN_N)
                        f = IB_KV_IN_OFF;
                    hi = ((pe[f] ^ pg[f]) & 0xffffffffULL) == 0;
                    snprintf(mdet, sizeof mdet, "k=%d %s.%c e=%08llx g=%08llx", k,
                             ib_kfld[f], hi ? 'h' : 'l',
                             (unsigned long long)(pe[f] >> (hi ? 32 : 0)),
                             (unsigned long long)(pg[f] >> (hi ? 32 : 0)));
                    ib_kline(grp, c, k, &c->kexp[k], "exp");
                    ib_kline(grp, c, k, &got, "got");
                }
                nmis++;
                continue;
            }
            /* 只比输出 5 字(o0..o3 + outf): 输入由生成器确定性推出, 不比 */
            if (!memcmp(pe + IB_KV_OUT_OFF, pg + IB_KV_OUT_OFF,
                        IB_KV_OUT_N * sizeof(uint64_t))) {
                nok++;
                if (g_verify) {
                    ib_kline(grp, c, k, &c->kexp[k], "exp");
                    ib_kline(grp, c, k, &got, "got");
                }
                continue;
            }
            nfail++;
            if (nfail == 1) {
                int f = IB_KV_OUT_OFF;
                int hi;
                while (f < 10 && pe[f] == pg[f])
                    f++;
                if (f > 9)
                    f = 9;
                hi = ((pe[f] ^ pg[f]) & 0xffffffffULL) == 0;
                snprintf(det, sizeof det, "k=%d %s.%c e=%08llx g=%08llx", k,
                         ib_kfld[f], hi ? 'h' : 'l',
                         (unsigned long long)(pe[f] >> (hi ? 32 : 0)),
                         (unsigned long long)(pg[f] >> (hi ? 32 : 0)));
            }
            /* 调试增强: verify 模式下每个失败档都吐 exp+got(原只吐首个失败档);
             * 判分/统计(det/ib_kat)逻辑不动, 仅扩大 dbg 观测面。 */
            if (nfail == 1 || g_verify) {
                ib_kline(grp, c, k, &c->kexp[k], "exp");
                ib_kline(grp, c, k, &got, "got");
            }
        }
        ib_intest = 0;
    } else {
        ib_intest = 0;
        ib_crash(grp, c->name, "kat", (int)ib_sig_nr);
        return 0;
    }
    ib_kat(grp, c->name,
           nmis ? IB_ST_INMISMATCH :
           nfail ? IB_ST_KATFAIL : (ncol ? IB_ST_COLLECT : IB_ST_OK),
           mdet[0] ? mdet : (det[0] ? det :
                             (ncol ? "collect 8/8 (表未回填)" : "8/8")));
    return nfail == 0 && nmis == 0;
}

static int ib_run_case(const char *grp, const ib_case *c)
{
    int allok = 1;
    ib_row_mode = 1;
    if (!ib_cpu_ok(c->cap)) {
        if (g_do_lat && c->lat)
            ib_unsup(grp, c->name, "lat", c->cap);
        if (g_do_tput && c->tput)
            ib_unsup(grp, c->name, "tput", c->cap);
        if (g_do_b8 && c->b8)
            ib_unsup(grp, c->name, "block8", c->cap);
        if (g_do_sem && c->sem)
            ib_unsup(grp, c->name, "sem", c->cap);
        ib_flush();
        ib_row_mode = 0;
        return 0;
    }
    if (g_do_lat && c->lat && !ib_case_lat(grp, c))
        allok = 0;
    if (g_do_tput && c->tput && !ib_case_tput(grp, c))
        allok = 0;
    if (g_do_b8 && c->b8 && !ib_case_b8(grp, c))
        allok = 0;
    if (g_do_sem && c->sem && !ib_case_sem(grp, c))
        allok = 0;
    if (!ib_case_kat(grp, c))
        allok = 0;
    ib_flush();
    ib_row_mode = 0;
    return allok;
}

int ib_run_cases(const char *grp, const ib_case *cases, int n)
{
    int i, ok = 0, tot = 0;
    if (g_list_cases) {
        printf("# %s: %d 个用例\n", grp, n);
        for (i = 0; i < n; i++)
            printf("%s\t%s\n", cases[i].name,
                   cases[i].cap ? cases[i].cap : "-");
        return 0;
    }
    for (i = 0; i < n; i++) {
        const ib_case *c = &cases[i];
        if (!ib_name_ok(c->name))
            continue;
        tot++;
        if (ib_run_case(grp, c))
            ok++;
    }
    ib_done(grp, ok, tot);
    return ok;
}

/* ==================== 单组 --help 详细帮助 ====================
 * 一个可执行的 --help 要说清三件事: 我能被怎么调、我吐什么、我判什么。
 * 选项表逐条给"默认值/关掉什么"; 输出协议逐记录类型列; 采集与守卫在最后。 */
static void ib_usage(const char *prog)
{
    fprintf(stderr,
"用法: %s [选项]\n"
"\n"
"选项:\n"
"  --time MS         吞吐计时窗口毫秒数(默认 100, 整数)\n"
"  --iters N         延迟链迭代上限(默认 2000000; 亚 ns 用例另有更小上限)\n"
"  --only=前缀[,..]  只跑名字以此前缀开头的用例(按用例名匹配, 逗号分隔多前缀)\n"
"  --list            只列出本组全部用例(名字 + 能力门控), 不跑测试\n"
"  --gen-gold        采集态: 忽略真值表, 逐槽吐 got 明细(供 gen_val.sh 收割出表;\n"
"                    仅真 x86 可用)\n"
"  --debug           吐 dbg 段: 逐 (用例,真值槽) 的 in/gold/got 明细, 落 debug_<grp>\n"
"  --no-lat          关掉单依赖链延迟测试\n"
"  --no-tput         关掉定时长吞吐测试\n"
"  --no-b8           关掉连续 8 指令块测试\n"
"  --no-sem          关掉语义对拍(若本组有)\n"
"  --help, -h        显示本帮助(全部走 stderr)\n"
"\n"
"环境变量:\n"
"  ISB_DEBUG=1       等价 --debug\n"
"  ISB_VERIFY=1      KAT 每个真值槽都打 exp+got 明细(dbg 全量, 需配合 --debug)\n"
"\n"
"输出(每行第一列 = 记录类型, 按 field 行分段):\n"
"  meta   本场运行标识与环境(k=v)\n"
"  field  英文列名 = 数据库列名(解析侧现读现建)\n"
"  label  中文列名(与 field 严格同列序)\n"
"  data   性能行: latency_status/ns, throughput_status/ops_s/mb_s, block8_*, diag_*\n"
"  func   功能行: 一行一用例, 列 = 各功能, 值 true/false/-(落 verify_<grp>)\n"
"  dbg    详细行(仅 --debug): in0..in3/inf/gold/o0..o3/outf\n"
"  group  组尾: 组名 + 通过数/总数\n"
"\n"
"功能判定(KAT): 输出 o0..o3+outf 与真值表全等 = true(OK), 不等 = false(FAIL);\n"
"  真值表未回填 = -(COLLECT); 本机不具备该能力 = -(HOSTUNSUPPORTED)。\n"
"真值表由 build.sh/gen_val.sh 在真 x86 上采集, 不在翻译层上自采。\n",
            prog);
}

/* ==================== 参数解析 ==================== */
void ib_init(int argc, char **argv)
{
    int i;
    g_abi = "x86_64";
#ifdef __i386__
    g_abi = "i386";
#endif
    g_os = "linux";
#ifdef _WIN32
    g_os = "windows";
#endif
    {
        const char *e = getenv("ISB_VERIFY");
        g_verify = (e != NULL && *e != '\0' && strcmp(e, "0") != 0);
        e = getenv("ISB_DEBUG");
        g_debug = (e != NULL && *e != '\0' && strcmp(e, "0") != 0);
    }
    signal(SIGILL, ib_on_sig);
    signal(SIGSEGV, ib_on_sig);
    signal(SIGFPE, ib_on_sig);
#ifdef SIGBUS
    signal(SIGBUS, ib_on_sig);
#endif
#ifdef _WIN32
    AddVectoredExceptionHandler(1, ib_veh);
#endif
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--time") && i + 1 < argc) {
            g_tput_ms = atoi(argv[++i]);
            if (g_tput_ms <= 0)
                g_tput_ms = 100;
        } else if (!strcmp(argv[i], "--iters") && i + 1 < argc) {
            g_lat_iters = strtoull(argv[++i], NULL, 0);
            if (!g_lat_iters)
                g_lat_iters = 2000000;
        } else if (!strncmp(argv[i], "--only=", 7)) {
            g_only = argv[i] + 7;
        } else if (!strcmp(argv[i], "--only") && i + 1 < argc) {
            g_only = argv[++i];
        } else if (!strcmp(argv[i], "--no-lat")) {
            g_do_lat = 0;
        } else if (!strcmp(argv[i], "--no-tput")) {
            g_do_tput = 0;
        } else if (!strcmp(argv[i], "--no-b8")) {
            g_do_b8 = 0;
        } else if (!strcmp(argv[i], "--no-sem")) {
            g_do_sem = 0;
        } else if (!strcmp(argv[i], "--debug")) {
            g_debug = 1;
        } else if (!strcmp(argv[i], "--list")) {
            g_list_cases = 1;
        } else if (!strcmp(argv[i], "--gen-gold")) {
            g_gen_gold = 1;
            g_debug = 1;      /* 采集需要 dbg 段承载逐槽 in/gold/got */
        } else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            ib_usage(argv[0]);
            exit(0);
        }
    }
    if (g_gen_gold && !ib_gold_host_ok()) {
        fprintf(stderr, "isbench: --gen-gold 只能在真 x86 上跑(本机机器名非 "
                        "x86_64) -> 翻译层上的结果不能当真值, 不出表\n");
        exit(3);
    }
}

/* ==================== 全局定义 ==================== */
int g_tput_ms = 100;
unsigned long long g_lat_iters = 2000000;
int g_do_lat = 1, g_do_tput = 1, g_do_sem = 1, g_do_b8 = 1;
int g_verify = 0;
int g_debug = 0;
const char *g_only = NULL;
const char *g_abi = "x86_64", *g_os = "linux";

#endif /* ISB_IB_CORE_H */
