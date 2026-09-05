/* ib.h —— isbench 统一公共层(仅被 src/isb_*.c 引用, 每个可执行恰好一个包含本头的 TU)
 *
 * 目标: 一套可移植静态探针, 全组共用:
 *   1) 统一输出: 单表 CSV(表头行 + T 用例行 + D 组尾行, 同列布局, xlsx
 *      可直接导入; 详见文件底部「输出行格式」注释);
 *   2) 两种测速内核(每用例声明式注册, 组文件里只剩数据表):
 *        lat  —— 稳态单依赖链 ns/op(替代旧 insn_probe 语义);
 *        tput —— 定时长窗口吞吐 ops/s + MB/s(替代第三方基准);
 *   3) 全宽签名 sig16: 每行结果 64 位, native/latx/wine 按 (grp,case,metric)
 *      键逐位对拍;
 *   4) 信号兜底: 每条用例每 metric 独立保护, SIGILL/SIGSEGV/SIGFPE ->
 *      CRASH 行后继续, 不毁整组(与旧 insn_probe/sse_state_probe 同哲学);
 *   5) CPUID 能力门控(自实现, mingw/Linux 通用, 不依赖 __builtin_cpu_supports);
 *   6) 计时: Linux CLOCK_MONOTONIC / Windows QPC —— 两者在 wine+LATX 下实测
 *      可靠; 不用 rdtsc(LATX 下被伪造)。
 *
 * 编码纪律(忠实 32 位 libcef 的指令形态, 沿用 legacy hf_probe 结论):
 *   - 组构建 flags 默认不开 -mavx*, 保证 SSE 家族为 legacy(66/0F) 编码;
 *   - AVX/FMA 用例由组文件内 __attribute__((target(...))) 单独发 VEX。
 *
 * 输出行格式(单表 CSV, 同列布局同表头, xlsx 软件可直接导入):
 * 每行 = 一个指令(case), 各测试方式做列; 首行表头(29 列):
 *   kind,group,abi,os,bits,tput_sec,lat_iters,case,
 *   lat_st,lat_ns,lat_sig,tput_st,tput_ops,tput_mbs,tput_sig,
 *   block8_st,block8_ns,block8_sig,
 *   sem_st,sem_sig,sem_tag,kat_st,kat_det,diag_st,diag_v,diag_u,diag_det,
 *   ok,total
 * block8_* = 连续8指令块(8 连独立链)执行时间 ns/块 + 稳定签名; 只有注册
 * 了 b8 函数的用例填值(该行适合 8 连形态), 其余行三列空 '-'。
 * 用例行 kind=T: 该指令出现的测试方式填对应列, 未测方式填 '-'; 状态列
 *   (CRASH/HOSTUNSUPPORTED/OK) 逐方式独立; 组尾行 kind=D 只填 group/ok/total
 * 每次 exec 的 stdout = 1 表头 + N 行 T + 1 行 D(无任何其它 stdout)。
 * 对拍(compare): 键 = (abi,group,case); 逐方式列比状态/sig/v1; lat 与 tput
 *   的数值列是同一指令行的两列, 不再有 metric 行拆分。
 *   sem/kat 比 sig16/status; CRASH/HOSTUNSUPPORTED/FAIL 视为已解释状态。
 */
#ifndef ISB_IB_H
#define ISB_IB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <time.h>
#include <x86intrin.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
/* mingw-w64 CRT 提供 signal()+setjmp, 但无 POSIX sigsetjmp: 探针单线程, setjmp 等价够用。
 * 另挂 VEH 兜底: 若异常未被 CRT 转成 C 信号, 至少留 CRASH 行再退出(避免无声死亡)。 */
#define IB_SIGSETJMP(e)   setjmp(e)
#define IB_SIGLONGJMP(e,v) longjmp(e, v)
typedef jmp_buf ib_jmp_t;
#else
#include <unistd.h>
#define IB_SIGSETJMP(e)   sigsetjmp(e, 1)
#define IB_SIGLONGJMP(e,v) siglongjmp(e, v)
typedef sigjmp_buf ib_jmp_t;
#endif

/* ---------------- 运行参数(ib_init 填充) ---------------- */
extern double g_tput_sec;               /* tput 定时窗口秒, 默认 0.5 */
extern unsigned long long g_lat_iters;  /* lat 依赖链迭代数, 默认 2000000 */
extern int g_do_lat, g_do_tput, g_do_sem, g_do_b8;  /* 四个 metric 开关 */
extern const char *g_only;              /* 用例名前缀过滤(NULL=全部) */
extern const char *g_abi, *g_os;        /* 构建目标标识 */

/* ---------------- 计时(禁 rdtsc: LATX 下伪造) ---------------- */
static inline double ib_now(void)
{
#ifdef _WIN32
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart * 1e9 / (double)f.QuadPart;
#else
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
#endif
}

/* 编译器屏障: 防止预热/计时调用被 DCE/重排(与 legacy volatile g_sink 同作用) */
#define IB_BARRIER() asm volatile("" ::: "memory")

/* ---------------- 全宽签名(结果逐位对拍基础) ---------------- */
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

/* ---------------- 统一输出: 宽行(每 case/实体一行, 方式做列) --------------
 * 行 key = case(指令); lat/tput/sem/kat/diag 各测试方式在同一行的列中。
 * 两种模式:
 *   行缓冲(ib_row_mode=1, ib_run_case 内): ib_lat/ib_tput/ib_sem/ib_unsup
 *     只写结果槽, 由 ib_run_case 在 case 尾调 ib_flush() 输出 1 行宽 CSV;
 *   立即(直接调用场景: crypto KAT / cpuid,timer 的 diag 等): 写槽后立即
 *     ib_flush()(每次调用 = 一个实体一行, 只填自身方式槽, 其余 '-')。
 * 数值/签名/文本全部落固定文本槽, 槽空 = 该方式未测, 输出 '-'; 槽写与
 * flush 在同一函数序内完成(单线程), 无跨函数存活冲突。
 */
enum { WV_LAT_ST, WV_LAT_NS, WV_LAT_SIG, WV_TPUT_ST, WV_TPUT_OPS,
       WV_TPUT_MBS, WV_TPUT_SIG, WV_B8_ST, WV_B8_NS, WV_B8_SIG,
       WV_SEM_ST, WV_SEM_SIG, WV_SEM_TAG,
       WV_KAT_ST, WV_KAT_DET, WV_DIAG_ST, WV_DIAG_V, WV_DIAG_U, WV_DIAG_DET };
static char ib_wv[19][40];
static char ib_wgrp[24], ib_wcase[48];
static int ib_row_mode = 0;          /* 1 = case 表内(尾 flush); 0 = 立即 flush */

static void ib_wreset(void)
{
    int i;
    ib_wgrp[0] = ib_wcase[0] = '\0';
    for (i = 0; i < 19; i++)
        ib_wv[i][0] = '\0';
}
static void ib_wset(int idx, const char *v)
{
    snprintf(ib_wv[idx], sizeof ib_wv[idx], "%s", v && *v ? v : "-");
}
static const char *ib_wget(int idx)
{
    return ib_wv[idx][0] ? ib_wv[idx] : "-";
}
static void ib_flush(void)
{
    printf("T,%s,%s,%s,%d,%.1f,%llu,%s,"
           "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,-,-\n",
           ib_wgrp[0] ? ib_wgrp : "-", g_abi, g_os,
           (int)(sizeof(void *) * 8), g_tput_sec,
           (unsigned long long)g_lat_iters, ib_wcase[0] ? ib_wcase : "-",
           ib_wget(WV_LAT_ST), ib_wget(WV_LAT_NS), ib_wget(WV_LAT_SIG),
           ib_wget(WV_TPUT_ST), ib_wget(WV_TPUT_OPS), ib_wget(WV_TPUT_MBS),
           ib_wget(WV_TPUT_SIG), ib_wget(WV_B8_ST), ib_wget(WV_B8_NS),
           ib_wget(WV_B8_SIG),
           ib_wget(WV_SEM_ST), ib_wget(WV_SEM_SIG), ib_wget(WV_SEM_TAG),
           ib_wget(WV_KAT_ST), ib_wget(WV_KAT_DET),
           ib_wget(WV_DIAG_ST), ib_wget(WV_DIAG_V), ib_wget(WV_DIAG_U),
           ib_wget(WV_DIAG_DET));
    ib_wreset();
}

/* 直接场景(crypto KAT / timer,cpuid diag / VEH): 写槽后强制立即一行 */
void ib_flush_always(void)
{
    ib_flush();
}

/* ---- 行缓冲写槽函数(case 表内调用, 不输出) ---- */
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
/* ---- block8: 连续8指令块执行时间 ns(同行新列, 不新建 case 行) ---- */
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
    ib_wset(idx, "HOSTUNSUPPORTED");
}

/* ---- 立即单行(直接场景) ---- */
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
    printf("kind,group,abi,os,bits,tput_sec,lat_iters,case,"
           "lat_st,lat_ns,lat_sig,tput_st,tput_ops,tput_mbs,tput_sig,"
           "block8_st,block8_ns,block8_sig,"
           "sem_st,sem_sig,sem_tag,kat_st,kat_det,diag_st,diag_v,diag_u,"
           "diag_det,ok,total\n");
    ib_wreset();
}

/* ---------------- 信号兜底 ---------------- */
static ib_jmp_t ib_jb;
static volatile sig_atomic_t ib_intest = 0;   /* 1 = 当前处于用例保护区 */
static volatile sig_atomic_t ib_sig_nr = 0;   /* 最近一次信号号(handler 记录) */
#ifdef _WIN32
static const char *ib_cur_grp, *ib_cur_name, *ib_cur_metric;   /* VEH 留痕用 */
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
void ib_flush_always(void);

#ifdef _WIN32
static LONG WINAPI ib_veh(PEXCEPTION_POINTERS ep)
{
    unsigned code = ep->ExceptionRecord->ExceptionCode;
    int sig = 0;
    switch (code) {
    case EXCEPTION_ILLEGAL_INSTRUCTION: sig = 4; break;            /* SIGILL */
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: sig = 11; break;         /* SIGSEGV */
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_FLT_DIVIDE_BY_ZERO: sig = 8; break;             /* SIGFPE */
    default: return EXCEPTION_CONTINUE_SEARCH;
    }
    if (ib_intest && ib_cur_name) {   /* 用例内裸异常: 宽行留 CRASH 后退出 */
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
    ib_wset(idx, "CRASH");
    if (!ib_row_mode)                 /* 直接场景: 崩即输出一行 */
        ib_flush();
}

/* 受保护区: 执行 BODY(复合语句)。
 *   崩(SIGILL/SIGSEGV/SIGFPE...): 输出该 metric 的 CRASH 行, 跳过 BODY, 置 *bad=1;
 *   正常: 什么都不做。
 * 用法: int bad = 0;
 *   IB_TRY(grp, name, metric, bad, { ...被保护代码... });
 * 注意: sigsetjmp 目标帧 = 本宏所在函数(崩溃时该函数尚未返回, 合法);
 * BODY 在 if 分支内, 其中的局部变量不跨 longjmp 存活, 不要在 BODY 外读它们。
 */
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

/* ---------------- CPUID 能力门控(自实现) ----------------
 * 能力名: sse sse2 sse3 ssse3 sse4.1 sse4.2 popcnt movbe aes pclmul
 *         avx avx2 fma sha bmi1 bmi2 abm(lzcnt)
 * 注: avx 族不查 OSXSAVE/XCR0 —— 翻译器(LATX)下以行为为准, 兜底靠 CRASH 行。
 */
static inline void ib_cpuid(unsigned leaf, unsigned subleaf,
                            unsigned *a, unsigned *b, unsigned *c, unsigned *d)
{
    unsigned ea = leaf, ec = subleaf;
    /* GNU asm: Linux gcc / mingw-w64 全平台通用(不用 MSVC __cpuidex) */
    __asm__ volatile("cpuid"
                     : "+a"(ea), "=b"(*b), "+c"(ec), "=d"(*d));
    *a = ea;
    *c = ec;
}
static int ib_cpu_ok(const char *cap)          /* NULL/空 = 恒支持 */
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
    if (!strcmp(cap, "abm"))    return (c >> 5) & 1u;   /* lzcnt */
    return 0;   /* 未知能力名: 保守拒绝 */
}

/* ---------------- 用例表与统一运行器 ---------------- */
typedef uint64_t (*ib_fn)(unsigned long long iters);
typedef struct {
    const char *name;       /* 用例名(输出 case 字段) */
    const char *cap;        /* CPUID 能力名, NULL/空 = 恒支持 */
    ib_fn lat;              /* 单依赖链: 执行 iters 次核心 op 并返回签名; NULL = 无 lat */
    ib_fn tput;             /* 多独立链展开(吞吐语义), 同上; NULL = 无 tput */
    ib_fn sem;              /* 语义对拍: 单次执行(忽略 iters)返回全宽签名; NULL = 无 sem */
    const char *tag;        /* sem 的 detail 标签(如寄存器高半分类), NULL = 无 */
    unsigned bpop;          /* tput 每 op 处理字节数(折算 v2=MB/s), 0 = 不折算 */
    ib_fn b8;               /* 连续8指令块(8 连独立链): 定时长测每块执行 ns + 稳定签名;
                             * NULL = 该行不适合 8 连, block8 三列空。同指令同行不同列 */
} ib_case;

/* 名字过滤(前缀匹配, 逗号分隔多前缀, 与 legacy -only= 同语义) */
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

/* ---- lat: 预热 + 单次正式测量(依赖链在组函数内部迭代 iters 次) ----
 * 保护模型: sigsetjmp 与执行体同帧(本函数), 崩溃恢复点只读 volatile 全局
 * ib_sig_nr —— 按 C 标准, sigsetjmp 后修改的自动变量在 longjmp 回来后值不
 * 确定, 故测量/输出全部在保护区内完成, 恢复路径不读任何局部。 */
static int ib_case_lat(const char *grp, const ib_case *c)
{
    unsigned long long it = g_lat_iters;
#ifdef _WIN32
    ib_cur_set(grp, c->name, "lat");
#endif
    ib_sig_nr = 0;
    ib_intest = 1;
    if (IB_SIGSETJMP(ib_jb) == 0) {
        uint64_t s;
        double t0, el;
        c->lat(1000);                 /* 预热 */
        IB_BARRIER();
        c->lat(1000);
        IB_BARRIER();
        t0 = ib_now();
        s = c->lat(it);               /* 正式测量 */
        IB_BARRIER();
        el = ib_now() - t0;
        ib_intest = 0;
        if (el > 0)
            ib_lat(grp, c->name, "OK", el / (double)it, s, "-");
        return 1;
    }
    ib_intest = 0;
    ib_crash(grp, c->name, "lat", (int)ib_sig_nr);
    return 0;
}

/* ---- tput: 定时长窗口, 只累计 fn 执行时间(骨架/调度停顿不稀释吞吐) ----
 * 自适应 K: 试跑估速, 目标单批 ~30us, 窗口内 ≥ 数百批。 */
static int ib_case_tput(const char *grp, const ib_case *c)
{
    double window = g_tput_sec;
    unsigned bpop = c->bpop;
#ifdef _WIN32
    ib_cur_set(grp, c->name, "tput");
#endif
    ib_sig_nr = 0;
    ib_intest = 1;
    if (IB_SIGSETJMP(ib_jb) == 0) {
        unsigned long long K, n = 0, ops;
        uint64_t sig = 0;
        double t0, t1, el = 0;
        t0 = ib_now();
        sig = c->tput(4096);          /* 试跑估速 */
        IB_BARRIER();
        el = ib_now() - t0;
        if (el > 1e-6)
            K = (unsigned long long)(30000.0 * 4096.0 / el);  /* 目标 ~30us/批 */
        else
            K = 1u << 16;
        if (K < 1024)
            K = 1024;
        if (K > (1ull << 26))
            K = 1ull << 26;
        el = 0;
        do {                          /* 定时长窗口 */
            t1 = ib_now();
            sig = c->tput(K);
            el += ib_now() - t1;
            n++;
        } while (el < window * 1e9);
        IB_BARRIER();
        /* 稳定签名: 窗口批数随运行波动, 末批终点不确定 -> 签名不可复现;
         * 固定 4096 次调用的结果与批数无关, 供跨机逐位对拍 */
        sig = c->tput(4096);
        IB_BARRIER();
        ops = n * K;
        ib_intest = 0;
        if (el > 0 && ops > 0) {
            double op_s = (double)ops / (el / 1e9);
            ib_tput(grp, c->name, "OK", op_s, "ops/s",
                    bpop ? op_s * (double)bpop / 1e6 : 0.0,
                    bpop ? "MB/s" : "-", sig, "-");
        }
        return 1;
    }
    ib_intest = 0;
    ib_crash(grp, c->name, "tput", (int)ib_sig_nr);
    return 0;
}

/* ---- block8: 连续8指令块执行时间 ns/块(同 tput 定时长窗口内核, 只报时间) ----
 * 语义: 块 = 同一指令 8 连、各作用独立链、互异确定性数据; 结果 = 每块
 * 平均执行 ns(块轮速倒数), 与 lat_ns(单指令链延迟)同列族语义、同 run 内
 * 对照判块级优化。稳定签名同样取固定 4096 次调用(窗口批数无关)。 */
static int ib_case_b8(const char *grp, const ib_case *c)
{
    double window = g_tput_sec;
#ifdef _WIN32
    ib_cur_set(grp, c->name, "block8");
#endif
    ib_sig_nr = 0;
    ib_intest = 1;
    if (IB_SIGSETJMP(ib_jb) == 0) {
        unsigned long long K, n = 0;
        uint64_t sig = 0;
        double t0, t1, el = 0;
        t0 = ib_now();
        sig = c->b8(4096);            /* 试跑估速 */
        IB_BARRIER();
        el = ib_now() - t0;
        if (el > 1e-6)
            K = (unsigned long long)(30000.0 * 4096.0 / el);
        else
            K = 1u << 16;
        if (K < 1024)
            K = 1024;
        if (K > (1ull << 26))
            K = 1ull << 26;
        el = 0;
        do {                          /* 定时长窗口, 只累计块执行时间 */
            t1 = ib_now();
            sig = c->b8(K);
            el += ib_now() - t1;
            n++;
        } while (el < window * 1e9);
        IB_BARRIER();
        sig = c->b8(4096);            /* 稳定签名(与批数无关, 跨机逐位可复现) */
        IB_BARRIER();
        ib_intest = 0;
        if (el > 0 && n * K > 0)
            ib_b8(grp, c->name, "OK", el / (double)(n * K), sig, "-");
        return 1;
    }
    ib_intest = 0;
    ib_crash(grp, c->name, "block8", (int)ib_sig_nr);
    return 0;
}

/* ---- sem: 单次执行语义对拍(不计时; 结果全宽签名逐位跨机比较) ---- */
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
        ib_sem(grp, c->name, "OK", s, c->tag);
        return 1;
    }
    ib_intest = 0;
    ib_crash(grp, c->name, "sem", (int)ib_sig_nr);
    return 0;
}

/* 逐用例: 门控 -> lat -> tput -> block8 -> sem(各自独立兜底: 崩只记该方式
 * CRASH, 不阻断其它); block8 为可空方式: 未注册 b8 的行三列留空, 不输出。
 * 该 case 全部方式完成后 flush 一行宽 CSV。 */
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
    ib_flush();
    ib_row_mode = 0;
    return allok;
}

/* 组尾行(kind=D): 29 列同布局, 只填 group/ok/total */
void ib_done(const char *grp, int ok, int tot)
{
    printf("D,%s,-,-,-,-,-,-,-,-,-,-,-,-,-,-,-,-,-,-,-,-,-,-,-,-,-,%d,%d\n",
           grp, ok, tot);
}

/* 跑完整个用例表, 输出 DONE 哨兵行(ok=全绿用例数, tot=过滤后总用例数) */
int ib_run_cases(const char *grp, const ib_case *cases, int n)
{
    int i, ok = 0, tot = 0;
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

/* ---------------- 参数解析 + 公共初始化 ---------------- */
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
            g_tput_sec = atof(argv[++i]);
            if (g_tput_sec <= 0)
                g_tput_sec = 0.5;
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
        } else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            fprintf(stderr, "usage: %s [--time SEC] [--iters N] "
                    "[--only=prefix[,..]] "
                    "[--no-lat|--no-tput|--no-b8|--no-sem]\n", argv[0]);
            exit(0);
        }
    }
}

/* ---------------- 全局定义 ----------------
 * 注意: 本文件按「每个可执行 = 恰好一个包含 ib.h 的翻译单元」设计(isb_*.c
 * 各自独立编译成独立可执行), 故可直接在此定义全局符号; 若将来单可执行
 * 链接多个 .c, 需把这些定义迁入独立的 .c。 */
double g_tput_sec = 0.5;
unsigned long long g_lat_iters = 2000000;
int g_do_lat = 1, g_do_tput = 1, g_do_sem = 1, g_do_b8 = 1;
const char *g_only = NULL;
const char *g_abi = "x86_64", *g_os = "linux";

#endif /* ISB_IB_H */
