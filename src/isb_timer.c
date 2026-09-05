/* isb_timer.c —— isbench 组6: 计时源开销/稳定性 + 进程生命周期计时
 *
 * 迁移来源: startup_probe.c(进程启动计时语义), tmelf.c/tmwin.c(CLOCK_MONOTONIC
 *           与 QPC 可靠性验证, round1 结论: 两者在 wine+LATX 下可靠, rdtsc 被伪造)。
 * 输出: 全 diag 行 —— 进程内首个时钟读(冷)、时钟单次开销、连续读间隔抖动统计。
 * 启动(exec->main)墙钟由 run.sh 记录首行输出时刻, 与本组 first_read 呼应。
 */
#include "ib.h"

int main(int argc, char **argv)
{
    enum { N = 200000, NJ = 20000 };
    double t0, t1, el, mn, mx, sum;
    unsigned long long i;
    char a[64], b[64], c[64];

    ib_init(argc, argv);
    ib_hdr("timer", 0);   /* 表头必须是 stdout 首行(单表 CSV 协议) */

    /* 冷: 进程内首次时钟读的代价(首次 syscall/vDSO 或翻译器时钟桥初始化摊分) */
    t0 = ib_now();
    t1 = ib_now();
    snprintf(a, sizeof a, "%.1f", t1 - t0);
    ib_out("timer", "first_read", "diag", "OK", a, "ns", "-", "-", "-",
           "gap-to-second-read");

    /* 稳态: ib_now() 单次开销(连续 N 次, 平均) */
    t0 = ib_now();
    for (i = 0; i < N; i++)
        (void)ib_now();
    el = ib_now() - t0;
    snprintf(a, sizeof a, "%.2f", el / (double)N);
    ib_diag("timer", "now_overhead", "OK", el / (double)N, "ns/op", "-");

    /* 一致性: 相邻读间隔的 min/avg/max(粗粒度或跳变会放大 max) */
    mn = 1e300; mx = 0; sum = 0;
    t0 = ib_now();
    for (i = 0; i < NJ; i++) {
        t1 = ib_now();
        el = t1 - t0;
        t0 = t1;
        if (el < mn) mn = el;
        if (el > mx) mx = el;
        sum += el;
    }
    snprintf(a, sizeof a, "%.1f", mn);
    ib_diag("timer", "read_gap_min", "OK", mn, "ns", a);
    snprintf(a, sizeof a, "%.1f", sum / (double)NJ);
    ib_diag("timer", "read_gap_avg", "OK", sum / (double)NJ, "ns", a);
    snprintf(a, sizeof a, "%.1f", mx);
    ib_diag("timer", "read_gap_max", "OK", mx, "ns", a);

    /* 生命周记时: 到 main 尾部的单调时间(进程驻留, 与 run.sh wall 对照) */
    t0 = ib_now();
    snprintf(a, sizeof a, "%.3f", t0 / 1e6);
    ib_diag("timer", "uptime_at_exit", "OK", t0 / 1e6, "ms", "-");

    ib_done("timer", 5, 5);
    (void)argc; (void)b; (void)c;
    return 0;
}
