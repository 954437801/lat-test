/* gen_gold_sfloat.c —— 生成 isbench sfloat 组的 8 槽真值表 src/sfloat/isb_sfloat_kat.h(真 x86 本地)
 *
 * 真值口径(逐位, 与探针 src/sfloat/isb_sfloat.c 的 got 同字符串格式, 逐字符 memcmp):
 *   sf_f64_*  <- 真 x86 SSE 硬件 double(IEEE-754 binary64, round-to-nearest-even);
 *   sf_f80_*  <- 真 x86 x87 硬件 long double(extended 80, precision=80) —— 与 SoftFloat
 *                的 extF80(extFloat80_t)同口径, 实测逐位一致;
 *   sf_f128_* <- GCC __float128(libgcc soft-fp, 与 SoftFloat 相互独立的第二实现)。
 *                x86 无 128 位硬件, 故此列为"非硬件真值", 已在表头与文档中标注。
 *   sf_f80_sin / sf_f128_sin 为仅测速用例(无真值), 不入表。
 *
 * 字符串格式(必须与探针 got 完全一致):
 *   f64  : %016llx                 (v)
 *   f80  : %04x_%016llx            (signExp, signif)
 *   f128 : %016llx_%016llx         (v[1], v[0]; 高字在前)
 *
 * 本程序不使用 SoftFloat: 真值只来自硬件/独立软实现, 与被测库解耦。
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <quadmath.h>
#include "isb_sfloat_slots.h"   /* 槽输入唯一来源(同目录, 免 -I 依赖) */

/* ---- 结果 -> 规范字符串 ---- */
static void f64_str(double r, char *o, size_t n)
{
    uint64_t u;
    memcpy(&u, &r, 8);
    snprintf(o, n, "%016llx", (unsigned long long)u);
}
static void f80_str(long double r, char *o, size_t n)
{
    unsigned char b[16];
    uint64_t sig;
    uint16_t se;
    memset(b, 0, sizeof b);
    memcpy(b, &r, sizeof r);           /* x86-64 sizeof(long double)=16, 有效 10 字节 */
    memcpy(&sig, b, 8);                /* 低 8 字节 = 尾数 */
    memcpy(&se, b + 8, 2);             /* 高 2 字节 = 符号+指数 */
    snprintf(o, n, "%04x_%016llx", (unsigned)se, (unsigned long long)sig);
}
static void f128_str(__float128 r, char *o, size_t n)
{
    uint64_t w[2];
    memcpy(w, &r, 16);
    snprintf(o, n, "%016llx_%016llx",
             (unsigned long long)w[1], (unsigned long long)w[0]);
}

/* ---- 用例表: width 0=f64/1=f80/2=f128; kind 0=add 1=sub 2=mul 3=div 4=sqrt ---- */
struct gen { const char *name; int width; int kind; };
static const struct gen G[] = {
    { "sf_f64_add",  0, 0 }, { "sf_f64_sub",  0, 1 }, { "sf_f64_mul",  0, 2 },
    { "sf_f64_div",  0, 3 }, { "sf_f64_sqrt", 0, 4 },
    { "sf_f80_add",  1, 0 }, { "sf_f80_sub",  1, 1 }, { "sf_f80_mul",  1, 2 },
    { "sf_f80_div",  1, 3 }, { "sf_f80_sqrt", 1, 4 },
    { "sf_f128_add", 2, 0 }, { "sf_f128_sub", 2, 1 }, { "sf_f128_mul", 2, 2 },
    { "sf_f128_div", 2, 3 }, { "sf_f128_sqrt", 2, 4 },
};
#define NG ((int)(sizeof G / sizeof G[0]))

static void compute(int width, int kind, int k, char *o, size_t n)
{
    volatile double ad = sf_slot_a[k], bd = sf_slot_b[k];
    if (width == 0) {
        volatile double a = ad, b = bd, r;
        switch (kind) {
            case 0: r = a + b; break; case 1: r = a - b; break;
            case 2: r = a * b; break; case 3: r = a / b; break;
            default: r = sqrt(a); break;
        }
        f64_str(r, o, n);
    } else if (width == 1) {
        volatile long double a = ad, b = bd, r;
        switch (kind) {
            case 0: r = a + b; break; case 1: r = a - b; break;
            case 2: r = a * b; break; case 3: r = a / b; break;
            default: r = sqrtl(a); break;
        }
        f80_str(r, o, n);
    } else {
        volatile __float128 a = ad, b = bd, r;
        switch (kind) {
            case 0: r = a + b; break; case 1: r = a - b; break;
            case 2: r = a * b; break; case 3: r = a / b; break;
            default: r = sqrtq(a); break;
        }
        f128_str(r, o, n);
    }
}

int main(void)
{
    int i, k;

    printf("/* isb_sfloat_kat.h —— isbench sfloat 组 8 槽真值表(生成物, 请勿手改) */\n");
    printf("/* 由 pack/gen_gold_sfloat.sh 在真 x86_64 上以硬件结果采集:\n");
    printf("     sf_f64_*  = x86 SSE 硬件 double;\n");
    printf("     sf_f80_*  = x86 x87 硬件 long double(extended 80, precision=80);\n");
    printf("     sf_f128_* = GCC __float128(libgcc soft-fp, 独立第二软实现; 非硬件真值)。\n");
    printf("   字符串格式与探针 got 逐字符比对: f64=%%016llx, f80=%%04x_%%016llx,\n");
    printf("   f128=%%016llx_%%016llx(高字在前)。sin 两条仅测速, 不入表。*/\n");
    printf("#ifndef ISB_SFLOAT_KAT_H\n#define ISB_SFLOAT_KAT_H\n\n");
    printf("#define SF_KAT_N %d\n\n", SF_KAT_N);

    for (i = 0; i < NG; i++) {
        printf("static const char *const gold_%s[SF_KAT_N] = {\n", G[i].name);
        for (k = 0; k < SF_KAT_N; k++) {
            char buf[48];
            compute(G[i].width, G[i].kind, k, buf, sizeof buf);
            printf("    \"%s\"%s\n", buf, (k == SF_KAT_N - 1) ? "" : ",");
        }
        printf("};\n\n");
    }
    printf("#endif /* ISB_SFLOAT_KAT_H */\n");
    return 0;
}
