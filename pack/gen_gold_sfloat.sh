#!/bin/bash
# gen_gold_sfloat.sh —— 生成 isbench sfloat 组 8 槽真值表 src/sfloat/isb_sfloat_kat.h(须在真 x86_64 上跑)
#
# 口径: 真值只来自硬件/独立软实现(生成器源码 src/sfloat/gen_gold_sfloat.c), 与被测的 SoftFloat 库解耦:
#   f64 <- x86 SSE double; f80 <- x86 x87 long double(80); f128 <- GCC __float128(非硬件)。
# 生成前形状自检 + LF 校验 + 幂等复跑比对, 任一不过 -> 保留旧表不回退(仿 pack/gen_val.sh)。
#
# 用法: bash pack/gen_gold_sfloat.sh
set -e

TOOL="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$TOOL/src"
SG="$SRC/sfloat"   # sfloat 组源码目录(探针 + slots + kat 均在此)
CC="${CC:-gcc}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---- 守卫: 必须是真 x86_64(本仓约定: 真值只能在真 x86 采集; 排除 LATX/其它架构) ----
arch="$(uname -m)"
if [ "$arch" != "x86_64" ]; then
    echo "FAIL: gen_gold 需真 x86_64(当前 $arch) -> 不改真值表" >&2
    exit 1
fi

# ---- 编译并运行生成器(真值来源 = 硬件 double/long double + __float128) ----
"$CC" -O2 -Wall -I"$SRC" -I"$SG" "$SG/gen_gold_sfloat.c" \
    -o "$TMP/gen_gold" -lm -lquadmath 2>"$TMP/build.log" || {
        echo "FAIL: gen_gold_sfloat.c 编译失败, 见下:" >&2; head -30 "$TMP/build.log" >&2; exit 1; }
"$TMP/gen_gold" > "$TMP/raw.h"
tr -d '\r' < "$TMP/raw.h" > "$TMP/kat.h"        # 归一化为 LF(本仓一律 LF)

# ---- 形状校验 ----
ns=$(grep -c '^static const char \*const gold_' "$TMP/kat.h" || true)
nr=$(grep -cE '^    "' "$TMP/kat.h" || true)
[ "$ns" = 15 ] || { echo "FAIL: gold 表数=$ns 应=15 -> 不覆盖旧表" >&2; exit 1; }
[ "$nr" = $((ns * 8)) ] || { echo "FAIL: 槽行=$nr 应=$((ns * 8)) -> 不覆盖旧表" >&2; exit 1; }
grep -q '^#endif' "$TMP/kat.h" || { echo "FAIL: 生成物不完整 -> 不覆盖旧表" >&2; exit 1; }
cr=$(tr -dc '\r' < "$TMP/kat.h" | wc -c)
[ "$cr" = 0 ] || { echo "FAIL: 生成物带 $cr 个 CR -> 不覆盖旧表" >&2; exit 1; }

# ---- 回填(备份旧表, 幂等复跑比对) ----
[ -f "$SG/isb_sfloat_kat.h" ] && cp "$SG/isb_sfloat_kat.h" "$TMP/bak.h"
cp "$TMP/kat.h" "$SG/isb_sfloat_kat.h"
echo "已生成 $SG/isb_sfloat_kat.h (gold 表=$ns, 槽行=$nr)"
if [ -f "$TMP/bak.h" ]; then
    cmp -s "$TMP/bak.h" "$SG/isb_sfloat_kat.h" \
        && echo "注: 与旧表逐字节相同(幂等)" || echo "注: 与旧表不同(首采/新口径)"
fi
