#!/bin/bash
# gen_val.sh <grp> [iters] [time_ms] —— 统一功能真值采集(本地真 x86)
#
# 合并早期采集脚本(采集 K 行)与 pack/gen_gold_pmul.sh(探针自出表)的思路, 统一为:
#   1) 编 isb_<grp>.c 的 x86_64-linux 采集版;
#   2) 跑 `<探针> --gen-gold` —— 探针忽略现表, 逐 (用例,槽) 把 got 打成 dbg 段;
#   3) 收割 dbg/src=got 行 -> 生成 src/<grp>/isb_<grp>_kat.h(每词干一个 #define 列表).
#
# 口径(功能测试标准 §2/§5):
#   - 真值单元 = 10 字: i0,i1,i2,i3,inf,o0,o1,o2,o3,outf(见 ib_core.h ib_kv);
#   - 只采 x86_64 一份表, i386 共用(真值若依赖 ABI, i386 一跑即 KATFAIL 暴露);
#   - 采集机守卫在探针内(--gen-gold 在非 x86_64 机器名上拒跑);
#   - 生成物形状自检 + LF 校验不过 -> 不覆盖旧表.
#
# 用法: bash pack/gen_val.sh alu
set -e
g="${1:?用法: gen_val.sh <grp> [iters] [time_ms]}"
IT="${2:-2000}"
TM="${3:-20}"
SRC="${SRC:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../src" && pwd)}"
CF="-O2 -static -msse2 -mno-avx -mno-avx2 -mno-fma"
N=8
cd "$SRC"
# i386 ELF 已能采集: 统一用 gcc 编 ELF(不再绕 Windows PE)
# x87 组必须 i386 编译(源码 #error 限制), 其他组用 x86_64
if [ "$g" = "x87" ]; then
    CCD="gcc"; CFLAGS_EXTRA="-m32"; SFX=""; OUTDIR="/tmp"
else
    CCD="gcc"; CFLAGS_EXTRA=""; SFX=""; OUTDIR="/tmp"
fi
BIN="$OUTDIR/gv_${g}${SFX}"
CSV="$OUTDIR/gv_${g}.csv"

$CCD $CF $CFLAGS_EXTRA -I"$SRC" -Wall -o "$BIN" "$g/isb_$g.c" 2>"/tmp/gv_${g}.build.log" || {
    echo "FAIL: 采集版编译失败, 见 /tmp/gv_${g}.build.log"; head -20 "/tmp/gv_${g}.build.log"; exit 1; }
# 退出码不参与判定(有些组把全绿用例数当退出码), 吃下它
"$BIN" --gen-gold --iters "$IT" --time "$TM" > "$CSV" 2>&1 || true

nline=$(grep -c '^dbg,' "$CSV" || true)
echo "dbg 行=$nline (采集态应对每个已接 KAT 的用例吐 $N 行 got)"
# Windows PE 走文本模式 stdout -> 带 CR; 归一化后再收割(本仓一律 LF)
tr -d '\r' < "$CSV" > "$CSV.lf"

# 收割: dbg,<grp>,<abi>,<case>,<stem>,<kk>,i0..i3,inf,o0..o3,outf,<src>
awk -F, -v GRP="$g" -v N="$N" '
BEGIN {
    print "/* isb_" GRP "_kat.h —— " GRP " 组 KAT 真值表(生成物, 请勿手改) */";
    print "/* 由 pack/gen_val.sh 在真 x86 上用 <探针> --gen-gold 采集 dbg(src=got) 行生成。";
    print "   字段序 = ib_kv(10 字): i0,i1,i2,i3,inf,o0,o1,o2,o3,outf。";
    print "   判定只比输出 o0..o3+outf; in 存表仅作错档核。两 ABI 共用一份。 */";
    print "#ifndef ISB_" toupper(GRP) "_KAT_H";
    print "#define ISB_" toupper(GRP) "_KAT_H";
    print "";
}
$1 == "dbg" && $17 == "got" {
    stem = $5; k = $6 + 0;
    if (!(stem in seen)) { seen[stem] = 1; ord[++n] = stem }
    v[stem SUBSEP k] = $7"|"$8"|"$9"|"$10"|"$11"|"$12"|"$13"|"$14"|"$15"|"$16;
    cnt[stem]++;
    next
}
END {
    err = 0;
    for (i = 1; i <= n; i++)
        if (cnt[ord[i]] != N) {
            printf "ERR %s: 只有 %d 组(应 %d)\n", ord[i], cnt[ord[i]], N > "/dev/stderr";
            err = 1;
        }
    if (err) { print "FAIL: 组数不齐, 生成物不覆盖旧表" > "/dev/stderr"; exit 1 }
    for (i = 1; i <= n; i++) {
        s = ord[i];
        printf "#define IB_KAT_%s { \\\n", s;
        for (k = 0; k < N; k++) {
            split(v[s SUBSEP k], f, "|");
            printf "    { 0x%sULL, 0x%sULL, 0x%sULL, 0x%sULL, 0x%sULL, 0x%sULL, 0x%sULL, 0x%sULL, 0x%sULL, 0x%sULL }%s\n", \
                   f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9], f[10], \
                   (k == N - 1 ? " \\" : ", \\");
        }
        print "}";
        print "";
    }
    print "#endif /* ISB_" toupper(GRP) "_KAT_H */";
    printf "OK: %d 个词干入表\n", n > "/dev/stderr";
}
' "$CSV.lf" > "/tmp/isb_${g}_kat.plain"

# 形状 + LF 校验: 不过一律不覆盖旧表
if [ ! -s "/tmp/isb_${g}_kat.plain" ] || ! grep -q '^#endif' "/tmp/isb_${g}_kat.plain"; then
    echo "FAIL: 生成物不完整 -> 不覆盖旧表"; exit 1
fi
ns=$(grep -c '^#define IB_KAT_' "/tmp/isb_${g}_kat.plain")
nr=$(grep -c '^    {' "/tmp/isb_${g}_kat.plain")
[ "$ns" != 0 ] && [ "$nr" = "$((ns * N))" ] || {
    echo "FAIL: 词干=$ns 数据行=$nr 应=$((ns * N)) -> 不覆盖旧表"; exit 1; }
cr=$(tr -dc '\r' < "/tmp/isb_${g}_kat.plain" | wc -c)
[ "$cr" = 0 ] || { echo "FAIL: 生成物带 $cr 个 CR(本仓 LF) -> 不覆盖旧表"; exit 1; }

[ -f "$SRC/$g/isb_${g}_kat.h" ] && cp "$SRC/$g/isb_${g}_kat.h" "/tmp/gv_${g}_bak.h"
cp "/tmp/isb_${g}_kat.plain" "$SRC/$g/isb_${g}_kat.h"
echo "已回填 $SRC/$g/isb_${g}_kat.h 词干=$ns 行数=$(wc -l < "$SRC/$g/isb_${g}_kat.h") (旧表备份 /tmp/gv_${g}_bak.h)"
if [ -f "/tmp/gv_${g}_bak.h" ]; then
    # 逐字节相同 = 幂等(同一台真机重跑必同)
    cmp -s "/tmp/gv_${g}_bak.h" "$SRC/$g/isb_${g}_kat.h" && echo "注: 与旧表逐字节相同(幂等)" || echo "注: 与旧表不同(新口径/首采)"
fi

echo "== 复编该组 + 看 kat 是否转 OK =="
$CCD $CF $CFLAGS_EXTRA -I"$SRC" -o "$OUTDIR/gv_${g}_v${SFX}" "$g/isb_$g.c" || { echo "FAIL: 回填后编译不过"; exit 1; }
"$OUTDIR/gv_${g}_v${SFX}" --iters "$IT" --time "$TM" > "/tmp/gv_${g}_v.csv" 2>&1 || true
nfail=$(grep -c 'KATFAIL' "/tmp/gv_${g}_v.csv" || true)
nok=$(awk -F, '$1=="data"{next} END{}' /dev/null; grep -o 'OK' "/tmp/gv_${g}_v.csv" | wc -l)
echo "回填后: KATFAIL 行=$nfail (期望 0)"
[ "$nfail" = 0 ] || { echo "FAIL: 回填后仍有 KATFAIL, 检查采集口径"; exit 1; }
