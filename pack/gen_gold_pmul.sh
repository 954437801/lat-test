#!/bin/bash
# gen_gold_pmul.sh —— 回填 pmul 组真值表: 调**本组探针自己的** --gen-gold, 自检全过才回填
#
# 用法:
#   bash pack/gen_gold_pmul.sh                  # 生成 + 自检 + 回填 + 复编 + 闭环冒烟
#   bash pack/gen_gold_pmul.sh --ver mytag      # 换版本串(随 meta 行 pmul_ver 入库)
#   bash pack/gen_gold_pmul.sh --dry-run        # 只生成并自检, 不动工作区的表
#
# 为什么公式不在这里再写一遍: 档位表只能有一份。外面另写一份公式的生成器, 早晚与
# 探针的 pmul_build_tiers() 漂移(改了那边忘了这边 = 真值错档 = A 档真值判 B 档结果)。
# 所以真值由探针自己出, 本脚本只管: 调它、验它的生成物、备份回填、复编闭环。
# 详见 src/pmul/isb_pmul.c 第 8b 节。
#
# 判据链(四道, 任一道不过工作区一个字节都不动):
#   1) 探针内部的出表前置检查: 采集机机器名 = x86_64(排除 LATX 等翻译层) + CPUID
#      有 pclmul + 96 档的积都不超 128 位; 不通过时它自己非 0 退出且不打一个字节。
#      注: 原先这里的"硬件 == 逐位模型复算"与两条恒等式互检已按 2026-09-10 定案
#      删除 —— 真机(PE/WSL/box31)采集进来的常量就是判定标准, 实测不符直接出 FAIL,
#      不再拿第二套实现去证明第一套没算错(objdump 静态核查同批取消)。
#   2) 生成物形状: #endif 在位 / N=96 / 数据行数=N / 每行恰好 4 个 16 位定宽 16 进制
#      字段 / CR 字节数=0(本仓行尾统一 LF) / 单独编译得过。
#   3) 幂等复核: 连跑两次 sha256 必须相同 —— 生成物不含日期等易变量, 任何人重跑都能
#      逐字节对上这份真值(这才是"可复核"的意思, 不是靠人转述)。
#   4) 回填后复编在册四形态, 再跑一次看全档 st=OK(探针判自己回填的表 = 闭环)。
set -euo pipefail
T="$(cd "$(dirname "$0")/.." && pwd)"
S="$T/src"
OUT="$S/pmul/isb_pmul_gold.h"
CF="-O2 -static -msse2 -mno-avx -mno-avx2 -mno-fma"
VER=""
DRY=0
want_n=96
for a in "$@"; do
    case "$a" in
        --ver=*)  VER="${a#*=}" ;;
        --ver)    echo "请用 --ver <串>(本脚本按 --ver=STR 形式取)" >&2; exit 1 ;;
        --dry-run) DRY=1 ;;
        *) echo "未知参数: $a (支持 --ver=STR / --dry-run)" >&2; exit 1 ;;
    esac
done
TMP="$(mktemp -d /tmp/pmul-gold.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

command -v gcc >/dev/null || { echo "FAIL: 缺 gcc(本脚本在 WSL 跑)" >&2; exit 1; }

echo "== 1/4 编探针(x86_64 linux, 与 build.sh 同一套 CFLAGS) =="
gcc $CF -I"$S" -Wall -o "$TMP/gengold" "$S/pmul/isb_pmul.c"
echo "   编译过(告警数=$( { gcc $CF -I"$S" -Wall -c "$S/pmul/isb_pmul.c" -o "$TMP/neg.o"; } 2>&1 | grep -c warning: || true ))"

# --ver 空时不传, 让探针用自己的默认(selfgen-hw-<abi>)—— 默认串里带 abi, 比脚本硬写一个更准
if [ -n "$VER" ]; then
    ARGS=(--gen-gold --gold-ver "$VER")
else
    ARGS=(--gen-gold)
fi

echo "== 2/4 生成 + 形状自检 =="
# 用 if ! 包起来而不是裸跑后读 $?: 本脚本开了 set -e, 裸跑失败会在下一行之前
# 就退出, 那句"探针自己拒绝出表"的人话永远打不出来(非 0 退出码本身是对的, 只是丢日志)
if ! "$TMP/gengold" "${ARGS[@]}" > "$TMP/gold.h" 2> "$TMP/gen.err"; then
    rc=$?
    cat "$TMP/gen.err" >&2
    echo "FAIL: --gen-gold rc=$rc(自检未过, 探针自己拒绝出表) -> 不回填" >&2
    exit 1
fi
cat "$TMP/gen.err"
if ! grep -q '^#endif' "$TMP/gold.h"; then
    echo "FAIL: 生成物缺 #endif(中途退出?) -> 不回填" >&2; exit 1
fi
gn=$(grep -m1 -oE '^#define IB_PMUL_GOLD_N [0-9]+' "$TMP/gold.h" | awk '{print $3}')
rows=$(grep -cE '^    \{ 0x[0-9a-f]{16}ULL, 0x[0-9a-f]{16}ULL, 0x[0-9a-f]{16}ULL, 0x[0-9a-f]{16}ULL \},? \\$' "$TMP/gold.h")
[ "$gn" = "$want_n" ] || { echo "FAIL: 生成物 N=$gn 应 $want_n -> 不回填" >&2; exit 1; }
[ "$rows" = "$want_n" ] || { echo "FAIL: 数据行=$rows 应 $want_n(有行形状不合文法?) -> 不回填" >&2; exit 1; }
cr=$(tr -dc '\r' < "$TMP/gold.h" | wc -c)
[ "$cr" = 0 ] || { echo "FAIL: 生成物带 $cr 个 CR(本仓行尾 = LF) -> 不回填" >&2; exit 1; }
printf '#include "%s"\nint main(void){return (int)(g_pmul_gold[IB_PMUL_GOLD_N-1][3]&1);}\n' \
    "$TMP/gold.h" > "$TMP/shape.c"
gcc -O1 -c "$TMP/shape.c" -o "$TMP/shape.o" || { echo "FAIL: 生成物单独编译不过" >&2; exit 1; }
echo "   N=$gn 数据行=$rows CR=$cr 单独编译 OK"

echo "== 3/4 幂等复核(重跑一次比 sha256) =="
"$TMP/gengold" "${ARGS[@]}" > "$TMP/gold2.h" 2>/dev/null
h1=$(sha256sum "$TMP/gold.h" | cut -c1-16)
h2=$(sha256sum "$TMP/gold2.h" | cut -c1-16)
if [ "$h1" != "$h2" ]; then
    echo "FAIL: 重跑生成物不同($h1 != $h2) -> 生成里混进了易变量, 不回填" >&2
    exit 1
fi
echo "   两次逐字节相同 sha256=$h1..."
if [ "$DRY" = 1 ]; then
    cp "$TMP/gold.h" "/tmp/isb_pmul_gold.dryrun.h"
    echo "== --dry-run: 未动工作区, 生成物留在 /tmp/isb_pmul_gold.dryrun.h =="
    exit 0
fi

echo "== 4/4 备份回填 + 复编四形态 + 闭环看 st =="
bak="/tmp/isb_pmul_gold.bak.$(date +%s).h"
cp "$OUT" "$bak"
cp "$TMP/gold.h" "$OUT"
echo "   已回填 $OUT (旧表备份 $bak)"
if ! (cd "$T" && bash build/build.sh --groups=pmul > "$TMP/build.log" 2>&1); then
    echo "FAIL: 回填后构建不过 -> 回滚旧表" >&2
    tail -15 "$TMP/build.log"
    cp "$bak" "$OUT"
    exit 1
fi
grep -E '实产自校|BUILD OK' "$TMP/build.log"
# 闭环只跑一次、存文件、再对文件计数: 原来那两段管道在 set -e 下是两颗地雷
#   一 grep 不命中就整脚本暴退(一句诊断都不会留下), 二两次分开跑还可能拿到不同结果
run_csv="$TMP/run.csv"
"$T/dist/bin/pmul-x64_linux" --time 2 --family rnd,dual \
    --impl ref,hw,t4,t8 >"$run_csv" 2>"$TMP/run.err" || true
sed -n '1,6p' "$TMP/run.err"
n_ok=$(grep -o 'status=OK' "$run_csv" | wc -l || true)
n_bad=$(grep -oE 'status=(FAIL|NOGOLD|TIERMISMATCH|CRASH|HOSTUNSUPPORTED)' "$run_csv" \
        | sort | uniq -c | tr '\n' ' ' || true)
# 值行认 `^data,` 而不是认 abi 开头: 探针输出已改成"第一列 = 记录类型
# (meta|field|label|data)"的自描述分段协议, 数据行不再以 abi 字面值起头。
n_row=$(grep -cE '^data,' "$run_csv" || true)
# 期望条数算得出来源: 4 实现 x (dual 16 档 + rnd 4 档) = 80 个 kat 单元; 行 = 4x2 = 8
want_ok=$((4 * (16 + 4)))
want_row=$((4 * 2))
echo "   闭环: 值行=$n_row(应 $want_row) status=OK=$n_ok(应 $want_ok) 非 OK 统计=${n_bad:-（无）}"
if [ "$n_ok" != "$want_ok" ] || [ "$n_row" != "$want_row" ]; then
    echo "FAIL: 闭环未过 -> 回滚旧表(工作区不留一份判不了对错的表)" >&2
    grep -m3 -oE '[a-z0-9]+=in=[^,]*' "$run_csv" | head -3 >&2 || true
    cp "$bak" "$OUT"
    exit 1
fi
echo "== gen_gold OK: 真值表已回填且探针自判全绿 =="
