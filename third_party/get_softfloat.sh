#!/bin/bash
# get_softfloat.sh —— 取回第三方 SoftFloat-3e 源码到 third_party/softfloat-3e/
#
# 为什么需要: isbench 的 sfloat 组要编 Berkeley SoftFloat-3e 的精确源集(软浮点
#   f64/f80/f128 的延迟与正确性基准)。该源树 300+ 文件、属第三方, 不入库(见 .gitignore);
#   首次构建前先跑本脚本取回, 之后即可离线复用。项目自有集成层(platform.h /
#   sf_sources.mk)在 src/sfloat/, 不在本目录。
#
# 源(多源 fallback, 先主后备):
#   1) gitee 镜像 luobing4365/berkeley-softfloat-3 @ 5c06db33(与本仓锁定快照同源)
#   2) github 官方 ucb-bar/berkeley-softfloat-3 tag 3e
#   3) github 官方 ucb-bar/berkeley-softfloat-3 master
#   备源与主源快照可能有细微差异; src/sfloat/sf_sources.mk 锁的是精确 .c 清单, 取到后
#   以 `bash build/build.sh --groups=sfloat` 编过为准(形状自检不过会直接报错)。
#
# 用法: bash third_party/get_softfloat.sh [--force]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="$HERE/softfloat-3e"
PIN="5c06db33fc1e2130f67c045327b0ec949032df1d"

if [ "${1:-}" = "--force" ]; then rm -rf "$DEST"; fi
if [ -f "$DEST/source/include/softfloat.h" ] && [ -f "$DEST/source/8086-SSE/specialize.h" ]; then
    echo "已存在 $DEST (跳过; 加 --force 重取)"
    exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

dl() { # dl <url> <out>
    timeout 120 python3 - "$1" "$2" <<'PY'
import sys, urllib.request
url, out = sys.argv[1], sys.argv[2]
try:
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    data = urllib.request.urlopen(req, timeout=90).read()
    open(out, 'wb').write(data)
    print('OK', url, len(data))
except Exception as e:
    print('FAIL', url, repr(e)[:120]); sys.exit(1)
PY
}

TGZ="$TMP/sf.tar.gz"
ok=0
for u in \
  "https://gitee.com/luobing4365/berkeley-softfloat-3/repository/archive/${PIN}.tar.gz" \
  "https://github.com/ucb-bar/berkeley-softfloat-3/archive/refs/tags/3e.tar.gz" \
  "https://codeload.github.com/ucb-bar/berkeley-softfloat-3/tar.gz/refs/heads/master"
do
    if dl "$u" "$TGZ"; then ok=1; break; fi
done
[ "$ok" = 1 ] || { echo "FAIL: 全部源下载失败" >&2; exit 1; }

tar xzf "$TGZ" -C "$TMP"
top="$(find "$TMP" -maxdepth 1 -mindepth 1 -type d -print -quit)"
[ -n "$top" ] || { echo "FAIL: 解压未得到目录" >&2; exit 1; }

# ---- 形状自检(缺一即拒, 不落半棵树) ----
for f in source/include/softfloat.h source/include/softfloat_types.h \
         source/8086-SSE/specialize.h source/8086-SSE/s_roundPackToF64.c; do
    [ -f "$top/$f" ] || { echo "FAIL: 缺 $f" >&2; exit 1; }
done
n=$(find "$top/source" -name '*.c' | wc -l)
echo "取到 SoftFloat-3e 源: source/*.c = $n"

rm -rf "$DEST"
mv "$top" "$DEST"
echo "已就位 $DEST"
