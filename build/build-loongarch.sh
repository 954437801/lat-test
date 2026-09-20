#!/bin/bash
# build-loongarch.sh —— isbench 指令测试工具: loongarch64 交叉编译专用入口
#
# 做什么:
#   1) 确保 loongarch64-linux-gnu-gcc 交叉工具链在位(自动探测 -> 缺失则下载解压);
#   2) 把它加入 PATH 后调用 ./build.sh, 复用既有 Makefile 的 loongarch64 形态规则
#      (CC_loongarch64_linux + get_flags 的 -O2 -static 分支), 编出全静态 loongarch
#      ELF 落 dist/bin/<grp>-loongarch64_linux。
#
# 为什么单独一个脚本:
#   交叉工具链不在 apt 默认源里, 需按 loongnix 官方 tarball 自助安装; 这段"探测/下载/
#   解压/PATH"引导逻辑与组矩阵构建(build.sh)解耦, 只在真要出 loongarch 二进制时才跑,
#   保持 build.sh 对无工具链环境"优雅跳过 loongarch 形态"的既有契约不变。
#
# 用法:
#   bash build/build-loongarch.sh                 # 默认编 loongarch 在册组(cfloat cint)
#   bash build/build-loongarch.sh cfloat          # 指定组(可多个, 空格分隔)
#   GRPS="cfloat" bash build/build-loongarch.sh   # 同上的环境变量写法
#   仅准备工具链、不构建:  bash build/build-loongarch.sh --toolchain-only
#   构建模式(透传给 build.sh): --static / --dynamic / --both (缺省=两套都编译)
#
# 可用环境变量覆盖:
#   TOOLCHAIN_URL   loongnix 交叉工具链 tarball 地址(默认见下)
#   TOOLCHAIN_DIR   解压目标目录(默认 $HOME/toolchain/loongarch)
#   GRPS            要交叉编译的组(默认 "cfloat cint"; 目前只有这两个自包含探针可非 x86 编)
#
# 工具链探测策略: 先查 PATH, 再查 TOOLCHAIN_DIR, 都缺则按 TOOLCHAIN_URL 下载解压到 TOOLCHAIN_DIR。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."   # 本脚本在 build/, 锚定仓库根

# ---- 可覆盖配置 ----
TOOLCHAIN_URL="${TOOLCHAIN_URL:-https://ftp.loongnix.cn/toolchain/gcc/release/loongarch/gcc8/loongson-gnu-toolchain-8.3-x86_64-loongarch64-linux-gnu-rc1.6.tar.xz}"
TOOLCHAIN_DIR="${TOOLCHAIN_DIR:-$HOME/toolchain/loongarch}"
GRPS="${GRPS:-cfloat cint}"

TC_BIN="$TOOLCHAIN_DIR/bin/loongarch64-linux-gnu-gcc"

# ---- 参数: 支持位置参数覆盖 GRPS、--toolchain-only 与模式 flag(--static/--dynamic/--both) ----
TOOLCHAIN_ONLY=0
MODEFLAG=""
pos=()
for a in "$@"; do
    case "$a" in
        --toolchain-only) TOOLCHAIN_ONLY=1 ;;
        --static|--dynamic|--both) MODEFLAG="$a" ;;
        -*) echo "未知参数: $a (支持 --toolchain-only / --static / --dynamic / --both)" >&2; exit 1 ;;
        *) pos+=("$a") ;;
    esac
done
if [ "${#pos[@]}" -gt 0 ]; then
    GRPS="${pos[*]}"
fi

echo "=== isbench loongarch64 交叉编译 ==="
echo "工具链目录: $TOOLCHAIN_DIR"
echo "目标组:     $GRPS"
echo ""

# ---- 1. 工具链探测/安装(幂等) ----
setup_toolchain() {
    if command -v loongarch64-linux-gnu-gcc >/dev/null 2>&1; then
        echo "[OK] 交叉工具链已在 PATH: $(command -v loongarch64-linux-gnu-gcc)"
        return 0
    fi
    if [ -x "$TC_BIN" ]; then
        echo "[OK] 交叉工具链已存在于用户目录, 加入 PATH: $TOOLCHAIN_DIR/bin"
        export PATH="$TOOLCHAIN_DIR/bin:$PATH"
        return 0
    fi

    echo "[INFO] 未找到 loongarch64-linux-gnu-gcc, 开始准备工具链 ..."
    echo "  URL: $TOOLCHAIN_URL"
    local tmp="/tmp/loongarch-toolchain.tar.xz"
    mkdir -p "$TOOLCHAIN_DIR"

    # 下载(已下过且非空则复用, 免重下 35MB)
    if [ -s "$tmp" ]; then
        echo "[INFO] 复用已下载的工具链包: $tmp"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --show-progress -O "$tmp" "$TOOLCHAIN_URL"
    elif command -v curl >/dev/null 2>&1; then
        curl -L --progress-bar -o "$tmp" "$TOOLCHAIN_URL"
    else
        echo "[ERROR] 需要 wget 或 curl 下载工具链" >&2
        exit 1
    fi

    echo "[INFO] 解压到 $TOOLCHAIN_DIR (顶层目录 strip 1 层) ..."
    # 解 .tar.xz: 优先系统 xz; 缺 xz(如精简系统无 xz-utils 且无法 sudo apt)则退回
    # python3 的 lzma 模块(纯标准库, 不需 root)先转 .tar 再 tar 解。
    if command -v xz >/dev/null 2>&1; then
        tar -xJf "$tmp" -C "$TOOLCHAIN_DIR" --strip-components=1
    elif command -v python3 >/dev/null 2>&1; then
        echo "[INFO] 未见 xz, 改用 python3 lzma 解压"
        python3 - "$tmp" "$TOOLCHAIN_DIR" <<'PY'
import lzma, sys, subprocess, os
xz, outdir = sys.argv[1], sys.argv[2]
tar = "/tmp/loongarch-toolchain.tar"
with lzma.open(xz) as f, open(tar, "wb") as o:
    while True:
        chunk = f.read(1 << 20)
        if not chunk:
            break
        o.write(chunk)
subprocess.check_call(["tar", "-xf", tar, "-C", outdir, "--strip-components=1"])
os.remove(tar)
PY
    else
        echo "[ERROR] 缺 xz 也缺 python3, 无法解压 .tar.xz; 请装 xz-utils 或 gcc-loongarch64-linux-gnu" >&2
        exit 1
    fi
    rm -f "$tmp"
    export PATH="$TOOLCHAIN_DIR/bin:$PATH"

    if command -v loongarch64-linux-gnu-gcc >/dev/null 2>&1; then
        echo "[OK] 工具链安装成功: $(loongarch64-linux-gnu-gcc --version | head -1)"
    else
        echo "[ERROR] 解压后仍未见 loongarch64-linux-gnu-gcc, 请核对 tarball 结构或设 TOOLCHAIN_DIR" >&2
        echo "        (期望: $TC_BIN)" >&2
        exit 1
    fi
}

setup_toolchain
echo ""

if [ "$TOOLCHAIN_ONLY" = 1 ]; then
    echo "=== --toolchain-only: 仅准备工具链, 不构建 ==="
    echo "后续可直接: PATH=\"$TOOLCHAIN_DIR/bin:\$PATH\" build/build.sh --groups=\"$GRPS\""
    exit 0
fi

# ---- 2. 复用 build.sh 的 loongarch64 形态规则构建 ----
# build.sh 的 forms_of() 命中 GRP_FORMS 专属形态(i386/x64/loongarch64)且 HAVE_LOONG 现
# 已为真(PATH 里能查到 gcc), 于是 loongarch64 形态纳入构建矩阵; Makefile 用
# CC_loongarch64_linux=loongarch64-linux-gnu-gcc + LOONGFLAGS="-O2"(静态/动态由 link_static 按 STATIC_位定)。
# 已纳入 PATH(setup_toolchain 里 export), build.sh 自身的 command -v 探测会因此为真。
echo "=== 调用 build.sh 构建 loongarch64(该组其余形态一并重编, 无害) ==="
# MODEFLAG 为空时 build.sh 默认两套都编译(static dynamic)。
bash build/build.sh --groups="$GRPS" $MODEFLAG

# ---- 3. 产物核对 ----
# 静态名 <g>-loongarch64_linux: 非 --dynamic 时核;
# 动态名 <g>-loongarch64_linux_dy: 非 --static 时核(默认两套都核)。
echo ""
echo "=== loongarch64 产物 ==="
rc=0
check_one() {
    local b="$1"
    if [ -f "$b" ]; then
        echo "  [OK] $b"
        file "$b" 2>/dev/null | sed 's/^/        /' || true
    else
        echo "  [MISS] $b (该组无 loongarch64 形态, 或工具链/编译失败)" >&2
        rc=1
    fi
}
for g in $GRPS; do
    [ "$MODEFLAG" = "--dynamic" ] || check_one "dist/bin/${g}-loongarch64_linux"
    [ "$MODEFLAG" = "--static" ]  || check_one "dist/bin/${g}-loongarch64_linux_dy"
done
echo ""
echo "拷到 loongarch64 目标机直接跑(原生, 非翻译): ./<产物> --iters 200000"
exit $rc
