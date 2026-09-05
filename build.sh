#!/bin/bash
# isbench build.sh —— WSL 静态交叉构建矩阵 -> dist/(LF/UTF-8, 禁 CRLF)
#
# 用法:
#   ./build.sh                # 全矩阵 6 组 x 4 形态
#   ./build.sh --without-32   # 跳过 i386 两种形态
#   ./build.sh --with-tar     # 另打包 isbench-dist.tar.gz
#
# 矩阵(每 grp 源 -> 4 静态产物, 命名契约供 dist/run.sh 使用):
#   bin/<grp>_x86_64_linux      gcc -static
#   bin/<grp>_i386_linux        gcc -m32 -static        (--without-32 跳过)
#   bin/<grp>_x86_64_windows.exe  x86_64-w64-mingw32-gcc -static
#   bin/<grp>_i386_windows.exe   i686-w64-mingw32-gcc -static (--without-32 跳过)
#
# 纪律(吸取 legacy 事故): 失败即终止; 每次全新编译到临时目录, 全部产物
# 静态核查(ELF 无 INTERP / PE 无 DLL Name)通过后才一次性 cp 进 dist/bin;
# 禁止把旧产物当成功。
set -euo pipefail
cd "$(dirname "$0")"

WITH32=1
WITH_TAR=0
for a in "$@"; do
    case "$a" in
        --without-32) WITH32=0 ;;
        --with-tar)   WITH_TAR=1 ;;
        *) echo "未知参数: $a (支持 --without-32 / --with-tar)" >&2; exit 1 ;;
    esac
done

# ---------- 1. 前置检查(mingw 缺失即提示一次性安装) ----------
need=""
command -v gcc >/dev/null || need="$need gcc"
command -v x86_64-w64-mingw32-gcc >/dev/null || need="$need x86_64-w64-mingw32-gcc"
command -v i686-w64-mingw32-gcc >/dev/null || need="$need i686-w64-mingw32-gcc"
if [ -n "$need" ]; then
    echo "缺少工具链:$need" >&2
    echo "安装: sudo apt-get install -y gcc-mingw-w64-x86-64 gcc-mingw-w64-i686" >&2
    exit 1
fi

# ---------- 2. 构建矩阵 ----------
GRPS="scalar sse avx crypto cpuid timer"
CFLAGS="-O2 -static -msse2 -mno-avx -mno-avx2 -mno-fma"
TMPD="$(mktemp -d /tmp/isbench-build.XXXXXX)"
trap 'rm -rf "$TMPD"' EXIT
mkdir -p dist/bin

echo "== isbench build: 6 组 x 4 形态 静态矩阵 =="
for g in $GRPS; do
    src="src/isb_${g}.c"
    [ -f "$src" ] || { echo "缺源文件 $src" >&2; exit 1; }
    echo "-- $g"
    # 4 形态逐一编译(先清目标: 绝不让旧产物冒充成功)
    for t in x86_64_linux i386_linux x86_64_windows i386_windows; do
        [ "$WITH32" = 0 ] && { [ "$t" = i386_linux ] || [ "$t" = i386_windows ]; } && continue
        case "$t" in
            x86_64_linux)      cc="gcc";                     flags="$CFLAGS" ;;
            i386_linux)        cc="gcc";                     flags="$CFLAGS -m32" ;;
            x86_64_windows)    cc="x86_64-w64-mingw32-gcc";  flags="$CFLAGS" ;;
            i386_windows)      cc="i686-w64-mingw32-gcc";    flags="$CFLAGS" ;;
        esac
        out="$TMPD/${g}_${t}"
        # mingw gcc 对无扩展名 -o 会自动追加 .exe(ELF gcc 不会), 统一显式命名
        case "$t" in *_windows) out="${out}.exe" ;; esac
        echo "  [$t] $cc $flags $src"
        rm -f "$out"
        $cc $flags "$src" -o "$out"
        # 静态核查(失败即终止)
        case "$t" in
            *_linux)
                if readelf -l "$out" 2>/dev/null | grep -q INTERP; then
                    echo "  !! $g/$t 仍带解释器(非静态), 构建失败" >&2; exit 1
                fi
                readelf -h "$out" >/dev/null 2>&1 || { echo "  !! $g/$t 不是有效 ELF" >&2; exit 1; }
                ;;
            *_windows)
                # PE 静态程序仍固定导入系统 DLL(KERNEL32/msvcrt/...); 检出任何
                # 非系统 DLL(如 libgcc_s/winpthread)才算动态链接
                if objdump -p "$out" 2>/dev/null | grep "DLL Name" | \
                   grep -viE 'KERNEL32|msvcrt|ntdll|ADVAPI32|GDI32|USER32|SHELL32|WS2_32|ole32|OLEAUT32|RPCRT4|VCRUNTIME'; then
                    echo "  !! $g/$t 链接了非系统 DLL, 构建失败" >&2; exit 1
                fi
                ;;
        esac
    done
done

# ---------- 3. dist 组装(全部核查通过后一次性落位) ----------
echo "== 组装 dist/ =="
for g in $GRPS; do
    for t in x86_64_linux i386_linux x86_64_windows i386_windows; do
        [ "$WITH32" = 0 ] && { [ "$t" = i386_linux ] || [ "$t" = i386_windows ]; } && continue
        src="$TMPD/${g}_${t}"; dst="dist/bin/${g}_${t}"
        case "$t" in *_windows) src="${src}.exe"; dst="${dst}.exe" ;; esac
        cp -f "$src" "$dst"
        # drvfs(/mnt/c) 无 exec 位概念, chmod 仅 Linux 原生目录生效, 失败不终止
        chmod +x "$dst" 2>/dev/null || true
    done
done
cp -f README.txt dist/README.txt
cp -f isbench.py dist/isbench.py
chmod +x dist/isbench.py 2>/dev/null || true
rm -f dist/SHA256SUMS
( cd dist && sha256sum bin/* isbench.py README.txt > SHA256SUMS )
echo "== 产物清单 =="
ls -la dist/bin/

if [ "$WITH_TAR" = 1 ]; then
    tar czf isbench-dist.tar.gz dist
    echo "== 打包 isbench-dist.tar.gz =="
fi
echo "== BUILD OK: dist/ 可整目录拷贝即用 =="
