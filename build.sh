#!/bin/bash
# isbench build.sh —— 构建调度器(参数解析 + 工具链检查 + .vars.mk 生成)
#
# 用法:
#   ./build.sh                # 全矩阵 18 组 x 4 形态(x87 只 i386)
#   ./build.sh --without-32   # 跳过 i386 两种形态
#   ./build.sh --with-tar     # 另打包 isbench-dist.tar.gz
#   ./build.sh --groups="mov" # 只构指定组(跳过 ossl/ossl11 重编)
#
# 命名契约(全链统一用 - 分隔组与形态): 目标名 = dist 产物名 = <grp>-<abi>_<os>,
# 例: scalar-x64_linux / scalar-i386_windows.exe。
# (abi 与 os 之间保留 _ 属于 form 名内部, form 形如 x64_linux)
# 编译/核查/打包规则在 Makefile 中。
set -euo pipefail
cd "$(dirname "$0")"

# ---------- 1. 参数解析 ----------
WITH32=1
WITH_TAR=0
GRPS_ARG=""
for a in "$@"; do
    case "$a" in
        --without-32) WITH32=0 ;;
        --with-tar)   WITH_TAR=1 ;;
        --groups=*)   GRPS_ARG="${a#*=}" ;;
        *) echo "未知参数: $a (支持 --without-32 / --with-tar / --groups=...)" >&2; exit 1 ;;
    esac
done

# ---------- 2. 工具链检查 ----------
need=""
command -v gcc >/dev/null || need="$need gcc"
command -v x86_64-w64-mingw32-gcc >/dev/null || need="$need x86_64-w64-mingw32-gcc"
command -v i686-w64-mingw32-gcc >/dev/null || need="$need i686-w64-mingw32-gcc"
command -v ar >/dev/null || need="$need ar"
command -v x86_64-w64-mingw32-ar >/dev/null || need="$need x86_64-w64-mingw32-ar"
command -v i686-w64-mingw32-ar >/dev/null || need="$need i686-w64-mingw32-ar"
if [ -n "$need" ]; then
    echo "缺少工具链:$need" >&2
    echo "安装: sudo apt-get install -y gcc-mingw-w64-x86-64 gcc-mingw-w64-i686" >&2
    exit 1
fi

# loongarch64 交叉工具链为**可选**(仅 cfloat 组的 loongarch64 形态需要):
# 缺则 forms_of() 自动跳过 loongarch64 形态, 不 fail 整构(其余 x86 形态照常)。
HAVE_LOONG=0
command -v loongarch64-linux-gnu-gcc >/dev/null && HAVE_LOONG=1

# ---------- 3. 组形态矩阵 ----------
ALL_GRPS="scalar sse avx crypto cpuid timer \
          mov alu logic flag shift cc ctrl bits special vec x87 \
          pmul cfloat cint"
GRP_32ONLY="x87"
ALL_FORMS="x64_linux i386_linux x64_windows i386_windows"
# 按组专属形态覆盖: 列在 GRP_FORMS 里的组走 GRP_FORMS_<grp>(不并入 ALL_FORMS,
# 以免 loongarch64 形态被推给只有 x86 源码、无法非 x86 编的其余 18 组)。
# cfloat = C 数据类型算术延迟, cint = C 整数类型算术延迟; 均为自包含独立探针,
# 三形态(i386/x64/loongarch64), 无 windows。
GRP_FORMS="cfloat cint"
GRP_FORMS_cfloat="i386_linux x64_linux loongarch64_linux"
GRP_FORMS_cint="i386_linux x64_linux loongarch64_linux"

forms_of() {
    local g="$1" t out="" fs
    case " $GRP_32ONLY " in
        *" $g "*) fs="i386_linux i386_windows" ;;
        *)        fs="$ALL_FORMS" ;;
    esac
    case " $GRP_FORMS " in
        *" $g "*) eval "fs=\$GRP_FORMS_$g" ;;
    esac
    for t in $fs; do
        if [ "$WITH32" = 0 ]; then
            case "$t" in i386_*) continue ;; esac
        fi
        # loongarch64 形态需交叉工具链在位, 缺则跳过并提示(不 fail 整构)
        case "$t" in
            loongarch64_*)
                if [ "$HAVE_LOONG" = 0 ]; then
                    echo "  注: 缺 loongarch64-linux-gnu-gcc, 跳过 $g-$t 形态" >&2
                    continue
                fi ;;
        esac
        out="$out $t"
    done
    echo $out
}

GRPS="$ALL_GRPS"
if [ -n "$GRPS_ARG" ]; then
    for q in $GRPS_ARG; do
        case " $ALL_GRPS " in
            *" $q "*) ;;
            *) echo "--groups 含未知组名: $q (清单: $ALL_GRPS)" >&2; exit 1 ;;
        esac
    done
    GRPS="$GRPS_ARG"
fi

# ---------- 3.5 GEN=1: 编译时采集阶段(真 x86 本地, 不依赖外部机器) ----------
# 两 ABI 组编 x86_64 ELF 采一份表(两 ABI 共用); x87 只 i386 在册 -> 编 i386 ELF
# WSL i386 ELF 已能采集: 统一用 gcc 编 ELF(不再绕 Windows PE)。守卫(机器名/CPUID/形状/幂等/LF)在 gen_val.sh 与探针内,
# 不过则保留旧表并失败退出(绝不回退)。默认(GEN≠1)沿用已入库真值表。
GEN="${GEN:-0}"
if [ "$GEN" = 1 ]; then
    GEN_SH="$(dirname "$0")/pack/gen_val.sh"
    GEN_GRPS="scalar sse avx crypto mov alu logic flag shift cc ctrl bits special vec x87"
    echo "== GEN=1: 采集阶段(真 x86 本地) =="
    for g in $GEN_GRPS; do
        case " $GRP_32ONLY " in
            *" $g "*) echo "-- 采集 $g (i386 ELF) --"; bash "$GEN_SH" "$g" ;;
            *)        echo "-- 采集 $g (x86_64 ELF) --"; bash "$GEN_SH" "$g" ;;
        esac
    done
    echo "== 采集阶段完成 =="
fi

# ---------- 4. 生成 .vars.mk ----------
# 目标名 = dist 产物名(均用 - 分隔组与形态, Make 可用 $(firstword) 拆分)
# 格式: <grp>-<form> (form 形如 x64_linux)
VARFILE=".vars.mk"
rm -f "$VARFILE"
TARGETS=""
for g in $GRPS; do
    [ -f "src/isb_${g}.c" ] || [ -f "src/isb_${g}_main.c" ] || { echo "缺源文件 src/isb_${g}.c(或 src/isb_${g}_main.c)" >&2; exit 1; }
    for t in $(forms_of "$g"); do
        target="${g}-${t}"
        distname="${target}"
        echo "FORM_${target} = ${t}" >> "$VARFILE"
        echo "GRP_${target} = ${g}" >> "$VARFILE"
        echo "DIST_${target} = ${distname}" >> "$VARFILE"
        TARGETS="$TARGETS $target"
    done
done
echo "TARGETS =${TARGETS}" >> "$VARFILE"

# ---------- 5. 调用 make ----------
n_targets=$(set -- $TARGETS; echo $#)
echo "== isbench build: $n_targets 个目标 =="
make -f Makefile all -j4
#make -f Makefile verify-all

# ---------- 6. ossl/ossl11(分批构时跳过) ----------
if [ -n "$GRPS_ARG" ]; then
    echo "== 分批构(--groups): 跳过 ossl/ossl11 重编 =="
    [ "$WITH_TAR" = 1 ] && make -f Makefile pack
    rm -f "$VARFILE"
    exit 0
fi

bash ossl/build-ossl.sh
rm -f dist/SHA256SUMS
( cd dist && sha256sum bin/* lib/* isbench.py README.txt > SHA256SUMS )
echo "== ossl 已入 dist/bin =="

bash ossl/build-ossl11.sh
rm -f dist/SHA256SUMS
( cd dist && sha256sum bin/* lib/* isbench.py README.txt > SHA256SUMS )
echo "== ossl11 已入 dist/bin =="

[ "$WITH_TAR" = 1 ] && make -f Makefile pack
rm -f "$VARFILE"

make assemble