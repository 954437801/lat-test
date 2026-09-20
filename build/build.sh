#!/bin/bash
# isbench build.sh —— 构建调度器(参数解析 + 工具链检查 + .vars.mk 生成)
#
# 用法:
#   bash build/build.sh                # 全矩阵 18 组 x 4 形态(x87 只 i386), 默认静态+动态两套都编
#   bash build/build.sh --without-32   # 跳过 i386 两种形态
#   bash build/build.sh --with-tar     # 另打包 isbench-dist.tar.gz
#   bash build/build.sh --groups="mov" # 只构指定组(跳过 openssl/openssl11 重编)
#   bash build/build.sh --static       # 只出静态(产物名不变)
#   bash build/build.sh --dynamic      # 只出动态(产物 _dy 后缀)
#   bash build/build.sh --both         # 静态+动态共存(等价于默认)
#
# 命名契约(全链统一用 - 分隔组与形态): 目标名 = dist 产物名 = <grp>-<abi>_<os>,
# 例: scalar-x64_linux / scalar-i386_windows.exe。
# (abi 与 os 之间保留 _ 属于 form 名内部, form 形如 x64_linux)
# 编译/核查/打包规则在 build/Makefile 中。
set -euo pipefail
# 本脚本在 build/, 所有相对路径以仓库根为准 -> 先锚定仓库根(并记下绝对路径)
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# ---------- 1. 参数解析 ----------
WITH32=1
WITH_TAR=0
GRPS_ARG=""
# 默认: 静态+动态两套都编译(静态名不变, 动态加 _dy 后缀共存); --static/--dynamic 收敛到单一模式。
MODES="static dynamic"
for a in "$@"; do
    case "$a" in
        --without-32) WITH32=0 ;;
        --with-tar)   WITH_TAR=1 ;;
        --groups=*)   GRPS_ARG="${a#*=}" ;;
        --static)     MODES="static" ;;
        --dynamic)    MODES="dynamic" ;;
        --both)       MODES="static dynamic" ;;
        *) echo "未知参数: $a (支持 --without-32 / --with-tar / --groups=... / --static / --dynamic / --both)" >&2; exit 1 ;;
    esac
done
# 模式标签(供横幅打印)
case "$MODES" in
    "static dynamic") MODE_LABEL=both ;;
    "dynamic")        MODE_LABEL=dynamic ;;
    *)                MODE_LABEL=static ;;
esac

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
          pmul cfloat cint sfloat"
GRP_32ONLY="x87"
ALL_FORMS="x64_linux i386_linux x64_windows i386_windows"
# 按组专属形态覆盖: 列在 GRP_FORMS 里的组走 GRP_FORMS_<grp>(不并入 ALL_FORMS,
# 以免 loongarch64 形态被推给只有 x86 源码、无法非 x86 编的其余 18 组)。
# cfloat = C 数据类型算术延迟, cint = C 整数类型算术延迟; 均为自包含独立探针。
# cfloat 四形态: i386/x64 Linux(原生 x86 参照) + loongarch64(LoongArch 原生基线)
#   + i386_windows(.exe, 用于看 mingw/msvcrt 下 long double 的实际精度与 libm 行为)。
# cint 仍三形态(纯整数, 无 libm/精度诉求, 不需要 windows)。
# sfloat = 软浮点(SoftFloat-3e)延迟+正确性: 与 cfloat/cint 同构的自包含独立探针, 三形态
# i386/x64/loongarch64(loongarch64 为原生基线, x86 为 under-LATX 对照)。
GRP_FORMS="cfloat cint sfloat"
GRP_FORMS_cfloat="i386_linux i386_windows x64_linux loongarch64_linux"
GRP_FORMS_cint="i386_linux x64_linux loongarch64_linux"
GRP_FORMS_sfloat="i386_linux x64_linux loongarch64_linux"

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
# i386 ELF 已能采集: 统一用 gcc 编 ELF(不再绕 Windows PE)。守卫(机器名/CPUID/形状/幂等/LF)在 gen_val.sh 与探针内,
# 不过则保留旧表并失败退出(绝不回退)。默认(GEN≠1)沿用已入库真值表。
GEN="${GEN:-0}"
if [ "$GEN" = 1 ]; then
    GEN_SH="$ROOT/pack/gen_val.sh"
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
# 格式: 静态 <grp>-<form>; 动态 <grp>-<form>_dy (form 形如 x64_linux)
# 每个 <grp>-<form> 按 MODES 展开: static→STATIC=1(原名), dynamic→STATIC=0(_dy 后缀)。
VARFILE=".vars.mk"
rm -f "$VARFILE"
TARGETS=""
for g in $GRPS; do
    [ -f "src/${g}/isb_${g}.c" ] || [ -f "src/${g}/isb_${g}_main.c" ] || { echo "缺源文件 src/${g}/isb_${g}.c(或 src/${g}/isb_${g}_main.c)" >&2; exit 1; }
    for t in $(forms_of "$g"); do
        for mode in $MODES; do
            case "$mode" in
                static)  suffix="";    st=1 ;;
                dynamic) suffix="_dy"; st=0 ;;
                *)       continue ;;
            esac
            target="${g}-${t}${suffix}"
            distname="${target}"
            echo "FORM_${target} = ${t}" >> "$VARFILE"
            echo "GRP_${target} = ${g}" >> "$VARFILE"
            echo "DIST_${target} = ${distname}" >> "$VARFILE"
            echo "STATIC_${target} = ${st}" >> "$VARFILE"
            TARGETS="$TARGETS $target"
        done
    done
done
echo "TARGETS =${TARGETS}" >> "$VARFILE"

# ---------- 5. 调用 make ----------
n_targets=$(set -- $TARGETS; echo $#)
echo "== isbench build: $n_targets 个目标 (模式: $MODE_LABEL) =="
make -f build/Makefile all -j4
#make -f Makefile verify-all

# ---------- 6. openssl/openssl11(分批构时跳过) ----------
if [ -n "$GRPS_ARG" ]; then
    echo "== 分批构(--groups): 跳过 openssl/openssl11 重编 =="
    [ "$WITH_TAR" = 1 ] && make -f build/Makefile pack -j4 
    rm -f "$VARFILE"
    exit 0
fi

bash build/build-openssl.sh
rm -f dist/SHA256SUMS
( cd dist && sha256sum bin/* lib/* isbench.py README.md > SHA256SUMS )
echo "== openssl 已入 dist/bin =="

bash build/build-openssl11.sh
rm -f dist/SHA256SUMS
( cd dist && sha256sum bin/* lib/* isbench.py README.md > SHA256SUMS )
echo "== openssl11 已入 dist/bin =="

[ "$WITH_TAR" = 1 ] && make -f build/Makefile pack -j4
rm -f "$VARFILE"

make -f build/Makefile assemble -j4
