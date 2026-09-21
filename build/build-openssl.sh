#!/bin/bash
# openssl(3.x) 独立测速探针构建 —— 从 get_openssl.sh 下载的 3.5.7 源码构建
# (不再链系统 libssl-dev, 使 openssl_ver 跨形态统一, 且可交叉出 Windows exe)。
#
# 一次 Configure+make build_libs 同时产静态 libcrypto.a 与共享 libcrypto.so/.dll,
# 据此链出: 静态探针(-static, libcrypto 烘进二进制)与动态探针(_dy, 运行期载共享库)。
# 自建的共享库编译后复制到 dist/lib/; 动态 linux 探针用 rpath $ORIGIN/../lib 定位,
# 动态 windows 探针旁置一份 dll 供 wine/本机直载。
#
# 产物 dist/bin/:
#   静态  openssl-{x64,i386}_linux   openssl-{x64,i386}_windows.exe
#   动态  openssl-{x64,i386}_linux_dy openssl-{x64,i386}_windows_dy.exe
# 用法: bash build/build-openssl.sh [static|dynamic|both]   (默认 both)
# 前置: gcc gcc-multilib libc6-dev-i386; 交叉 x86_64/i686-w64-mingw32-gcc; perl make;
#       源码 ~/osrc/openssl-openssl-3.5.7 (third_party/get_openssl.sh 下载解压)
set -e
cd "$(dirname "$0")"
SRC=../src/openssl/isb_openssl.c        # 探针源(CWD=build/)
OSRC="${OSRC:-$HOME/osrc}"
SRCDIR="$OSRC/openssl-openssl-3.5.7"
PFX="$OSRC/inst3"                       # Configure --prefix(仅占位, 不 install)
DIST=../dist/bin
LIBD=../dist/lib
PROBE=openssl
mkdir -p "$DIST" "$LIBD"

MODE="${1:-both}"
case "$MODE" in
    static)  MODES="static" ;;
    dynamic) MODES="dynamic" ;;
    *)       MODES="static dynamic" ;;
esac

[ -f "$SRCDIR/Configure" ] || { echo "缺 3.5.7 源码: $SRCDIR (先跑 third_party/get_openssl.sh 下载解压)"; exit 1; }

# 共享库依赖(静态/动态都用): linux 走 dl+pthread; windows 走 ws2_32/crypt32/... 及 winpthread
SYS_LIBS_linux="-ldl -pthread"
SYS_LIBS_win="-lws2_32 -lcrypt32 -ladvapi32 -lbcrypt -lgdi32 -luser32 -lpthread"

# 核查: $1=out, $2=linux|win, $3=static|dynamic
check() {
    local out=$1 os=$2 kind=$3
    if [ "$os" = win ]; then
        file "$out" | grep -q 'PE32' || { echo "FAIL $out 不是 PE"; exit 1; }
        if [ "$kind" = dynamic ]; then
            objdump -p "$out" 2>/dev/null | grep -qi 'libcrypto.*\.dll' \
                || { echo "FAIL $out 动态未依赖 libcrypto dll"; exit 1; }
        fi
        echo "OK  $out (PE $kind)"
    else
        if [ "$kind" = static ]; then
            file "$out" | grep -q 'statically linked' || { echo "FAIL $out not static"; exit 1; }
        else
            file "$out" | grep -q 'dynamically linked' || { echo "FAIL $out not dynamic"; exit 1; }
            readelf -d "$out" 2>/dev/null | grep -q 'libcrypto' || { echo "FAIL $out 未 NEEDED libcrypto"; exit 1; }
        fi
        echo "OK  $out ($kind ELF)"
    fi
}

# 链一个探针: $1=out $2=cc $3=linux|win $4=static|dynamic $5..=额外链接 flags
link_probe() {
    local out=$1 cc=$2 os=$3 kind=$4; shift 4
    local extra=("$@")
    local libs; [ "$os" = win ] && libs="$SYS_LIBS_win" || libs="$SYS_LIBS_linux"
    local stdio=; [ "$os" = win ] && stdio="-D__USE_MINGW_ANSI_STDIO=1"
    if [ "$kind" = static ]; then
        $cc -O2 -Wall -Wno-deprecated-declarations -Wno-unused-result $stdio "${extra[@]}" \
            -I"$SRCDIR/include" "$SRC" -o "$out" -static -L"$SRCDIR" -lcrypto $libs
    else
        $cc -O2 -Wall -Wno-deprecated-declarations -Wno-unused-result $stdio "${extra[@]}" \
            -I"$SRCDIR/include" "$SRC" -o "$out" -L"$SRCDIR" -lcrypto $libs
    fi
    check "$out" "$os" "$kind"
}

# 复制共享库: linux 按 abi 子目录(64/32 同 SONAME libcrypto.so.3 会互覆); win dll 名各异
# 拷到 dist/lib + 旁置到 dy exe 目录。$1=os $2=abi $3=dyexe
deploy_shared() {
    local os=$1 abi=$2 dyexe=$3 f
    if [ "$os" = linux ]; then
        mkdir -p "$LIBD/$abi"
        for f in "$SRCDIR"/libcrypto.so.*; do
            [ -e "$f" ] || continue
            cp -P "$f" "$LIBD/$abi/"
        done
        ln -sf libcrypto.so.3 "$LIBD/$abi/libcrypto.so" 2>/dev/null || true
    else
        for f in "$SRCDIR"/libcrypto-*.dll; do
            [ -e "$f" ] || continue
            cp -P "$f" "$LIBD/"
            [ -n "$dyexe" ] && cp -P "$f" "$(dirname "$dyexe")/"
        done
    fi
}

# 构建一个 form: $1=abi(x64/i386) $2=os(linux/windows)
build_form() {
    local abi=$1 os=$2 conf cc xcp mflag
    case "$abi:$os" in
        x64:linux)    conf=linux-x86_64 cc=gcc  xcp= mflag= ;;
        i386:linux)   conf=linux-x86    cc=gcc  xcp= mflag=-m32 ;;
        x64:windows)  conf=mingw64 cc=x86_64-w64-mingw32-gcc xcp=x86_64-w64-mingw32- mflag= ;;
        i386:windows) conf=mingw   cc=i686-w64-mingw32-gcc  xcp=i686-w64-mingw32-  mflag= ;;
        *) echo "bad form $abi:$os"; exit 1 ;;
    esac
    local sfx=""; [ "$os" = windows ] && sfx=".exe"

    echo "===== $PROBE-${abi}_${os} (Configure $conf) ====="
    ( cd "$SRCDIR" && make distclean >/dev/null 2>&1 || true )
    ( cd "$SRCDIR" && ./Configure "$conf" ${xcp:+--cross-compile-prefix=$xcp} \
        $mflag shared no-tests no-dso --prefix="$PFX" \
        >"$OSRC/cfg3_${abi}_${os}.log" 2>&1 ) \
        || { echo "configure $abi/$os FAIL"; tail -12 "$OSRC/cfg3_${abi}_${os}.log"; exit 1; }
    ( cd "$SRCDIR" && make -j"$(nproc)" build_libs \
        >"$OSRC/make3_${abi}_${os}.log" 2>&1 ) \
        || { echo "make $abi/$os FAIL"; tail -18 "$OSRC/make3_${abi}_${os}.log"; exit 1; }

    local exe="$DIST/${PROBE}-${abi}_${os}" osk rp=()
    [ "$os" = windows ] && osk=win || osk=linux
    # 动态 linux 探针 rpath 指向 per-abi 子目录(64/32 同 SONAME 不能共存于同一 lib/)
    [ "$os" = linux ] && rp=("-Wl,-rpath,\$ORIGIN/../lib/$abi")
    # $mflag(i386 linux=-m32)须同时作用于探针编译+链接, 否则按 64 位生成误链系统 lib。
    for m in $MODES; do
        case "$m" in
            static)  link_probe "${exe}${sfx}"    "$cc" "$osk" static  ${mflag:+"$mflag"} ;;
            dynamic) link_probe "${exe}_dy${sfx}" "$cc" "$osk" dynamic ${mflag:+"$mflag"} "${rp[@]}" ;;
        esac
    done
    # 复制共享库(仅当产了动态才需要; 幂等: 有共享产物就拷)
    if echo " $MODES " | grep -q ' dynamic '; then
        deploy_shared "$os" "$abi" "$DIST/${PROBE}-${abi}_${os}_dy${sfx}"
    fi
}

build_form x64  linux
build_form i386 linux
build_form x64  windows
build_form i386 windows

echo "== openssl(3.x) build done (mode=$MODE) =="
rm -f ../dist/SHA256SUMS
( cd ../dist && sha256sum bin/* lib/* isbench.py README.md > SHA256SUMS )
echo "== SHA256SUMS 已重算(含 openssl + dist/lib 共享库) =="
