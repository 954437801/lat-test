#!/bin/bash
# openssl11 独立测速探针构建 —— openssl 1.1.1w 静态链版(与 3.x 版 openssl 共存)
# 与 openssl 版共用同一探针源 src/openssl/isb_openssl.c(纯 legacy EVP API, 1.1.1 兼容);
# 仅被测 libcrypto 版本不同 -> native/LATX 下直接对拍 1.1.1 vs 3.x 加密实现。
# 产物: ../dist/bin/openssl11-{x64,i386}_linux(全静态 ELF)
#       stdout 首行 "# openssl_ver=OpenSSL 1.1.1w ..." 与 3.x 版(openssl_*)区分,
#       同一 openssl 表 openssl_ver 列自然分版本; 1.1.1 无 sm4-gcm -> 该组自动不出列。
# 源码: $OSRC/openssl-OpenSSL_1_1_1w (缺省 $HOME/osrc; 可用环境变量 OSRC 覆盖;
#        下载见 third_party/get_openssl.sh, 或手动下载解压 openssl-1.1.1w.tar.gz)
# 前置: make gcc gcc-multilib libc6-dev-i386 (1.1.1 无 zlib/zstd 依赖)
set -e
cd "$(dirname "$0")"
SRC=../src/openssl/isb_openssl.c   # 探针源(本脚本 CWD=build/)
OSRC="${OSRC:-$HOME/osrc}"           # OpenSSL 源码根(可用环境变量 OSRC 覆盖)
SRCDIR="$OSRC/openssl-OpenSSL_1_1_1w"
DIST=../dist/bin
PROBE=openssl11
mkdir -p "$DIST" "$OSRC"

[ -f "$SRCDIR/Configure" ] || {
    echo "缺 1.1.1w 源码: $SRCDIR (先跑 third_party/get_openssl.sh 下载)"; exit 1; }

check_static() {
    if file "$1" | grep -q "statically linked"; then
        echo "OK  $1 (static ELF)"
    else
        echo "FAIL $1 not static"; file "$1"; exit 1
    fi
}

# configure + build_libs + 静态链探针; $1=abi, $2=arch-target, $3=mflag
build_one() {
    local abi=$1 arch=$2 mflag=$3
    echo "== configure 1.1.1w $abi (linux-$arch $mflag)"
    ( cd "$SRCDIR" && make distclean >/dev/null 2>&1 || true )
    ( cd "$SRCDIR" && ./Configure "linux-$arch" $mflag no-shared no-tests no-dso \
        --prefix=$OSRC/inst111 >$OSRC/cfg111_$abi.log 2>&1 ) || {
        echo "configure $abi FAIL"; tail -10 $OSRC/cfg111_$abi.log; exit 1; }
    echo "== make build_libs $abi"
    ( cd "$SRCDIR" && make -j8 build_libs >$OSRC/make111_$abi.log 2>&1 ) || {
        echo "make $abi FAIL"; tail -15 $OSRC/make111_$abi.log; exit 1; }
    echo "== link $abi probe"
    gcc -O2 -Wall -Wno-deprecated-declarations -Wno-unused-result $mflag \
        -I"$SRCDIR/include" "$SRC" -o "$DIST/${PROBE}-${abi}_linux" -static \
        -L"$SRCDIR" -lcrypto -ldl -pthread
    check_static "$DIST/${PROBE}-${abi}_linux"
}

build_one x64  x86_64 ""
build_one i386 x86    "-m32"

echo "== openssl11 build done"
# 独立执行时同步 dist/SHA256SUMS(全量重算, 含当时 dist 全部产物)
rm -f ../dist/SHA256SUMS
( cd ../dist && sha256sum bin/* isbench.py README.md > SHA256SUMS )
echo "== SHA256SUMS 已重算(含 openssl11) =="
