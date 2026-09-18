#!/bin/bash
# ossl 独立测速探针构建(独立于 src/ 指令探针矩阵, 可单独执行)
# 静态链接同形态 libcrypto.a, 产 dist/bin/ossl-{x64,i386}_linux(全静态 ELF)
# 前置: sudo apt install libssl-dev libssl-dev:i386 gcc-multilib libc6-dev-i386
set -e
cd "$(dirname "$0")"
SRC=ossl_probe.c
DIST=../dist/bin
mkdir -p "$DIST"

check_static() {
    if file "$1" | grep -q "statically linked"; then
        echo "OK  $1 (static ELF)"
    else
        echo "FAIL $1 not static"; file "$1"; exit 1
    fi
}

# 静态链 Debian libcrypto.a 依赖: zlib + zstd(Debian openssl 编入两者)+dl+pthread
# $1=out, $2..=flags
build_one() {
    local out=$1; shift
    gcc -O2 -Wall -Wno-deprecated-declarations -Wno-unused-result "$@" \
        "$SRC" -o "$out" -static -lcrypto -lz -lzstd -ldl -pthread
}

echo "== build dist/bin/ossl-x64_linux"
build_one "$DIST/ossl-x64_linux"
check_static "$DIST/ossl-x64_linux"

echo "== build dist/bin/ossl-i386_linux"
build_one "$DIST/ossl-i386_linux" -m32
check_static "$DIST/ossl-i386_linux"

echo "== ossl build done"
# 独立执行时同步 dist/SHA256SUMS(全量重算, 含当时 dist 全部产物)
rm -f ../dist/SHA256SUMS
( cd ../dist && sha256sum bin/* isbench.py README.txt > SHA256SUMS )
echo "== SHA256SUMS 已重算(含 ossl) =="
