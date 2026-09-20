#!/bin/bash
# 下载 openssl 3.5.7 与 1.1.1w 源码(多源 fallback), 解压到 ~/osrc
cd ~
dl() { # dl <url> <out>
  timeout 90 python3 - "$1" "$2" <<'PY'
import sys, urllib.request
url, out = sys.argv[1], sys.argv[2]
try:
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    data = urllib.request.urlopen(req, timeout=60).read()
    open(out, 'wb').write(data)
    print('OK', url, len(data))
except Exception as e:
    print('FAIL', url, repr(e)[:120]); sys.exit(1)
PY
}
mkdir -p ~/osrc && cd ~/osrc
# 3.5.7
if [ ! -f openssl-3.5.7.tar.gz ]; then
  dl https://github.com/openssl/openssl/archive/refs/tags/openssl-3.5.7.tar.gz openssl-3.5.7.tar.gz \
    || dl https://www.openssl.org/source/openssl-3.5.7.tar.gz openssl-3.5.7.tar.gz \
    || dl http://mirrors.ustc.edu.cn/debian/pool/main/o/openssl/openssl_3.5.7.orig.tar.gz openssl-3.5.7.tar.gz
fi
# 1.1.1w
if [ ! -f openssl-1.1.1w.tar.gz ]; then
  dl https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_1_1w.tar.gz openssl-1.1.1w.tar.gz \
    || dl https://www.openssl.org/source/old/1.1.1/openssl-1.1.1w.tar.gz openssl-1.1.1w.tar.gz
fi
ls -la
for f in openssl-3.5.7.tar.gz openssl-1.1.1w.tar.gz; do
  if [ -f "$f" ]; then tar xzf "$f"; fi
done
ls -d openssl-* 2>/dev/null
