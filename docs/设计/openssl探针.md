# 独立 openssl 测速探针（openssl / openssl11）

## openssl：独立 openssl 测速探针

- **目的**：加密/摘要算法在 x86 openssl 实现上的吞吐，同一静态/动态 ELF 原生直跑
  vs LATX 全翻译对拍 —— “LATX 翻译 x86 openssl 加密实现”的性能，服务
  AES 位切/vpaes 类翻译优化价值判断。与 `src/` 指令探针**分离编译、另建
  表 `openssl` 入库**（列名 = 加密名_块尺寸），互不干扰。
- **形态**：`src/openssl/isb_openssl.c` + `build/build-openssl.sh` 从
  `third_party/get_openssl.sh` 取回的 **3.5.7 源码**构建（`Configure`+`make build_libs`，
  不再链系统 `libssl-dev`，使 `openssl_ver` 跨形态统一）。每 form 一次构建同时产出
  静态 `libcrypto.a` 与共享 `libcrypto.so/.dll`，据此链出静态探针与动态探针（`_dy`）。
  产 `dist/bin/`：静态 `openssl-{x64,i386}_linux` + `openssl-{x64,i386}_windows.exe`；
  动态 `openssl-{x64,i386}_linux_dy` + `openssl-{x64,i386}_windows_dy.exe`。自建共享库
  复制到 `dist/lib/`：动态 linux 探针用 `-rpath $ORIGIN/../lib` 定位，动态 windows 探针
  旁置一份 dll 供 wine/本机直载。linux target `linux-x86_64`/`linux-x86 -m32`，windows
  交叉 `mingw64`/`mingw`（`--cross-compile-prefix`）。`build/build.sh` 尾段按模式
  (`static/dynamic/both`)自动调用。构建前置：`gcc gcc-multilib libc6-dev-i386`、交叉
  `gcc-mingw-w64-x86-64 gcc-mingw-w64-i686`、`perl make`；源码经 `third_party/get_openssl.sh`。
- **计时纪律**：只 `clock_gettime(CLOCK_MONOTONIC)` 定时长窗口（默认 0.5s/
  （算法,尺寸））；**禁 rdtsc** —— LATX 伪造 rdtsc，openssl speed 自带
  rdtsc 计时在 LATX 失真，故本探针弃用之。
- **输出**（探针 stdout，3 行）：`# openssl_ver=<版本>` / 表头 = 度量列名 CSV
  （列名 = `<EVP 算法名 '-'->'_'>_<块尺寸>`，如 `aes_128_cbc_8192`）/ 值行
  MB/s（2 位小数）。库无的算法（探测失败）整组不出列，列集随库版本自适应。
- **算法/尺寸**：cipher `aes-128/192/256 x ecb/cbc/ctr/gcm` + `sm4-ecb/cbc/ctr`
  （sm4-gcm 仅库支持时纳入：3.5.x 与 1.1.1w 静态库实测均未编入，
  动态枚举自动跳过，列集合两版一致）+ `chacha20`；digest
  `sha1/sha256/sha512/sm3`（对 size 字节输入做摘要）；
  尺寸 16/64/256/1024/8192/16384。
  `EVP_get_cipherbyname/digestbyname` 运行时枚举。
- **数据**：isbench.py 新表 `openssl`，每（mode,abi）一行（`runs.mode` 记
  `openssl_<native|latx|wine>`；run key 不带 abi，形态靠 openssl 表 abi 列区分，
  `--abi all` 时两形态 key 由各自时间戳天然不同），`runs/env_wide`
  照常采集 + openssl 一行。openssl 固定列
  仅 `run_id/abi/os/bits/tput_ms/openssl_ver`；度量列（算法_尺寸）按探针表头列名
  动态 ALTER（全数值 REAL），新增算法/尺寸免改 py；reps>1 数值取中位
  聚合为一行。不参与指令哨兵/compare。
- **命令**：`python3 dist/isbench.py openssl <native|latx|wine> [--abi x64,i386|all]
  [--link static|dynamic] [--time MS] [--reps N] [--push URL]`。`--link dynamic` 选 `_dy`
  动态探针；`wine` 模式跑 `_windows[_dy].exe`（`WINE`/`kylin-wine`/`wine`，`os` 记
  `windows`）。ls/show/export 识别
  openssl run（export 导该行宽 CSV）；serve/push 载荷含 openssl 行。
- **判读示例**（即 LATX 翻译优化候选信号）：同算法同尺寸列 native vs LATX
  MB/s 比值 = 翻译保留率；AES 系列（LATX 侧 AES 位切路径/tr-vpaes 开关）
  与 SM4/Chacha20（软实现）的表现差分别归属翻译与实现两层。
- **调试**：环境变量 `OPENSSL_PROBE_ERR=1` 时探针 fail 路径打印 OpenSSL 错误栈
  （定位 fetch/init 类失败用）。

## openssl11：openssl 1.1.1 共存模块

- **形态**：与 openssl 同源 `src/openssl/isb_openssl.c`（纯 legacy EVP API，1.1.1 兼容），
  `build/build-openssl11.sh` 与 build-openssl.sh 同构，从 `get_openssl.sh` 取回的 1.1.1w
  源码编 `libcrypto`（静态 `.a` + 共享 `.so/.dll`），产 `dist/bin/openssl11-{x64,i386}_linux[_dy]`
  与 `openssl11-{x64,i386}_windows[_dy].exe`，共享库复制到 `dist/lib/`；
  `build/build.sh` 尾段按模式自动调用。1.1.1 无 zlib/zstd 依赖，linux 静态链仅 `-ldl -pthread`。
- **数据**：与 3.x **同一 `openssl` 表共存**，`openssl_ver` 列分版本（`runs.mode` 记
  `openssl11_<mode>`，二进制 `openssl11_*`）；列集合与 3.x 版一致（3.5.x 静态
  库与 1.1.1 同不出 sm4-gcm）。serve/push/export/show 全复用（export 已认
  `openssl11_` 前缀），run key 仍不带 abi。
- **命令**：`python3 dist/isbench.py openssl <native|latx|wine> --ver 11 [--abi all]
  [--link static|dynamic] [...同 openssl 参数]`；`--ver` 默认 3 即 3.x，行为不变。
- **作用**：3.x 同源 legacy-API 探针的 1.1.1 对照形态（同一算法在两代库上的性能与行为对照）。
