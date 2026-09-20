# 独立 openssl 测速探针（openssl / openssl11）

## openssl：独立 openssl 测速探针

- **目的**：加密/摘要算法在 x86 openssl 实现上的吞吐，同一静态 ELF 原生直跑
  vs LATX 全翻译对拍 —— “LATX 翻译 x86 openssl 加密实现”的性能，服务
  AES 位切/vpaes 类翻译优化价值判断。与 `src/` 指令探针**分离编译、另建
  表 `openssl` 入库**（列名 = 加密名_块尺寸），互不干扰。
- **形态**：`src/openssl/isb_openssl.c` + `build/build-openssl.sh`（x86_64 构建机）静态链同形态
  `libcrypto.a`，产全静态 ELF `dist/bin/openssl-x64_linux` +
  `openssl-i386_linux`（i386 加 `gcc -m32`）；`build/build.sh` 尾段自动调用。构建前置
  （x86_64 构建机）：`apt install libssl-dev libssl-dev:i386 gcc-multilib
  libc6-dev-i386 zlib1g-dev zlib1g-dev:i386 libzstd-dev libzstd-dev:i386`
  （Debian libcrypto.a 静态链需补 zlib/zstd）。
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
  `openssl_<native|latx>`；run key 不带 abi，形态靠 openssl 表 abi 列区分，
  `--abi all` 时两形态 key 由各自时间戳天然不同），`runs/env_wide`
  照常采集 + openssl 一行。openssl 固定列
  仅 `run_id/abi/os/bits/tput_ms/openssl_ver`；度量列（算法_尺寸）按探针表头列名
  动态 ALTER（全数值 REAL），新增算法/尺寸免改 py；reps>1 数值取中位
  聚合为一行。不参与指令哨兵/compare。
- **命令**：`python3 dist/isbench.py openssl <native|latx> [--abi x64,i386|all]
  [--time MS] [--reps N] [--push URL]`。ls/show/export 识别
  openssl run（export 导该行宽 CSV）；serve/push 载荷含 openssl 行。
- **判读示例**（即 LATX 翻译优化候选信号）：同算法同尺寸列 native vs LATX
  MB/s 比值 = 翻译保留率；AES 系列（LATX 侧 AES 位切路径/tr-vpaes 开关）
  与 SM4/Chacha20（软实现）的表现差分别归属翻译与实现两层。
- **调试**：环境变量 `OPENSSL_PROBE_ERR=1` 时探针 fail 路径打印 OpenSSL 错误栈
  （定位 fetch/init 类失败用）。

## openssl11：openssl 1.1.1 共存模块

- **形态**：与 openssl 同源 `src/openssl/isb_openssl.c`（纯 legacy EVP API，1.1.1 兼容），
  `build/build-openssl11.sh`（x86_64 构建机）自编 openssl 1.1.1w 静态 `libcrypto.a`（源码
  由 `third_party/get_openssl.sh` 取回），产
  `dist/bin/openssl11-x64_linux` + `openssl11-i386_linux`（全静态 ELF）；
  `build/build.sh` 尾段自动调用。1.1.1 无 zlib/zstd 依赖，静态链仅 `-ldl -pthread`。
- **数据**：与 3.x **同一 `openssl` 表共存**，`openssl_ver` 列分版本（`runs.mode` 记
  `openssl11_<mode>`，二进制 `openssl11_*`）；列集合与 3.x 版一致（3.5.x 静态
  库与 1.1.1 同不出 sm4-gcm）。serve/push/export/show 全复用（export 已认
  `openssl11_` 前缀），run key 仍不带 abi。
- **命令**：`python3 dist/isbench.py openssl <native|latx> --ver 11 [--abi all]
  [...同 openssl 参数]`；`--ver` 默认 3 即 3.x，行为不变。
- **作用**：3.x 同源 legacy-API 探针的 1.1.1 对照形态（同一算法在两代库上的性能与行为对照）。
