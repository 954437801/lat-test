# third_party —— 第三方依赖

本目录集中安放 isbench 依赖的第三方源码。**第三方源码不入库**（见 `.gitignore`）：
各机首次构建前用本目录脚本取回；项目自有的集成/适配层不在本目录（如 SoftFloat 的
`platform.h` / `sf_sources.mk` 在 `src/sfloat/`，真值生成脚本在 `pack/`）。

## 清单

| 依赖 | 版本/锁定 | 用途 | 上游 | 取回方式 | 许可 |
|------|-----------|------|------|----------|------|
| SoftFloat-3e | 快照 commit `5c06db33`（2021-11-29） | sfloat 组：软浮点 f64/f80/f128 的延迟与正确性基准 | gitee 镜像 `luobing4365/berkeley-softfloat-3`；官方 `ucb-bar/berkeley-softfloat-3` | `bash third_party/get_softfloat.sh` | BSD 3-Clause（见 `softfloat-3e/COPYING.txt`） |
| OpenSSL | 3.5.7 与 1.1.1w（两版并存） | openssl 组：TLS/密码学原语测速（`openssl speed`）的跨环境对照 | openssl.org；GitHub `openssl/openssl` | `bash third_party/get_openssl.sh`（源码落 `~/osrc/`，不入库） | Apache-2.0（3.x）；OpenSSL+SSLeay 双许可（1.1.1） |

## 获取

```bash
bash third_party/get_softfloat.sh          # 已存在则跳过
bash third_party/get_softfloat.sh --force  # 强制重取
bash third_party/get_openssl.sh           # OpenSSL 源码取回 ~/osrc/(多源 fallback)
```

脚本多源 fallback：gitee 镜像（锁定 commit，与本仓快照同源）→ GitHub 官方 tag `3e` →
GitHub 官方 `master`。下载后做形状自检（缺 `source/include/softfloat.h`、
`source/8086-SSE/specialize.h` 等即拒绝落地），避免留下半棵树。

## 落地位置与口径

- 落地到 `third_party/softfloat-3e/`，`source/`、`source/8086-SSE/`、`build/`、`COPYING.txt` 齐备。
- 编译只取 `source/` 与 `source/8086-SSE/` 的精确 .c 清单（由 `src/sfloat/sf_sources.mk`
  锁定，据官方 `build/Linux-x86_64-GCC` 的 `make -Bn` 采得），**不用 `source/*.c` 通配**
  （会编不过）。`build/` 仅供对照，不参与构建。
- 取到后以 `bash build/build.sh --groups=sfloat` 编过为准；备源快照与主源若有差异，以此暴露。

## 为什么外部源而非入库

第三方源树 300+ 文件（约 1.8 MB）且为 upstream 拷贝，入库会让仓库体积与噪声膨胀、
且易与上游脱钩。本仓既有外部依赖（openssl 各版）也走「下载脚本 + 不入库」的同一范式
（见 `third_party/get_openssl.sh`），本目录沿用之。
