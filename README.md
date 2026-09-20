# isbench —— 面向 LAT 翻译器的 x86 指令形态跨环境基准

同一套**静态探针**，把 x86 指令的四种测法编成可携带的静态二进制，在
**原生 x86 / LATX（龙芯二进制翻译）/ wine** 三环境直跑并对拍：

- **lat** —— 单指令依赖链延迟（ns/op）
- **tput** —— 定时长窗口吞吐（ops/s，可附 MB/s）
- **sem / kat** —— 语义对拍与功能正确性（KAT 真值逐字段比对）
- **block8** —— 连续 8 条同指令块执行时间（ns/块）

定位：本项目服务于 **LAT 翻译器**（把 x86 二进制翻译到 LoongArch）的适配与优化 ——
回答“哪条指令 / 哪种形态在翻译执行下偏离原生多少、语义是否仍正确”。它不是任何单一
上层软件的测试工具；探针取材于**真实 32 位 x86 应用负载**的运行时分派形态。

测试对象是**指令（case）**：lat/tput/block8/sem/kat/diag 都是同一指令的测试方式（适合
8 连的指令才填 block8 三列）。数据模型为「每（架构, 指令）一行，方式做列」——探针输出、
数据库、导出三处同构，xlsx 直接导入即“一指令一行”。

## 目录结构

```
src/            探针源码: 共享框架头 ib_*.h 留 src 根, 各组在 src/<grp>/ 一目录
                (isb_<grp>.c + _kat.h; x87 多文件; pmul 带 gold.h; sfloat 带 slots.h + 集成层 platform.h/sf_sources.mk)
                src/openssl/ = 独立 openssl 测速探针 isb_openssl.c
build/          构建与编译脚本(build.sh 调度器 / Makefile 规则 / build-loongarch.sh / build-openssl*.sh)
app/            isbench.py 主入口 + model/ 包(db/env/领域常量)与附属数据(sql/、field_dict.json); 装配到 dist/{isbench.py, app/}
pack/           功能真值统一采集与真值表生成(gen_val.sh + gen_gold_*.sh)
third_party/    第三方源码(SoftFloat-3e, 不入库)与取回脚本(get_softfloat.sh / get_openssl.sh)
docs/           详细文档(设计 / 指南 / 规划)
dist/           运行环境(装配产物): isbench.py + app/{sql,field_dict.json,model/} + bin/ lib/ docs/
```

## 快速开始

依赖 python3 ≥ 3.6（仅标准库）。首次构建前先取第三方源码：

```bash
bash third_party/get_softfloat.sh          # 取第三方 SoftFloat-3e(仅 sfloat 组需要)
bash build/build.sh                        # 全组 × 形态编译 + 组装 dist/
bash build/build.sh --groups="mov ctrl"    # 只构指定组
python3 dist/isbench.py run native         # 在 dist 运行环境跑一轮并入库
python3 dist/isbench.py run latx --reps 3  # 龙芯主机; 3 轮聚合成一行
python3 dist/isbench.py compare <truth> <run>   # 库内两 run 对拍
python3 dist/isbench.py ls                 # 列出 runs
```

## 文档

详细文档在 `docs/`，入口见 [`docs/README.md`](docs/README.md)。

- 设计与实现（数据模型/协议/分组命名/测量/KAT/openssl）→ [`docs/设计/`](docs/设计/)
- 使用指南（安装部署/命令行/多机数据流）→ [`docs/指南/`](docs/指南/)
- 规划与记录（跨机验证记录）→ [`docs/规划/`](docs/规划/)
- 第三方依赖 → [`third_party/README.md`](third_party/README.md)

## 依赖

- 运行：python3 ≥ 3.6（仅标准库）
- 构建：gcc、gcc-multilib、mingw-w64（x86_64/i686）；loongarch64 交叉工具链与
  libssl-dev 等为可选，详见 [`docs/指南/安装与部署.md`](docs/指南/安装与部署.md)
- 第三方：Berkeley SoftFloat-3e（外部源，见 [`third_party/README.md`](third_party/README.md)）
