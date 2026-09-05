isbench —— 企业微信 libcef 指令形态跨环境基准(py3 + sqlite3 宽表版)
================================================================

用途: 以同一套静态探针测「单指令链延迟(lat) + 定时长吞吐(tput) + 语义
签名(sem/kat)」, 在原生 x86 / LATX(龙芯二进制翻译) / wine 三环境运行。
测试对象是**指令(case)**: lat/tput/sem/kat/diag 都是同一指令的测试方式,
数据模型为「每 (架构, 指令) 一行, 方式做列」——探针输出、库、导出三处同构,
xlsx 直接导入即"一指令一行"。

目录
----
  bin/            6 组 x 4 形态全静态产物; 拷贝本目录(含 isbench.py)到目标机
  isbench.py      唯一运行入口(py3 单文件, 无 txt 报告, 全部入库)
  SHA256SUMS      产物与脚本校验
  results/        数据库与历史结果(运行时自动创建)

依赖
----
  python3 >= 3.6(仅标准库)。自检: python3 --version
  测试机(Linux)缺 python3 时: apt install python3

子命令(--db FILE 默认 results/isbench.db, 自动建宽库)
-----------------------------------------------------
  run <native|latx|wine> [组...]      执行一轮测试并入库(宽表聚合)
      [--abi x86_64|i386|all] [--reps N] [--time S] [--only PREFIX[,..]]
      [--warm 0|1] [--check 0|1] [--push URL] [--db FILE]
  serve [--host 0.0.0.0] [--port 8770] [--token TOK] [--db FILE]
                                      常驻接收各测试机 push, 写集中库
  push [run] [--last] [--url URL] [--db FILE]  推送指定/最近一次 run
  compare <truth> <run> [--db FILE]   对拍两个库内 run(逐方式列比)
  ls [--mode M] [--host 子串] [--db]  列出 runs(机器过滤/完整性/check)
  show <run> [--db FILE]              run 详情: 头部 + env_wide 一行 + bench 分布
  env-diff <a> <b> [--db FILE]        两 run 环境差异(env_wide 逐列)
  export <run> [--db FILE]            导出宽表 CSV(26 列同探针表头, xlsx 导入)

运行示例
--------
  python3 isbench.py run native                   # 本机全组 x86_64+i386
  python3 isbench.py run latx --reps 3            # 龙芯主机; 3 轮聚合成一行
  python3 isbench.py run wine sse crypto          # wine 跑 exe(自动 killw)
  python3 isbench.py compare 164955 165048        # 库内 key 前缀对拍
  python3 isbench.py export 165048 > run.csv      # xlsx 软件直接导入
  python3 isbench.py ls --host 3A6000             # 只看该机器结果
  ISBENCH_PUSH=http://分析机IP:8770 python3 isbench.py run latx   # 免 scp

产物命名(每 6 组): bin/<group>_<x86_64|i386>_<linux|windows.exe>
组: scalar(标量整数) sse(legacy SSE/SSE2/3/SSSE3/SSE4.x) avx(AVX/AVX2/FMA)
    crypto(AES-NI KAT+ECB / PCLMUL / SHA) cpuid(能力+开销) timer(时钟)

数据模型(为什么一行一个指令)
----------------------------
- 每个指令(case)在探针里依次经历 lat(单依赖链 ns/op)与 tput(定时长窗口
  ops/s, 可附 MB/s), 部分指令另有 sem(语义对拍)或独立 kat/diag 实体。
- 旧模型按 (case,metric) 拆行, reps 再放大 N 倍(全量 reps=3 达 942 行/run);
  宽表把 lat/tput/sem/kat/diag 变成同一行的列, reps 多轮只聚合一行
  (数值列取中位, 状态取多数, 状态波动/签名波动记 probe 注记)。
- 全量单架构: 97 指令行(原 157 metric 行); 双架构 reps=3 也仅 ~194 行。

探针 stdout 契约(单表宽 CSV, 26 列同布局, xlsx 可直接导入)
-----------------------------------------------------------
每次 exec 的 stdout = 1 表头 + N 行用例 + 1 行组尾, 无任何其它输出:
  表头: kind,group,abi,os,bits,tput_sec,lat_iters,case,
        lat_st,lat_ns,lat_sig,tput_st,tput_ops,tput_mbs,tput_sig,
        sem_st,sem_sig,sem_tag,kat_st,kat_det,diag_st,diag_v,diag_u,
        diag_det,ok,total
  用例行 kind=T: case = 指令名; 该指令出现的测试方式填对应列, 未测填 '-';
    状态列(CRASH/HOSTUNSUPPORTED/OK/FAIL/PASS)逐方式独立
  组尾行 kind=D: 只填 group/ok/total, 其余 '-'
  sig16 = 64 位结果签名; 空字段 '-'
Excel/WPS: 「数据 > 自文本/CSV」导入即得宽表, 每行一个指令, 直接筛选透视。

协议演进与列自增(后续新增探针输出不需要同步改解析/入库/导出)
----------------------------------------------------------------
- 探针表头只加列不改旧列; 解析按列名取值, 缺列按未测(旧探针), 多列
  保留为 extra(新探针字段不丢); 截断行(无 case 名)自动丢弃。
- 解析出的新列入 bench 时自动 ALTER TABLE ADD COLUMN(列名须标识符;
  数值型新列 reps 聚合取中位, 其余取首值, 波动记 probe 注记);
  export 表头自动追加该 run 的自增列; serve/push 全列传输同样自增。
- 库缺列自愈: 升级 isbench.py 后旧库自动补列(无需删库/指定); 纯旧结构
  (窄表时代)库整体改名 *.old 备份后重建空宽库。
- compare 只比已知语义列; 新列语义(状态/数值/签名)由 py 登记后纳入对拍。

run 内建测量纪律(默认开, --warm 0 / --check 0 可关)
---------------------------------------------------
- 预热丢弃: 每个 (组, abi) 正式 reps 前先跑一次该组哨兵用例并丢弃输出
  (计 runs.warm_discards), 使 LATX 现场翻译/AOT 建立、icache/频率稳定
  的开销落在正式测量外(防缓存未建立首用例污染)。
- reps 聚合: 每 (组,abi) exec N 次, 同指令行按 cname 归并: 数值列(lat_ns/
  tput_ops/tput_mbs/diag_v)取 OK rep 的中位; 状态取多数(单 rep 波动记注记);
  sem_sig 跨 rep 不等记注记。
- 一致性自校验: run 完成后取哨兵指令(x86_add_r64/aesenc)lat 列与本机
  (同 hname+cpu_model)最近一次 run 对拍, >±10% 记 check_note=MISMATCH 并在
  ls/compare 醒目告警(新装 LAT/清 AOT 后首次跑属预期); compare 打印两侧
  check_note 防污染样本当基准。

入库 schema(摘要)
-----------------
  runs(key PK, mode, arch, abi, reps, tsec, started_at, done_note, py_ver,
       imported_at, push_src, warm_discards, check_note, hname, cpu_model, ip)
  env_wide(run_id PK, 40+ 键列平铺)     -- 每 run 一行(键做列), 含 probe 注记
  bench(run_id, abi, grp, cname, rep_n, lat_st, lat_ns, lat_sig, tput_st,
        tput_ops, tput_mbs, tput_sig, sem_st, sem_sig, sem_tag, kat_st,
        kat_det, diag_st, diag_v, diag_u, diag_det,
        PRIMARY KEY(run_id, abi, grp, cname))
run key = <mode>_<arch>_<cpu>_<ip>_<YYYYmmdd-HHMMSS>; 按 key 幂等
(push 重复自动 dup)。库为单文件, WAL 关闭, 备份/拷回即拷 db 文件。

环境收集(每次 run 自动入 env_wide 一行; 容错, 取不到标 na/unset)
----------------------------------------------------------------
  machine: arch/hname/cpu 型号/ip      os: distro kernel libc
  cpu: logical_cores freq_cur_mhz governor max_freq_mhz(单位 MHz)
  sys: mem_total_gb mem_avail_gb load1/5/15 date_iso
  latx: LATX64/LATX32/LATX_OPTS/LATX_AOT/LATX_VPAES/LATX_SOFFPU/
        LATX_DEBUG_AOT + 名单外 LATX*(other) + aot_dir 条目数/最新 mtime
  latx 翻译器指纹(每次 run 收集):
    effective 路径解析顺序: $LATX64/$LATX32(显式即用) -> PATH 中
    latx-x86_64/latx-i386 -> /usr/bin 默认;
    每架构记 tr64/tr32: effective,size,mtime,sha256,ver(--version 首行,
    超时/不支持 na); 另以 ps -eo 观测活跃 latx 进程(直接指定路径启动
    如 /home/loongson/latx-opt/lat/build64/latx-x86_64 时以进程为准),
    记 latx_proc_paths(去重)与 latx_proc_count。翻译器更新/换装后
    env-diff 一眼可见。
  wine: WINE/WINEPREFIX/WINEARCH wine_ver prefix_exists(仅 wine 模式)
  run: reps/tsec/only sha256sums_mtime;  probe_notes: 全部注记合并一段
跨机对拍/归因: env-diff(同库任意两 run 逐列比)。

多机数据流(免 scp)
------------------
- 被测机: run 完成后自动/手动推送分析机:
      python3 isbench.py run latx --push http://<分析机IP>:8770
      python3 isbench.py push --last --url http://<分析机IP>:8770
  推送内容 = runs + env_wide + bench 宽行(JSON); 断网仅警告, 可补推。
- 分析机常驻: python3 isbench.py serve --db central.db(默认 0.0.0.0:8770,
  防火墙放行; 可选 --token 与客户端 ISBENCH_TOKEN)。
- 不提供库-库 merge: 集中靠 push/serve, 离线拷 db 文件。

compare 语义
------------
以 truth 为基准, 对库内两 run 的 bench 宽行逐指令(key = abi|grp|cname)对拍,
每个测试方式(lat/tput/sem/kat/diag)各出一行明细:
状态一致性 / OK 行 sig 逐位 / OK 行数值保留率(±15% 外记 DEVIATION)。
CRASH/HOSTUNSUPPORTED 属已解释状态, 同态即通过; 汇总计数(DEVIATION>0 或
truth 缺键退出码 1); 两侧 check_note 一并打印。

用例名(宽表 case 列)首段 = ISA 段
---------------------------------
  scalar: x86_(基线) | sse42_(crc32) | popcnt | abm_(lzcnt)
  sse:    sse_ sse2_ sse3_ ssse3_ sse41_ sse42_
  avx:    avx_ avx2_ fma_
  crypto: aesenc/aesdec/pclmulqdq/sha256rnds2(名已含 ISA) | aes_ecb128
  cpuid/timer: diag 名即能力/度量名, 无混叠
原名保留为后段(如 ssse3_pshufb); 同指令的语义用例独立 case(如 ssse3_pshufb_sem
与测速 case 分开, 各占一行)。只跑子集: --only PREFIX[,..](前缀带尾下划线,
--only sse2_ 精确选 SSE2; --only sse 会连坐 sse2_/sse41_/sse42_, 不命中 ssse3_)。

单指令数据纪律(读结果前必读)
----------------------------
- 单指令用例一律固定数据: 固定输入=固定输出, sig16 跨 run 可复现, 用于
  验证 LATX 翻译语义正确性(不随机化, 本基准核心契约)。
- 组文件全局不开 -mavx*: SSE 家族保持 legacy 66/0F 编码(32 位 libcef 形态);
  AVX/FMA/AES 各用例函数 target 属性单发 VEX, 编译期即忠实编码形态。
- 依赖链第二操作数/掩码来自轮转内存(确定性填充), 防 GCC 闭式折叠
  (折叠假象: lat≈0.0x ns 或 tput>1e11 ops/s)。
- 纯访存用例由 asm volatile 钉死, 地址用寄存器约束(防提升为循环不变量)。
- 访存族 lat 是近似参考(无寄存器依赖链); tput 才是其真值。
- crypto KAT 为 FIPS-197 自检(PASS 即密钥展开/加密/解密正确)。
- 新增块状用例(如 block8)以独立 case 走 lat/tput 列, 数据连续互异,
  与单指令固定数据分开; 协议无需再改。

部署动作(目标机第一次)
----------------------
1. 整目录拷贝(含 bin/ isbench.py)
2. python3 --version 自检; 缺则安装(apt install python3)
3. (可选) 分析机起 serve; 测试机 run 加 --push 或 export ISBENCH_PUSH
