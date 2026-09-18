isbench —— 企业微信 libcef 指令形态跨环境基准(py3 + sqlite3 宽表版)
================================================================

用途: 以同一套静态探针测「单指令链延迟(lat) + 定时长吞吐(tput) + 语义
签名(sem/kat) + 连续 8 指令块执行时间(block8)」, 在原生 x86 / LATX(龙芯
二进制翻译) / wine 三环境运行。
测试对象是**指令(case)**: lat/tput/block8/sem/kat/diag 都是同一指令的测
试方式(适合 8 连的指令才填 block8 三列), 数据模型为「每 (架构, 指令) 一
行, 方式做列」——探针输出、库、导出三处同构, xlsx 直接导入即"一指令一行"。

目录
----
  bin/            组矩阵全静态产物(18 组, x87 只 i386 两形态); 拷贝本目录(含 isbench.py)到目标机
  lib/            同组同形态的静态归档(一组一库; 与 bin 里的 exe 共用同一个 .o)
  isbench.py      唯一运行入口(py3 单文件, 无 txt 报告, 全部入库)
  SHA256SUMS      产物与脚本校验(含 bin/ 与 lib/)
  results/        数据库与历史结果(运行时自动创建)

依赖
----
  python3 >= 3.6(仅标准库)。自检: python3 --version
  测试机(Linux)缺 python3 时: apt install python3

子命令(--db FILE 默认 results/isbench.db, 自动建宽库)
-----------------------------------------------------
  run <native|latx|wine> [组...]      执行一轮测试并入库(性能/功能/详细 三族表)
      [--abi x64|i386|all] [--reps N] [--time MS] [--only PREFIX[,..]]
      [--warm 0|1] [--check 0|1] [--debug] [--push URL] [--db FILE]
                                      --debug: 透传探针, 另采详细明细入 debug_<grp>
  serve [--host 0.0.0.0] [--port 8770] [--token TOK] [--db FILE]
                                      常驻接收各测试机 push, 写集中库
  push [run] [--last] [--url URL] [--db FILE]  推送指定/最近一次 run
  compare <truth> <run> [--db FILE]   对拍两个库内 run(逐方式列比)
  ls [--mode M] [--host 子串] [--db]  列出 runs(机器过滤/完整性/check)
  show <run> [--db FILE]              run 详情: 头部 + env_wide 一行 + bench 分布
  env-diff <a> <b> [--db FILE]        两 run 环境差异(env_wide 逐列)
  export <run> [--db FILE]            导出性能表 CSV(列同探针 data 行, xlsx 导入)
  ossl <native|latx|wine> [...]       独立 openssl 测速探针(入 ossl 表)
  dict [--table T] [--csv F] [--db]   字段翻译表出口(字段名/字段名解释/字段
                                      数据解释; --csv '-' 打 stdout)

库内表(读法)
------------------------------
每组一套三张表(键统一 (run_id, abi, grp, cname); pmul 的 cname = "<实现>/<档族>"):
  bench_<grp>  性能表: 只放具体指标 + 状态(结果签名 _sig / 语义对拍 / 迭代数 /
               kat 明细 / diag 明细全部移出)。列 = 本组探针 data 行的非身份列,
               按需 ALTER 补(逐表独立, **不跨表统一**); 另带 rep_n。
               pmul: 列 = abi/os/bits/window_sec/pmul_ver/<档>_ns/<档>_ops_s
  verify_<grp> 功能表: 一次功能测试一行, 列 = 该组每个功能名, 值 true/false;
               NULL = 本轮没判。宽表组的身份列是占位 '-'
               (功能判定的完整标准见同级 功能测试标准.md)
  debug_<grp>  详细表(仅 run --debug): 逐条明细, 第二键 kk
               标准组: in_v0/in_v1/in_flag + gold_*/got_*/st/diff_cols/expect_by/note
                 (每 case 每真值槽 kk=0..7; 由探针 dbg 段的 exp/got 两条合并)
               pmul:   in/gold/got/status/inbits/minpop(每 (实现,档族,档))
  (旧版 verify_x87 是明细表 —— 升级后 connect() 自动改名 debug_x87, 名 verify_x87
   留给 x87 的功能表)
  bench_all    视图已取消: 各组列独立, 读侧逐 bench_<grp> 表读
  field_dict   字段翻译表(严格三列, field_ 前缀), 真源 = isbench.py 顶部
               FIELD_DICT 常量, 库里是副本; 字段含义**以 field_dict 为准**
  腐化哨兵(dict_rot_check): 库里有列而字典没登记 -> 点名; 反之也点名。
常用 SQL:
  python3 isbench.py show <run> --db FILE                 # run 详情(三族表分布)
  SELECT grp, count(*) FROM bench_pmul GROUP BY grp;      # 某表行数
  SELECT cname, p00 FROM verify_pmul WHERE p00='true';    # 功能为真的用例
  SELECT cname,kk,diff_cols FROM debug_x87 WHERE st='FAIL'
   AND run_id='<本机 PE 的 run key>';                     # 逐字段差异(需 --debug)

运行示例
--------
  python3 isbench.py run native                   # 本机全组 x86_64+i386
  python3 isbench.py run latx --reps 3            # 龙芯主机; 3 轮聚合成一行
  python3 isbench.py run wine sse crypto          # wine 跑 exe(自动 killw)
  python3 isbench.py compare 164955 165048        # 库内 key 前缀对拍
  python3 isbench.py export 165048 > run.csv      # xlsx 软件直接导入
  python3 isbench.py ls --host 3A6000             # 只看该机器结果
  ISBENCH_PUSH=http://分析机IP:8770 python3 isbench.py run latx   # 免 scp

产物命名(每 18 组): bin/<group>-<x64|i386>_<linux|windows.exe>
                  lib/<group>-<同一形态名>.a(与 exe 同 .o 归档)
                  (例外: x87 只 i386 在册 -> 全仓永不存在 x87-x64_*)
组: scalar(标量整数) sse(legacy SSE/SSE2/3/SSSE3/SSE4.x) avx(AVX/AVX2/FMA)
    crypto(AES-NI KAT / PCLMUL / SHA; ECB 块负载已去, 归 ossl) cpuid(能力+开销) timer(时钟)
    本轮新增 10 组: mov 搬运 / alu 算术 / logic 布尔 / flag 比较测试 / shift
    移位旋转 / cc 条件分支三族 / ctrl 栈类 / bits 位扫描与 BMI(这 8 组 = xperf
    三层映射 k90 形态驱动的模板组) + special 串·原子·屏障·预取 / vec 向量
    补齐(这 2 组 = 直写口径, 一条指令一个函数, 不穷举形态)
    (两组均已落地: special 21 case / 11 词干接 KAT; vec 36 case / 26 词干接 KAT
    —— vec 只登记 sse/avx 两组之外的功能缺口, 不重测已有形态)
    x87 定点数搬运组(i386 专属, 18 case / 18 词干): 原属 special 的 6 条 x87 已
    整体迁至此组(词干与用例名不变, 迁后实测的 6x8 字段与 special 旧表逐字相同),
    另加 12 条高有效位整型往返。本组只在 i386 注册 —— 只有 -m32 的编译器会发射
    x87 整型搬运, 给 x86_64 造 x87 探针是测一份不存在的路径。
    ★ 护栏不能只靠构建清单, 也不能指望硬件: 实测(_tmp/x87_abi_cmp.sh, 见
      src/isb_x87.c 取证 6)拿 gcc 不带 -m32 编出的 x86_64 版照样能跑(SDM 说
      FLD/FST m80real 在 64-Bit Mode Invalid, 本机微架构并不拦), rc=0、自报
      18/18 全绿、144 块 K 行与 i386 ELF 逐字相同 —— 误登记在运行期完全看不出来。
      所以隔离做在编译期: isb_x87.c 顶部 #if !defined(__i386__) #error
    在册范围登记在三处且必须同集: build.sh 的 GRP_32ONLY / isbench.py 的 GRP_ABIS /
    _tmp/gen_val.sh 的 GRP_32ONLY; 对账挂 _tmp/sent_chk.sh(它还会反向验 x86_64 编不过)
    x87 也不进 CHECK_SENT(一致性自校验): 它只在一个 ABI 在册, 而自校验按两 ABI 查
    lat -> 必在 x86_64 侧静默落空(就是 mov/alu/logic 踩过的那个坑)
    pmul 多项式乘法实现对照组(两 ABI 均在册): 同一次 64x64->128 无进位乘的
    多实现同 run 对照(base/ref/hw/t4/t8); 用例 = (实现, 档族) 二维, 故入库键
    与其余组不同(impl/family 代替 cname), 列名全由本组自打的 field 行决定。
    分组依据 = LATX 成本结构 + 风险隔离(一条形态算错不拖全族), 不是按权重切块
build.sh 支持 --groups="mov ctrl" 分批构(组名必须在内置 ALL_GRPS 内, 未知名直接
拒绝); isbench.py 的 GROUPS 与 ALL_GRPS 必须同序同集。每组该产哪几个形态由
build.sh 的 forms_of() 算(= ALL_FORMS 减去不在册 ABI, 再叠 --without-32), 构矩阵与
dist 组装两个循环共用它, 所以"编了什么"与"落位什么"不可能不一致。

数据模型(为什么一行一个指令)
----------------------------
- 每个指令(case)在探针里依次经历 lat(单依赖链 ns/op)与 tput(定时长窗口
  ops/s, 可附 MB/s); 适合 8 连的指令另测 block8(每 8 连块执行 ns/块,
  同行新列, 不占新行); 部分指令另有 sem(语义对拍)或独立 kat/diag 实体。
- 旧模型按 (case,metric) 拆行, reps 再放大 N 倍(全量 reps=3 达 942 行/run);
  宽表把 lat/tput/block8/sem/kat/diag 变成同一行的列, reps 多轮只聚合一行
  (数值列取中位, 状态取多数, 状态波动/签名波动记 probe 注记)。
- 全量单架构: 97 指令行(原 157 metric 行); 双架构 reps=3 也仅 ~194 行。

探针 stdout 契约(三段同布局, xlsx 可直接导入)
-----------------------------------------------------------
每次 exec 的 stdout = 三段, 每段 = field 行(列名) + label 行(中文名) + 本段数据行;
末行是组尾行:
  性能段(data): group,abi,os,bits,window_sec,case,
        latency_status,latency_ns,throughput_status,throughput_ops_s,
        throughput_mb_s,block8_status,block8_ns,diag_status,diag_value,diag_unit
    每用例一行; 只放"指标 + 状态"(对不对不在这张表里)。
    (block8 三列仅注册了 8 连探针的指令填值, 其余行三列 '-')
  功能段(func): field,group,abi,<功能1>,<功能2>,...  一行:
        func,scalar,x86_64,true,false,...   值 true/false/-(本轮没判)
  详细段(dbg, 仅 --debug): field,group,abi,case,stem,kk,
        i0,i1,i2,i3,inf,o0,o1,o2,o3,outf,src   (标准组 = 10 字真值单元; src=got/exp)
        (pmul 为 group,abi,case,tier,in,gold,got,status,inbits,minpop)
  组尾行(group): group,<组名>,<ok>,<total>
  '-' 约定: '-' = 未测/不适用(入库 NULL); 段以 field 行为界, 换一组列就换一段。
Excel/WPS: 「数据 > 自文本/CSV」导入即得三段, 性能段每行一个指令。

探针列动态入库(新增探针数据列免改本脚本)
------------------------------------------
- 解析无静态列清单: 探针表头 = 契约, META 列(kind/group/abi/os/bits/
  window_sec/lat_iters/case/ok/total)之外全部按列名认领为数据槽; 缺列按
  未测(如旧探针无 block8 列), 截断行(无 case 名)自动丢弃。
- 入库自动补列: 先预扫本 run 全部行, 库缺列即 ALTER TABLE ADD COLUMN
  (列名须 [A-Za-z][A-Za-z0-9_]{0,30}); 类型按值推断: 全部数值建 REAL,
  否则 TEXT; 无任何有效值的列不建。各组表**各自独立补列**(见上节)。
- 聚合按列名后缀通用启发: *_status 状态取多数(有 OK 取 OK)、数值列
  (*_ns/_ops_s/_mb_s, 有同前缀 *_status 时仅用其 OK rep)取中位、
  其余文本取 OK rep 首值; 波动记 probe 注记。
- export 表头 = 各 bench_<grp> 列并集(缺列打 '-'); serve/push 全列传输,
  动态列免任何同步。
- 库缺列自愈: 升级 isbench.py 后旧库自动补列(无需删库/指定); 纯旧结构
  (窄表时代)库整体改名 *.old 备份后重建空宽库; 旧 verify_x87 自动改名 debug_x87。
- compare 只比指标模板列(latency/throughput/block8/diag); 缺列/行未测该
  方式自动跳过, 模板外未知列不参与对拍。

run 内建测量纪律(默认开, --warm 0 / --check 0 可关)
---------------------------------------------------
- 预热丢弃: 每个 (组, abi) 正式 reps 前先跑一次该组哨兵用例并丢弃输出
  (计 runs.warm_discards), 使 LATX 现场翻译/AOT 建立、icache/频率稳定
  的开销落在正式测量外(防缓存未建立首用例污染)。
- reps 聚合: 每 (组,abi) exec N 次, 同指令行按 cname 归并; 规则 = 列名
  后缀启发(见「探针列动态入库」节): 数值列(*_ns/_ops/_mbs/_v, 含
  block8_ns)取 OK rep 中位; 状态取多数; 签名波动/状态波动记 probe 注记。
- 一致性自校验: run 完成后取哨兵指令(x86_add_r64/aesenc)lat 列与本机
  (同 hname+cpu_model)最近一次 run 对拍, >±10% 记 check_note=MISMATCH 并在
  ls/compare 醒目告警(新装 LAT/清 AOT 后首次跑属预期); compare 打印两侧
  check_note 防污染样本当基准。

入库 schema(摘要)
-----------------
  runs(key PK, mode, arch, abi, reps, tput_ms, started_at, done_note, py_ver,
       imported_at, push_src, warm_discards, check_note, hname, cpu_model, ip)
  env_wide(run_id PK, 40+ 键列平铺)     -- 每 run 一行(键做列), 含 probe 注记
  bench(run_id, abi, grp, cname, rep_n,       -- 固定列仅这 5 个
        PRIMARY KEY(run_id, abi, grp, cname))
   度量列(lat_*/tput_*/block8_*/sem_*/kat_*/diag_*) 不定: 首次入库按探针
   表头列名自动 ALTER 补建(见「探针列动态入库」); 类型 = 值推断 REAL/TEXT。
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
  run: reps/tput_ms/only sha256sums_mtime;  probe_notes: 全部注记合并一段
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
以 truth 为基准, 对库内两 run 的 bench 宽行对拍。行归并按 cname(同 cname
多 abi 时取库序末行 = 单 abi 视图; 同机同流程的两 run 两侧取同一 abi, 故
跨机同 abi 对拍有效; 库表行键仍为 (run_id,abi,grp,cname))。每个测试方式
(lat/tput/block8/sem/kat/diag)各出一行明细:
状态一致性 / OK 行 sig 逐位 / OK 行数值保留率(±15% 外记 DEVIATION)。
CRASH/HOSTUNSUPPORTED 属已解释状态, 同态即通过; 汇总计数(DEVIATION>0 或
truth 缺键退出码 1); 两侧 check_note 一并打印。

用例名(宽表 case 列)首段 = ISA 段
---------------------------------
  scalar: x86_(基线; x86_add_r64 带 block8 列) | sse42_(crc32) | popcnt | abm_(lzcnt)
  sse:    sse_ sse2_ sse3_ ssse3_ sse41_ sse42_  (sse2_paddd 带 block8 列)
  avx:    avx_ avx2_ fma_
  crypto: aesenc/aesdec/pclmulqdq/sha256rnds2(名已含 ISA) | aes_ecb128
  cpuid/timer: diag 名即能力/度量名, 无混叠
原名保留为后段(如 ssse3_pshufb); block8 不产生独立 case —— 适合 8 连的
指令在同一行以 block8_* 列测(与 lat/tput 并列的计时方式, 见下节), 其余
指令行该三列空。同指令的语义用例仍独立 case(如 ssse3_pshufb_sem 与测速
case 分开, 各占一行)。只跑子集: --only PREFIX[,..](前缀带尾下划线,
--only sse2_ 精确选 SSE2; --only sse 会连坐 sse2_/sse41_/sse42_, 不命中
ssse3_)。

用例粒度与命名(两条口径并存)
------------------------------
已落地的 8 个模板组(mov/alu/logic/flag/shift/cc/ctrl/bits)是**形态级**用例,
不沿用上面的 ISA 前缀命名, 而是机械对齐 xperf 实测的形态表
(isbench/xperf-采集存放/round5_form_weights.csv, 107 助记符 / 443 form_key)
的 k90 形态 —— 这套名字保留是为了让已入库的 run 与 --only 切片不失效:

  case 名 = x86_<助记符>__<形态段>
  形态段变换: 助记符后的空格 -> '__'; 段内 '.' -> '_'; '/' -> '_'
  C 词干(sn) = 同段但只用单下划线(mov_r_m_q_base), 避开 __ 保留标识符

special / vec 起改为**直写口径**(本轮定案: 测的是指令集的功能, 不与 xperf 的
form_key/权重对齐, 不为对齐做形态穷举): 一条指令 = 一个 lat 函数 + 一个定时长
函数(+ 有架构结果时一个 KAT 探针), 不用参数化模板宏; case 名 = x86_<助记符> /
x87_<助记符>(如 x86_cmpxchg、x87_fadd_m64), 词干 = 去掉 ISA 前缀的同一串。vec
组同口径, 只是 ISA 前缀带版本号且用数字(sse_/sse2_/sse41_/avx_/avx2_, 如
sse2_psrlw、avx2_vpsllq、sse41_ptest), 词干 = 去掉该前缀的助记符。宽度
档、寻址段档不再机械枚举(模板组那套 `__<形态段>` 后缀在直写组里不出现); 只有
需要区分的功能差才各自手写一条(xchg 的寄存器/内存两形、cmpxchg 的 lock 前缀
两形), 具体形制直接写死在那个函数里。

例(form_key 逐字取自 CSV, 括号内为其全样本占比):
  mov r.m.q/base       -> x86_mov__r_m_q_base       (7.2318%)
  push m.r.q/rsp       -> x86_push__m_r_q_rsp       (6.9960%)
  sar r..l             -> x86_sar__r__l             (0.4056%)
  idiv r..l            -> x86_idiv__r__l
  mul r..q             -> x86_mul__r__q
  jne .                -> x86_jne___                je . -> x86_je___
  双点 `r..l` = 「无第二操作数」+ 宽度占位(隐式 1 位移位、单乘单除族都这形);
  点号 `je .` = 「无显式操作数」—— 目标确是 rel32, 但名里不写(见下条教训)。
- 名字不是文案问题, 是接口: cc/ctrl 两组的预热哨兵曾按直觉登成
  x86_jne__rel32 / x86_call__rel32, 而两组表行里根本没这两个名字 —— --only
  不命中时探针跑 0 个用例、退出码 0、不告警 = 预热静默关闭。现已由
  _tmp/sent_chk.sh 固定对账(从两 ABI 各自的 .o 里比 case 名字面量是否在册,
  再实跑 --only 数 T 行), 并挂进全矩阵自检 kat_all.sh 第 3 步。
- 踩到的第二个命名相关事实: `.q`(64 位 GPR)形态只在 x86_64 注册(组文件用
  #ifdef __x86_64__ 同时包住内核实例与表项), 所以 i386 侧 T 行数天然少于
  x86_64(alu 15/31、shift 8/21、mov 16/34 ……), 不是漏采; 也因此哨兵必须选
  两 ABI 都在册的 `_l` 形态(交集由 _tmp/sent_pick.sh 从两个 ABI 的 .o 算出)。
  直写组另有一条共表约束: KAT 表只在 x86_64 采一份给两 ABI 共用 -> 接 KAT 的
  case 其操作数宽度必须与 ABI 无关(special 的原子族因此钉死 32 位; 不上表的
  预取/屏障/pause/nop 不受此限; vec 的 7 条 ymm 因结果宽 256 位整族不上表)。
- CSV 里 nf=0 的形(ror r.i.q 与 BMI2 四条 shlx/sarx/shrx/rorx: 采样窗内没抓
  到, 但属静态清单里的贵形态/锚点)名字按同一变换机械合成, 组头注里一律标
  nf=0 —— 不假装有实测权重。模板组仍按此口径维护; 直写组不再引 CSV 形态。

单指令数据纪律(读结果前必读)
----------------------------
- 单指令用例一律固定数据: 固定输入=固定输出, sig16 跨 run 可复现, 用于
  验证 LATX 翻译语义正确性(不随机化, 本基准核心契约)。
  口径补充(本轮接 KAT 后): 「固定」= 确定可复现, 不等于「只有一个常数」。
  计时内核仍是单一定值(签名跨机逐位比); KAT 探针的输入是由(词干, 序号)
  哈希推导的 8 组伪随机值(FNV-1a + splitmix64, 编译期即可重算) —— 既不是
  运行时 rand(), 也不需额外数据文件: 同一份源码在任何机器上推得同一套输入。
- 组文件全局不开 -mavx*: SSE 家族保持 legacy 66/0F 编码(32 位 libcef 形态);
  AVX/FMA/AES 各用例函数 target 属性单发 VEX, 编译期即忠实编码形态。
- 依赖链第二操作数/掩码来自轮转内存(确定性填充), 防 GCC 闭式折叠
  (折叠假象: lat≈0.0x ns 或 tput>1e11 ops/s)。
- 纯访存用例由 asm volatile 钉死, 地址用寄存器约束(防提升为循环不变量)。
- 访存族 lat 是近似参考(无寄存器依赖链); tput 才是其真值。
- crypto KAT 为 FIPS-197 自检(PASS 即密钥展开/加密/解密正确)。
- block8 已落地: 不建独立 case 行 —— 8 连块是同一指令行的新列(与 lat/
  tput 并列的计时方式), 数据另源(确定性轮转缓冲, 见下节)。

功能测试统一标准(KAT v2; 单一出处 = 同级 功能测试标准.md)
--------------------------------------------------------
- 本节及下面 KAT 一节只是速览; 功能测试(这条指令译对没有)的完整口径以
  `功能测试标准.md` 为**单一出处**: 测试对象与真值来源 / 10 槽真值单元与字段序 /
  统一输入生成器(ib_gen.h) / 判定与状态机(含错档核 INMISMATCH) / 采集与守卫
  (gen_val.sh + build.sh GEN=1) / 分组清单与去重口径 / 各组归属 / 单组 --help 契约。
- 一句话: 真值只来自真 x86(本地 WSL x86_64 ELF + Windows 本机 PE), 同一输入在
  任何机器重导; 判定只比输出 o0..o3+outf; 输入存表仅作错档核(不一致报 INMISMATCH)。

KAT 真值表(同一次运行内自采集 / 自比对, 无独立取数程序)
--------------------------------------------------------
- 契约: 每个接了 KAT 的 case 在源码里带一张 8 行真值表 src/isb_<grp>_kat.h,
  每行 = {i0,i1,i2,i3,inf,o0,o1,o2,o3,outf}(4 字输入 + 入标志 + 4 字输出 + 出标志,
  覆盖 GPR 32/64、XMM 128、YMM 256、x87 80 与 EFLAGS)。KAT v2 以后“判定只比
  输出 o0..o3+outf”, 输入存表仅作错档核(表内输入 != 现场生成输入 -> INMISMATCH)。
  统一标准见同级 `功能测试标准.md`。
  探针启动时只看表是否已回填: 未回填 -> 采集分支, 单发执行该指令 1 次(不进
  计时循环)并把 8 组输入输出以 kind=K 附表行打到 stdout; 已回填 -> 比对分支,
  逐字段相等才 kat_st=OK, 不等则 KATFAIL 且 kat_det 直接指到出错字段与行序号
  (如 k=3 o0.l e=0000abcd g=0000abce)。所以「采集」不是一个模式、也不需单独
  写取数 exe: 同一份二进制、同一次运行, 表空即采、表满即比。
- kat_st 三种合法值: OK(已比对通过) / COLLECT(表未回填, 本次在产 K 行) /
  '-'(本 case 未接 KAT)。一个 KATFAIL 产 2 行 K(期望行 + 实得行)。
- 输入不是运行时 rand: IB_KIN8 由(词干, 序号)经 FNV-1a + splitmix64 推导,
  同一份源码在任何机器上推得同一套输入(编译期可重算, 无数据文件); 标志入值
  IB_KFL/IB_FV 恒置 bit1(RES 位)并按族套掩码(全量 0x8d5 / 只 CFOF 0x801 /
  逻辑 0x8c5 / 移位 0x0c5 / 旋转 0x0d5 / 扫描 0x041), 不拿不可比对的状态当
  判据。每指令 8 组输入也是将来 8 连块(block8)的数据源。
- 探针的栈纪律(实测坑): IB_SETF/IB_GETF 用的是 pushq/pushfq, 写的正好是 [rsp-8],
  而 -O2 下叶子探针里 GCC 会把按地址逃逸的局部量放进红区(-0x2..-0x80(%rsp)) ——
  一次 push 就能把必须跨 asm 存活的栈上数据踩掉(special 组 x87_fcw_rt 首采就
  把 i0/o0 全写成 0, 复现 _tmp/x87o.sh; 该用例现已迁至 x87 组、词干仍叫 fcw_rt)。
  口径: 用了这两个宏的探针, 操作数槽
  一律放文件作用域数组(g_mem/g_f/g_cw), 需要带出 asm 的值走寄存器输出或全局槽,
  输入在 asm 之前就写进 got; 详见 ib.h 的 IB_SETF 头注。
- 采集与入表(KAT v2, 本地真 x86): 统一脚本 `bash _tmp/gen_val.sh <grp> [iters]
  [time]` —— 编 x86_64 采集版 -> 跑 `<探针> --gen-gold`(忽略现表, 逐槽吐 got 明细)->
  收割 dbg(src=got) 行生成 10 字真值表。只采 x86_64 一份表, i386 共用: 若某形态
  真值其实依赖 ABI, i386 一跑即 KATFAIL(运行时暴露)。探针内 `ib_gold_host_ok()`
  守卫 --gen-gold 只在真 x86_64 上跑; 生成物形状/LF 校验不过即保留旧表。完整标准见
  同级 `功能测试标准.md`。
- 现状(KAT v2, 10 字真值单元): **全部指令组已接表并已按新口径重采**: flag 18 /
  bits 17 / alu 31 / logic 15 / shift 21 / cc 44 / mov 34 / ctrl 6 / special 11 /
  vec 26 / scalar 3 / sse 42 / avx 22 / crypto 4 / x87 47 词干。两 ABI 共用一份
  x86_64 采集表(x87 只在 i386 在册 -> 走 i686 PE 采集)。cpuid/timer 无指令语义
  真值 -> 只走 diag; special 的预取/屏障/pause/nop 与 vec 的纯 store 等无架构结果
  的形态不接表。分组职责与去重口径见 `功能测试标准.md` 第六节。
- 跨机 + 跨 ABI 实测(2026-09-06, _tmp/box31_kat.sh / box31_neg.sh): WSL
  采集的 8 张表推到 box31(Kylin V10 SP1 x86_64)后, 8 组 x 两 ABI 共 16 个
  二进制全部 rc=0, 零 KATFAIL、零 CRASH/SIGILL, K 行=0; x86_64 侧合计 186
  行 OK, i386 侧 107 行 OK(差额全是不在本 ABI 注册的 .q 形态)。同一批注入表
  再在真机上用真机自己的 gcc 9.3.0 现编现跑 -> 10/10 注入在两 ABI 上全检出,
  即「检出」不依赖构建机的寄存器分配。例外: ctrl 的 i386 侧接 KAT 行数为 0
  (六条 push/pop 全在 #ifdef __x86_64__ 内, leave/retf 不上表), 不要把该组
  「i386 全 OK」当跨 ABI 证据。
- 上条只覆盖当时那 8 组; special 的 11 词干与 vec 的 26 词干目前仅有构建机(WSL,
  真机 x86_64)侧的采集 + 审计 + 注入闭环 + 两 ABI 共表比对, 推到 box31 复验排在
  全矩阵轮。vec 的两 ABI 共表已在构建机原生跑过(2026-09-06, WSL1 interop 直接跑
  PE): x86_64_windows.exe 与 i386_windows.exe 各 36 行 T / 26 行 kat OK / 零 KATFAIL
  / 零 CRASH / K 行=0 —— 表只在 x86_64 采一份、i386 直接比通(本组无 .q 门控形态,
  两 ABI 的 T 行数天然相等)。
- 自检四件套(脚本在 isbench/_tmp/, 开发侧; kat_audit.py 随发布目录):
    build.sh [--groups=]  四形态编译 + 静态核查 + dist 组装(全矩阵 18 组 x 4 形态)
    gen_val.sh <grp>     采集入表(合并原 gen_kat.sh 与 pmul/gen_gold.sh; PE=1 走
                         i686 PE 采 x87; 形状/幂等/LF 校验不过则保留旧表)
    kat_audit.py <表>    独立 Python 第二实现逐字段复算, 与 C 探针不共享代码
                         （全部已接表词干 15 组 / 341 词干全覆盖, 不符=0 跳过=0）
                         —— 只验「表与规则自洽」, 不验「规则与 x86 一致」
    kat_neg.sh <grp>     负向: 15 处注入(10 字段各翻首位 + 输出侧 5 字段翻末位)
                         必须全检出: 输入侧翻 -> 错档核报 INMISMATCH、输出侧翻 ->
                         输出比对报 KATFAIL, 且 dbg 段 exp/got 指到被注入字段;
                         判据只看该 case 是否翻转, 不把未接 KAT 的 '-' 行当检出
    kat_all.sh          上面三项 + 哨兵对账 + 全矩阵四形态编译, 末行须为
                        `== 结论: 全部干净 ==`
- 为何计时签名不够、还要 KAT: 计时内核的 sig16 是 N 轮链累加后的末值, 一条
  指令算错可能被后续轮次掩盖(不动点/折叠, isb_shift.c 头注实测过 7 条 case
  lat_sig 全等于 1), 且说不出错在哪; KAT 是单发执行 + 逐字段比对, 错在哪个
  操作数/哪个标志直接点名。
- 判据分层(本轮改判, 影响所有组的读法): 正确性 = KAT 逐字段比对; 计时列只
  要求跨 run/跨机可复现 —— 「两条 case 同签名」不再当交付缺陷(q_dup.sh /
  sig_const.sh 从门槛降为诊断工具), 因为同签名大多只是「同骨架下值流本就
  相同」: flag 组 18 条只剩 11 个唯一 lat_sig(cmp 若与 test 同值 => 本窗口内
  CF 恒 0 的实测证据)、ctrl 组 push/pop 三条同值(每轮 push+pop 成对 => 净栈 0,
  骨架使然)、bits 组 bsf≡tzcnt、shift 组 shl/shr 的 $3 与 %cl=3(同一条运算的
  两种编码)。逐对解释写在各组文件头注, 不在这里重列。
  但「链主进吸收态」仍算缺陷(不是撞车, 是整族从计时列里拿不出任何信息):
  isb_cc.c 头注的 v1->v5 链就是为了让三族都拿到唯一签名而记的账。
- 栈类(push/pop/pushf)真值语义: 输出在栈上 -> 从栈顶回读, 回读连带验 rsp
  位移; 造栈帧只能 push, 且 push 的值必须与槽内原值不同, 否则「真写了内存」
  与「什么都没写」回读同值 = 不可证伪(故 IB_KT_POPM 压 i0, 而写槽已被广播成
  i1); pushf 压的是标志本身 -> o0 = 栈字 & 0x8d5, 即 inf 的同掩码值。

连续8指令块(block8): 块级优化探针与判定口径
------------------------------------------
- 落地形态: 不建独立 case 行。注册了 b8 探针的指令(现: x86_add_r64 =
  scalar 8 连 addq/addl; sse2_paddd = 8 连 paddd)在自身行填 block8_* 三
  列, 与同行的 lat/tput 同 run 对照; 未注册行(不适合 8 连形态)三列空。
- 语义: 块 = 同一指令连续 8 条, 各作用于一条独立寄存器链(零块内依赖);
  操作数来自确定性轮转缓冲 8 个相位(同轮互异、8B 步进轮转不重复, 与单
  指令用例的固定常数源区分, 防"同值重复"被数据级优化利用)。
- 计时与签名: 与 tput 同内核 —— 定时长窗口累计块执行时间, block8_ns =
  每 8 连块平均执行 ns(单块时间, 批数自适应, 与 rep 数无关); 稳定签名
  固定取 4096 块调用的返回值, 不受窗口批数影响。行内于是并列三计时量:
  lat_ns(单链依赖延迟) / tput_ops(流水吞吐) / block8_ns(8 连独立链块
  流水时间), 同 run 可互相对照。
- 目的: 探 LATX/CPU 是否出现块级(跨 8 条同指令窗口)特化 —— 8 连互异数
  据、零块内依赖, 正是翻译器「整块向量化/合并/批量派发」的候选形态。
- 判定口径(同 run 同行与单指令列对照):
  块内 8 条若与单指令同流水吞吐, block8_ns 应 ≈ 8 个单 op 吞吐时间量级
  (对照 tput_ops); 显著更低 = 疑似块级特化(整块合并/向量化/批量派发,
  须反汇编佐证); 显著更高 = 块间转换/派发开销放大(如 LATX 无批量路径
  的逐条边界损耗)。block8 块内刻意零依赖 + 互异数据, 与 lat_ns 无换算
  关系: 若 block8_ns 反常贴近 8xlat_ns, 说明块内链未断开(实现可疑)。
  LATX 与 native 同口径对拍, 比值差异即翻译器块级路径信号与代价。
- 签名纪律: 数据确定性(非随机) -> sig16 跨 run/跨机逐位可复现; 链初值
  须互异大常数 —— 若用连续小整数(1..8), 周期对称 + 加法交换律使 8 链
  16 轮同增量、只差初值, sig16 会数学归零(实测恒 0000)丧失区分度, 勿复。
- 实测(2026-09-05 首采; ns/块, 机间比值即判读例):
    x86_add_r64: x86_64 0.83(构建机) 1.45(box31 native) 1.62(box22 LATX);
                 i386 3.11(box31) 5.05(box22)
    sse2_paddd : x86_64 2.9(构建机) 4.34(box31) 6.33(box22);
                 i386 5.48(box31) 11.97(box22)
  sig16 跨构建机/box31/box22 逐位一致: x86_add_r64 = f3e55bbe1634f248
  (x86_64) / 213ff1ef1d16c344(i386); sse2_paddd = 001d00000000c000(x86_64)
  / 000f800000000000(i386) —— LATX 翻译语义逐位正确, block8_ns 是纯性能
  侧量纲。
- i386(寄存器受限: 7 GPR/8 xmm): 退化为 4 链 x 每轮 2 相位, 块内仍保持
  8 条连续指令, 判定口径不变。

全矩阵验证结果(2026-09-06: box31 native + Windows 本机 PE + box22 LATX)
----------------------------------------------------------------------
- 判定基准只有两条(用户口径): 冒烟 = box31 上跑的 native ELF, 加 Windows 本机直跑的 PE。
  两者结果一致(T 行数 / katOK / KATFAIL 逐项同数)=> 测试工具与被测代码都没问题。
  LATX 或 wine 报出的差异是另一层的事(翻译器 / wine 自身), 到那边去修, **不得倒逼改
  测试工具的判据** —— 工具要保持干净纯净: 数据通道只承载探针 stdout, 解析判据不因
  外部噪声放宽。本轮据此撤掉了上一版"让 parse_seg 容前导噪声"的写法(见下 wine 段)。
- 重跑 build.sh 后哪些结论还能用(_tmp/dist_hash_cmp.sh 逐文件哈希对账, 按路径 join
  只比共同文件 —— 否则会把"真机没推的新产物"误读成"产物变了"): 共同 132 文件
  只有 33 条变化 = 32 个 windows.exe + 1 个刚改的 README.txt; **_linux 与 .a 变化 0 条**
  -> 指令探针 ELF 逐文件未变, 真机 native 与 box22 latx 两轮的测物就是重建后这份。
  PE 全变是 mingw 在 PE 头写 TimeDateStamp(实测 0x6a9d54a3 = 本次构建时刻) -> **PE 属
  不可复现构建**, 源码没变哈希也会变; 所以只要重跑过 build.sh, Windows 本机 PE 基准
  必须重跑一次才能说"双基准对同一份 dist 成立"(本轮已重跑: T=617 katOK=379 KATFAIL=0)。
  另: 本地 dist 有 bin/ossl11-{x64,i386}_linux 而真机无 —— ossl 探针对没随本轮 tar 推,
  不属指令矩阵, 要跑 ossl 得单独推。
- 测物 = 交付物: 同一份 dist(18 组 = 17 组 x 4 形态 + x87 只 i386 两形态 = 70 产物,
  tar 20MB)推到各机
  ~/isbench-dist/dist, 真机上一律不重编(曾在真机现编, 参数与自检脚本漂移会得出
  只在本机成立的结论)。box22 无 sshpass(WSL 未装), 但 WSL 公钥已授权 -> 免密直用。
- box31 native(Intel i3-4150/Haswell, sse 全族+avx2/bmi2/f16c/movbe 硬件都有):
  `run native --time 300` -> 617 指令行, katOK=379 / KATFAIL=0 / COLLECT=0 /
  CRASH=0(x86_64 229 词干 + i386 150)。i386 行数天然少(mov 16/34、alu 15/31、
  ctrl 2/8)是能力门控(.q/REX.W 形态只在 64 位注册), 不是失败。
- PE 判定优先 Windows 本机直跑(_tmp/win_run_pe.ps1, 用户定的口径: wine 可能不正确):
  32 个 PE -> `T=617 katOK=379 KATFAIL=0 KATPEND=0 CRASH=0 PEND=0`, 与 box31 native
  逐项同数 -> PE 侧产物无问题。脚本必须用 Start-Process -RedirectStandardOutput
  取原始字节: PS 的 `> file` 写 UTF-16(同一份输出 3922 字节变成 7844), 喂给
  parse_seg 会整份判 0 行(踩过)。
- wine(kylin-wine on box31): 上一版为它改错了地方, 本轮纠正。症状是 wine 轮整轮判 0 行
  (rc=0、3981 字节), 当时改成"在前若干行里定位 kind 表头"去容 wine 的启动警告 —— 方向
  就错了(让外部噪声倒逼工具放宽判据)。真取证(_tmp/box31_pure.sh 步骤 0, 直跑 wine 人工
  分两管道): stdout 3924 字节且**首行就是 kind 表头**、T 行 27 / D 行 1, 而 635 字节噪声
  (004c:fixme:ole:CoInitializeSecurity … 及 GL/MESA 警告)全在 stderr —— 噪声从来就不在
  数据通道里, 是 execp 自己用 stderr=STDOUT 把它合进来的。改法: execp 分开捕获两管道
  (stdout 独占给 CSV, stderr 经 _brief 缩成一行只进 notes 诊断列; 附带使 EXIT/TIMEOUT
  注记现在能带上真正的错因), parse_seg 恢复"表头必须在第 1 行"的严格判据。
  真机复验(同一份 dist, 16 组 x 两 ABI): native 617 行 + wine 617 行, 两轮都
  consistent(亚ns跳过6); native vs wine 对拍 1505 方式行 DEVIATION 46, 其中 sig 不一致
  3 条与上一轮逐条相同 -> 解析内容零漂移、判据未削弱。挂 _tmp/chan_purity_chk.sh 作
  回归(拿 Windows 本机真跑的样本 + 模拟 wine 噪声走 stderr: stdout 与样本等长 3922
  字节、解出 27 行; 若噪声真占了首行必须判 0 行告警, 不得吸收)。
  wine 自身仍可能不正确(下条实证), 但它不正确不是工具要迁就的理由。本轮与 native
  对拍的 3 条 sig 不一致, 三方归因(Windows 本机 / kylin-wine / Linux ELF 各跑同一 case):
    x86_leave___(i386): Win 本机 == wine == a4bfbe065c819184 != ELF f1cc75d765f121c8
      -> wine 正确, 差异是 PE/ELF 平台固有(leave 签名卷入栈内容, 两 OS 初始栈与
      模块基址本就不同) -> 跨 os 对拍这类行必然报, 记档不设门槛;
    fma_vfmadd213ps_sem(x86_64): Win 本机 == ELF == fdcbe0356793c4b4 != wine
      fdcbe035666c9bb6 -> **kylin-wine 侧不正确**(同一 PE 在真 Windows 与 Linux
      逐位一致)。这就是"wine 只作参考"的实测依据。
- box22 latx(Loongson-3A6000, latx-x64-update 20251230, binfmt i386+x86_64 都已注册,
  故 latx 模式直接 exec x86 ELF, 不需 LATX64/LATX32 前缀): `run latx --time 300` ->
  617 行(与 box31 native 同数), `push` 并入 box31 中心库后 compare:
  **1505 方式行零签名不一致**, 功能类例外 10 条分两类:
    HOSTUNSUPPORTED 7 条 = abm_lzcnt(两 ABI lat+tput) + x86_movbe__r_m_q_base
      (lat+tput+kat) -> LATX 能力边界(box31 硬件 flags 里有 abm/movbe, 所以是
      翻译器不发射, 不是 CPU 不支持), 记档;
    KATFAIL 3 条 = bits x86_bsf__r_r_l(两 ABI) + x86_bsr__r_r_q -> **已定到指令级**:
      det 报的差异字段是 outf 而非 o0, 独立探针(_tmp/bsf_probe.c, 同一份 static
      ELF 在两机各跑, 11 组输入 x 两 ABI)显示 bsf/bsr/tzcnt 的结果逐位一致, 唯
      EFLAGS 的 CF: 真机非 0 源时 CF=0(0x206/0x202), LATX 恒 CF=1(0x283/0x297)。
      按 SDM, BSF/BSR 的 CF 是明定义的(src=0 -> 1, 否则清 0) -> LATX 该位未按架构
      清零, 修复方向在 LATX; 结果与 ZF 都对, 所以不是"扫位算错"。
  计时只作开销数据: lat 倍率均值 298.8%(极值 1652.7%), tput 均值 56.7%(极值
  2592.8%)。跨 run 自校验报 `MISMATCH(x86_64_aesenc 83%)`, 与 9/5 两轮同一条
  (115%) -> LATX 上 aesenc 计时跨 run 不稳, 属计时侧。
- 本轮随之改掉的两个判据(都是先误报、后拿实测收口, 勿复):
    CHECK_MIN_NS = 1.0: 亚 ns 的行不参与 ±10% 跨 run 自校验 —— box31 同机三次
      native 的 x86_64/x86_add_r64 = 0.300/0.450/0.310, 连着两轮报 150%、69%
      MISMATCH, 而 i386 同行(0.670/0.670/0.680)与 aesenc 全稳定 -> 不是内核不
      确定, 是这一行本身在计时粒度上。现在显示 `consistent(亚ns跳过6)`;
    _tmp/fold_chk.sh(已挂成 kat_all.sh 第 4 步)v2: 防折叠必须每配置跑 2 次取
      best(噪声只会把时间读长), 同 iters 比 sig、跨 iters 只比量级 —— lat_sig
      本就随 iters 变(s = c->lat(it)), 拿它跨 iters 比是错判据; WSL1 上一次调度
      抢占就能把 0.74ns 读成 9.49ns(x86_ror__r_i_q, 曾报 x12.17 假例外)。现 10 组
      251 行全零例外。
- 计时签名退化按现行口径只记档不返工: 真机 52 行 tput_sig 恒 0(vec 23/36、
  sse 21/42、avx 8/15、special 8/27), lat_sig 仅 2 行 -> 只影响计时列区分度,
  正确性由 KAT 逐字段比对承担(见上「判据分层」)。
- 数据位置: 中心库 = 指令测试工具/results/isbench.db(由 box31 库经 _tmp/db_pull.sh
  <ip> [commit] 收回, 11 runs / 3352 bench, 含 box31 native x2 + wine x2 与 box22
  latx); 跨机合并走 push -> serve(两向 8791/8792 实测都可达, 选 box31 当中心因为
  native 真值与 wine 都在它库里)。

部署动作(目标机第一次)
----------------------
1. 整目录拷贝(含 bin/ isbench.py)
2. python3 --version 自检; 缺则安装(apt install python3)
3. (可选) 分析机起 serve; 测试机 run 加 --push 或 export ISBENCH_PUSH

独立 openssl 测速探针(ossl)
----------------------------
- 目的: 加密/摘要算法在 x86 openssl 实现上的吞吐, 同一静态 ELF 原生直跑
  vs LATX 全翻译对拍 —— "LATX 翻译 x86 openssl 加密实现"的性能, 服务
  AES 位切/vpaes 类翻译优化价值判断。与 src/ 指令探针**分离编译、另建
  表 ossl 入库**(列名 = 加密名_块尺寸), 互不干扰。
- 形态: ossl/ossl_probe.c + ossl/build-ossl.sh(WSL) 静态链同形态
  libcrypto.a, 产全静态 ELF dist/bin/ossl-x64_linux +
  ossl-i386_linux(i386 加 gcc -m32); build.sh 尾段自动调用。构建前置
  (构建机 WSL): apt install libssl-dev libssl-dev:i386 gcc-multilib
  libc6-dev-i386 zlib1g-dev zlib1g-dev:i386 libzstd-dev libzstd-dev:i386
  (Debian libcrypto.a 静态链需补 zlib/zstd)。
- 计时纪律: 只 clock_gettime(CLOCK_MONOTONIC) 定时长窗口(默认 0.5s/
  (算法,尺寸)); **禁 rdtsc** —— LATX 伪造 rdtsc, openssl speed 自带
  rdtsc 计时在 LATX 失真, 故自研探针弃用之。
- 输出(探针 stdout, 3 行): '# ossl_ver=<版本>' / 表头 = 度量列名 CSV
  (列名 = <EVP 算法名 '-'->'_'>_<块尺寸>, 如 aes_128_cbc_8192) / 值行
  MB/s(2 位小数)。库无的算法(探测失败)整组不出列, 列集随库版本自适应。
- 算法/尺寸: cipher aes-128/192/256 x ecb/cbc/ctr/gcm + sm4-ecb/cbc/ctr
  (sm4-gcm 仅库支持时纳入: Debian 3.5.7 与 1.1.1w 静态库实测均未编入,
  动态枚举自动跳过, 列集合两版一致) + chacha20; digest
  sha1/sha256/sha512/sm3(对 size 字节输入做摘要);
  尺寸 16/64/256/1024/8192/16384。
  EVP_get_cipherbyname/digestbyname 运行时枚举。
- 数据: isbench.py 新表 ossl, 每 (mode,abi) 一行(runs.mode 记
  ossl_<native|latx>; run key 不带 abi, 形态靠 ossl 表 abi 列区分,
  --abi all 时两形态 key 由各自时间戳天然不同), runs/env_wide
  照常采集 + ossl 一行。ossl 固定列
  仅 run_id/abi/os/bits/tput_ms/ossl_ver; 度量列(算法_尺寸)按探针表头列名
  动态 ALTER(全数值 REAL), 新增算法/尺寸免改 py; reps>1 数值取中位
  聚合为一行。不参与指令哨兵/compare。
- 命令: python3 isbench.py ossl <native|latx> [--abi x64,i386|all]
  [--time MS] [--reps N] [--warm 0|1] [--push URL]。ls/show/export 识别
  ossl run(export 导该行宽 CSV); serve/push 载荷含 ossl 行。
- 判读示例(即 LATX 翻译优化候选信号): 同算法同尺寸列 native vs LATX
  MB/s 比值 = 翻译保留率; AES 系列(LATX 侧 AES 位切路径/tr-vpaes 开关)
  与 SM4/Chacha20(软实现)的表现差分别归属翻译与实现两层。
- 调试: 环境变量 OSSL_PROBE_ERR=1 时探针 fail 路径打印 OpenSSL 错误栈
  (定位 fetch/init 类失败用)。

openssl 1.1.1 共存模块(ossl11)
--------------------------------
- 形态: 与 ossl 同源 ossl/ossl_probe.c(纯 legacy EVP API, 1.1.1 兼容),
  ossl/build-ossl11.sh(WSL) 自编 openssl 1.1.1w 静态 libcrypto.a(源码
  /tmp/osrc/openssl-OpenSSL_1_1_1w, 下载见 _probe/dl_src.sh), 产
  dist/bin/ossl11-x64_linux + ossl11-i386_linux(全静态 ELF);
  build.sh 尾段自动调用。1.1.1 无 zlib/zstd 依赖, 静态链仅 -ldl -pthread。
- 数据: 与 3.x **同一 ossl 表共存**, ossl_ver 列分版本(runs.mode 记
  ossl11_<mode>, 二进制 ossl11_*); 列集合与 3.x 版一致(Debian 3.5.7 静态
  库与 1.1.1 同不出 sm4-gcm)。serve/push/export/show 全复用(export 已认
  ossl11_ 前缀), run key 仍不带 abi。
- 命令: python3 isbench.py ossl <native|latx> --ver 11 [--abi all]
  [...同 ossl 参数]; --ver 默认 3 即 3.x, 行为不变。
- 作用: 3.x 同源 legacy-API 探针的 1.1.1 对照形态。两种形态在各机各
  ABI 的对照结论等背景详见过程报告:
  过程报告/LATX-OpenSSL3.x-provider失效-定点x87fild精度-20260906.md
