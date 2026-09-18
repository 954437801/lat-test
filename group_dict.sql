-- group_dict.sql -- 测试组与环境变量的翻译/解释(单文件权威来源)
-- isbench.py 读取并 executescript; 修改注释只改本文件。

CREATE TABLE IF NOT EXISTS group_dict(
 grp         TEXT PRIMARY KEY,
 grp_meaning TEXT,
 grp_detail  TEXT,
 grp_fields  TEXT);

-- 18 个指令测试组(产物名 = grp 列值)
INSERT OR IGNORE INTO group_dict VALUES
('scalar', '标量整数指令', '基础整数运算: ADD/SUB/MUL/DIV/INC/DEC 等; 无 SIMD/x87 特性依赖', 'run_id,abi,grp,cname,rep_n + 动态度量列'),
('sse', 'SSE 浮点/SIMD 指令', '128 位 SIMD: MOVAPS/MULPS/ADDPS/CVTSI2SS 等 SSE/SSE2/SSE3/SSSE3/SSE4', 'run_id,abi,grp,cname,rep_n + 动态度量列'),
('avx', 'AVX/AVX2/AVX-512 指令', '256/512 位宽 SIMD: VMOVDQA/VMULPD/VFMADD231PD 等; 需 VEX/EVEX 编码', 'run_id,abi,grp,cname,rep_n + 动态度量列'),
('crypto', '加密指令', 'AES-NI/PCLMULQDQ: AESENC/AESDEC/AESKEYGENASSIST/MCLMULQDQ 等', 'run_id,abi,grp,cname,rep_n + 动态度量列'),
('cpuid', 'CPUID 变体测试', '不同输入 EAX 值下的 CPUID 输出; 验证特性位上报一致性', 'run_id,abi,grp,cname,rep_n + 动态度量列'),
('timer', '时间戳指令', 'RDTSC/RDTSCP/ARDETECT 等计时器指令; 测量翻译开销', 'run_id,abi,grp,cname,rep_n + 动态度量列'),
('mov', '数据搬运指令', 'MOV 全族: 寄存器/内存/立即数/段寄存器; 含 LEA/PUSH/POP/BSWAP', 'run_id,abi,grp,cname,rep_n + 动态度量列'),
('alu', '算术逻辑指令', 'ADD/ADC/SUB/SBB/AND/OR/XOR/NOT/NEG/IMUL/IDIV 全族', 'run_id,abi,grp,cname,rep_n + 动态度量列'),
('logic', '位运算指令', 'BT/BTS/BTR/BTC/BSF/BSR/POPCNT/LZCNT/TZCNT 等位操作', 'run_id,abi,grp,cname,rep_n + 动态度量列'),
('flag', '标志位指令', 'LAHF/SAHF/SETcc/CMOVcc/ADCX/Aadox 等标志位密集型', 'run_id,abi,grp,cname,rep_n + 动态度量列'),
('shift', '移位指令', 'SHL/SHR/SAR/ROL/ROR/RCL/RCR/SHLD/SHRD 全族', 'run_id,abi,grp,cname,rep_n + 动态度量列'),
('cc', '条件跳转/调用', 'Jcc/JMP/CALL/RET/LOOP 等控制流; 含 REL8/REL32/INDIRECT', 'run_id,abi,grp,cname,rep_n + 动态度量列'),
('ctrl', '段/栈控制指令', 'ENTER/LEAVE/LOOPcc/LOOPE/LOOPNE/REP 等栈与循环控制', 'run_id,abi,grp,cname,rep_n + 动态度量列'),
('bits', '位域指令', 'SHRD/SHLD/BFEXTU/BFINS/EXTBL 等位域操作(LoongArch 对应)；x86 侧用 BT/BSF 等模拟', 'run_id,abi,grp,cname,rep_n + 动态度量列'),
('special', '特殊/杂项指令', 'CPUID/UD2/INT3/NOP/XCHG/LFENCE/SFENCE/MFENCE 等不宜归类的指令', 'run_id,abi,grp,cname,rep_n + 动态度量列'),
('vec', '向量/多媒体指令', 'MMX/XMM 混合: PACKSSDW/PMULLW/PUNPCK 等; 非纯 SSE 族', 'run_id,abi,grp,cname,rep_n + 动态度量列'),
('x87', 'x87 FPU 指令', '传统 x87 浮点: FILD/FISTP/FADD/FMUL/FSIN/FCOS 等; 只 i386 在册', 'run_id,abi,grp,cname,rep_n + 动态度量列'),
('pmul', '多项式乘法实现对照', '同一次 64x64->128 无进位乘的多实现同 run 对照: base/ref/hw/t4/t8; 每行 = 一个 (实现,档族), cname = "<实现>/<档族>"', 'run_id,abi,grp,cname,rep_n + 动态度量列(<档>_ns/<档>_ops_s)');

-- LATX 翻译器环境变量(采集自 env_wide.latx_* 列)
INSERT OR IGNORE INTO group_dict VALUES
('env_latx', 'LATX 翻译器环境', 'LATX 翻译器运行时环境变量与翻译器指纹; 非测试组, 是环境采集维度',
 'latx_LATX64, latx_LATX32, latx_LATX_OPTS, latx_LATX_AOT, ' ||
 'latx_LATX_VPAES, latx_LATX_SOFFPU, latx_LATX_DEBUG_AOT, ' ||
 'latx_other, latx_tr64_effective, latx_tr64_size, latx_tr64_mtime, ' ||
 'latx_tr64_sha256, latx_tr64_ver, latx_tr32_effective, latx_tr32_size, ' ||
 'latx_tr32_mtime, latx_tr32_sha256, latx_tr32_ver, ' ||
 'latx_proc_paths, latx_proc_count, latx_aot_dir_entries, latx_aot_dir_latest_mtime');

-- wine 运行环境(采集自 env_wide.wine_* 列)
INSERT OR IGNORE INTO group_dict VALUES
('env_wine', 'Wine 运行环境', 'wine/kylin-wine 环境变量与版本; 非测试组, 是环境采集维度',
 'wine_WINE, wine_WINEPREFIX, wine_WINEARCH, wine_wine_ver, wine_prefix_exists');

-- 三族表(每组一套): bench_<grp> 性能 / verify_<grp> 功能 / debug_<grp> 详细
-- (表名里的 <grp> 是占位; 实际每组一张, 如 bench_scalar / verify_scalar / debug_scalar)
INSERT OR IGNORE INTO group_dict VALUES
('bench_<grp>', '性能表(每组一张)', '只放具体指标 + 状态; 结果签名/明细/语义对拍全部移出(对不对由 verify_<grp> 承担)',
 'run_id, abi, grp, cname, rep_n + 动态度量列(<词根>_ns / <词根>_ops_s / <词根>_mb_s 及其 _status)'),
('verify_<grp>', '功能表(每组一张)', '一次功能测试一行, 列 = 该组每个功能名, 值 true/false; 空(NULL) = 本轮没判(无金标组的功能测试后续补)',
 'run_id, abi, grp, cname + 各功能名列(true/false)'),
('debug_<grp>', '详细表(每组一张, 仅 --debug)', '逐条明细: 标准组 = in/gold/got/diff_cols(每 case 每真值槽 kk); pmul = in/gold/got/status/inbits/minpop(每档)',
 'run_id, abi, grp, cname, kk + 明细列');
