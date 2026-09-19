-- schema.sql -- isbench 宽表 DDL(单文件权威来源, isbench.py 读取并 executescript)
-- 修改表结构只改本文件, 不改 isbench.py。

CREATE TABLE IF NOT EXISTS runs(
 key TEXT PRIMARY KEY, mode TEXT, arch TEXT, abi TEXT, reps INT,
 tput_ms INT, started_at TEXT, done_note TEXT, py_ver TEXT,
 imported_at TEXT, push_src TEXT, warm_discards INT, check_note TEXT,
 hname TEXT, cpu_model TEXT, ip TEXT);
CREATE INDEX IF NOT EXISTS idx_runs_mach ON runs(mode, hname);

CREATE TABLE IF NOT EXISTS env_wide(
 run_id TEXT PRIMARY KEY REFERENCES runs(key),
 machine_arch TEXT,
 machine_hname TEXT,
 machine_cpu TEXT,
 machine_ip TEXT,
 os_distro TEXT,
 os_kernel TEXT,
 os_libc TEXT,
 cpu_logical_cores TEXT,
 cpu_freq_cur_mhz TEXT,
 cpu_governor TEXT,
 cpu_max_freq_mhz TEXT,
 sys_mem_total_gb TEXT,
 sys_mem_avail_gb TEXT,
 sys_load1 TEXT,
 sys_load5 TEXT,
 sys_load15 TEXT,
 sys_date_iso TEXT,
 latx_LATX64 TEXT,
 latx_LATX32 TEXT,
 latx_LATX_OPTS TEXT,
 latx_LATX_AOT TEXT,
 latx_LATX_VPAES TEXT,
 latx_LATX_SOFFPU TEXT,
 latx_LATX_DEBUG_AOT TEXT,
 latx_other TEXT,
 latx_tr64_effective TEXT,
 latx_tr64_size TEXT,
 latx_tr64_mtime TEXT,
 latx_tr64_sha256 TEXT,
 latx_tr64_ver TEXT,
 latx_tr32_effective TEXT,
 latx_tr32_size TEXT,
 latx_tr32_mtime TEXT,
 latx_tr32_sha256 TEXT,
 latx_tr32_ver TEXT,
 latx_proc_paths TEXT,
 latx_proc_count TEXT,
 latx_aot_dir_entries TEXT,
 latx_aot_dir_latest_mtime TEXT,
 wine_WINE TEXT,
 wine_WINEPREFIX TEXT,
 wine_WINEARCH TEXT,
 wine_wine_ver TEXT,
 wine_prefix_exists TEXT,
 run_reps TEXT,
 run_tput_ms TEXT,
 run_only TEXT,
 run_verify TEXT,
 run_sha256sums_mtime TEXT,
 probe_notes TEXT);

-- bench_<grp>: 每组独立计时表(不在此列出, 也不预建)。
-- 度量列(探针输出槽)不定列: 首次入库按探针表头列名动态 ALTER 补列(见 ingest)。

-- 每组一套三族表(均按需创建, 不在此列出; 由 isbench.py ensure_group_table() 在某组
-- 首次输出对应段时才建: data->bench / func->verify / dbg->debug):
--   bench_<grp>  性能: 只放指标+状态(键 run_id,abi,grp,cname);
--   verify_<grp> 功能: 列 = 该组每个功能名, 值 true/false(NULL = 本轮没判);
--   debug_<grp>  详细: in/gold/got 等明细, 仅 run --debug 时采(第二键 kk)。
-- 注: 旧版的 verify_x87(明细表)已迁移为 debug_x87 —— 旧库 connect() 自动改名。

-- field_dict: 字段翻译表(三列, 统一 field_ 前缀)。
CREATE TABLE IF NOT EXISTS field_dict(
 field_ref      TEXT PRIMARY KEY,
 field_meaning  TEXT,
 field_data     TEXT);

-- ossl: 独立 openssl 测速探针, 度量列名 = <EVP算法>_<块尺寸>, 动态 ALTER。
CREATE TABLE IF NOT EXISTS ossl(
 run_id TEXT PRIMARY KEY REFERENCES runs(key),
 abi TEXT, os TEXT, bits INT, tput_ms INT, ossl_ver TEXT);
