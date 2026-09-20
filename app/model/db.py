"""isbench 数据层: 宽 schema 建表/自愈、按需建组表、run 入库与读取、表路由。

双源: schema.sql(固定表建表权威) 与 本文件 TABLES(旧库自愈 + ingest 白名单),
一致性由 schema_guard() 比对告警(只告警不改权威来源, 见其文档串)。
组清单等模型常量取自 model 包; 不 import isbench.py(避免循环)。
"""
import os
import re
import sqlite3
import sys

from model import AUX, GROUPS, fnum, eprint


def _ddl_bench(g):
    return [
        "CREATE TABLE IF NOT EXISTS bench_%s(\n"
        " run_id TEXT REFERENCES runs(key), abi TEXT, grp TEXT, cname TEXT,\n"
        " rep_n INT,\n"
        " PRIMARY KEY(run_id, abi, grp, cname)\n"
        ");" % g,
        "CREATE INDEX IF NOT EXISTS idx_bench_%s_key "
        "ON bench_%s(abi, grp, cname);" % (g, g),
    ]


def _ddl_verify(g):
    return [
        "CREATE TABLE IF NOT EXISTS verify_%s(\n"
        " run_id TEXT REFERENCES runs(key), abi TEXT, grp TEXT, cname TEXT,\n"
        " PRIMARY KEY(run_id, abi, grp, cname)\n"
        ");" % g,
        "CREATE INDEX IF NOT EXISTS idx_verify_%s_key "
        "ON verify_%s(abi, grp, cname);" % (g, g),
    ]


def _ddl_debug(g):
    return [
        "CREATE TABLE IF NOT EXISTS debug_%s(\n"
        " run_id TEXT REFERENCES runs(key), abi TEXT, grp TEXT, cname TEXT, "
        "kk TEXT,\n"
        " PRIMARY KEY(run_id, abi, grp, cname, kk)\n"
        ");" % g,
        "CREATE INDEX IF NOT EXISTS idx_debug_%s_key "
        "ON debug_%s(abi, grp, cname);" % (g, g),
    ]


# 组表按段按需创建(见 ensure_group_table), 不预建: 某组首次输出对应段
# (性能 data / 功能 func / 详细 dbg)时才建对应表。主键统一 (run_id,abi,grp,cname)。
_DDL_BY_KIND = {"bench": _ddl_bench, "verify": _ddl_verify, "debug": _ddl_debug}


def ensure_group_table(conn, tn):
    """按需建组表(段级): tn ∈ {bench,verify,debug}_<grp>, 已存在则 no-op。
    connect()/load_schema() 不再预建任何组表 —— 只有该组真正输出对应段时才建。
    用 execute(非 executescript) 以保持调用方事务的原子性。"""
    kind, _, grp = tn.partition("_")
    mk = _DDL_BY_KIND.get(kind)
    if mk and grp:
        for stmt in mk(grp):
            conn.execute(stmt)

def load_schema():
    """读 schema.sql。只含固定表(runs/env_wide/field_dict/openssl);
    组表 bench_/verify_/debug_<grp> 不预建, 由 ensure_group_table() 按段按需创建。"""
    with open(SCHEMA_FILE, "r") as f:
        return f.read()

# ---------------- 数据库(宽 schema) ----------------

ENV_COLS = [
    "machine_arch", "machine_hname", "machine_cpu", "machine_ip",
    "os_distro", "os_kernel", "os_libc",
    "cpu_logical_cores", "cpu_freq_cur_mhz", "cpu_governor", "cpu_max_freq_mhz",
    "sys_mem_total_gb", "sys_mem_avail_gb", "sys_load1", "sys_load5",
    "sys_load15", "sys_date_iso",
    "latx_LATX64", "latx_LATX32", "latx_LATX_OPTS", "latx_LATX_AOT",
    "latx_LATX_VPAES", "latx_LATX_SOFFPU", "latx_LATX_DEBUG_AOT",
    "latx_other",
    "latx_tr64_effective", "latx_tr64_size", "latx_tr64_mtime",
    "latx_tr64_sha256", "latx_tr64_ver",
    "latx_tr32_effective", "latx_tr32_size", "latx_tr32_mtime",
    "latx_tr32_sha256", "latx_tr32_ver",
    "latx_proc_paths", "latx_proc_count", "latx_aot_dir_entries",
    "latx_aot_dir_latest_mtime",
    "wine_WINE", "wine_WINEPREFIX", "wine_WINEARCH", "wine_wine_ver",
    "wine_prefix_exists",
    "run_reps", "run_tput_ms", "run_only", "run_verify",
    "run_sha256sums_mtime", "probe_notes",
]

# 附属文件(sql/、field_dict.json)统一在 <运行根>/app/(AUX 由 model 包给出)。
SCHEMA_FILE = os.path.join(AUX, "sql", "schema.sql")
GROUP_DICT_FILE = os.path.join(AUX, "sql", "group_dict.sql")
# 表列类型声明(与 schema.sql 同源; runs/env_wide 固定, 版本自愈按此补列)。
# bench 仅主键/分组键固定: 度量列由 ingest 按探针表头列名动态补建(见 ingest),
# 探针将来新增数据列无需在本文件登记。
# 供 connect() 版本自愈: 旧库缺列时 ALTER TABLE ADD COLUMN 补齐。
RUNS_T = {"key": "TEXT", "mode": "TEXT", "arch": "TEXT",
          "abi": "TEXT", "reps": "INT", "tput_ms": "INT",
          "started_at": "TEXT", "done_note": "TEXT", "py_ver": "TEXT",
          "imported_at": "TEXT", "push_src": "TEXT",
          "warm_discards": "INT", "check_note": "TEXT",
          "hname": "TEXT", "cpu_model": "TEXT", "ip": "TEXT"}
ENV_T = dict((c, "TEXT") for c in ENV_COLS)
BENCH_T = {"abi": "TEXT", "grp": "TEXT", "cname": "TEXT", "rep_n": "INT"}


def _bench_t(g):
    """bench_<grp> 固定列声明(connect 自愈补列用): 键列全组统一。"""
    return {"abi": "TEXT", "grp": "TEXT", "cname": "TEXT", "rep_n": "INT"}


FIELD_DICT_T = {"field_meaning": "TEXT", "field_data": "TEXT"}
# openssl 固定列(度量列无界, 不在此登记; 本表只给补列/哨兵用)
OPENSSL_T = {"run_id": "TEXT", "abi": "TEXT", "os": "TEXT", "bits": "INT",
          "tput_ms": "INT", "openssl_ver": "TEXT"}
# 三族表(每组一套, 主键统一 (run_id,abi,grp,cname)): 度量/功能/明细列全部由探针
# field 行现读现建, 逐表独立(不跳表统一)。debug_<grp> 明细行第二键 = kk。
BENCH_TABLES = tuple("bench_%s" % g for g in GROUPS)
VERIFY_TABLES = tuple("verify_%s" % g for g in GROUPS)
DEBUG_TABLES = tuple("debug_%s" % g for g in GROUPS)
TABLES = {"runs": RUNS_T, "env_wide": ENV_T,
          "field_dict": FIELD_DICT_T, "openssl": OPENSSL_T}
for _g in GROUPS:
    TABLES["bench_%s" % _g] = _bench_t(_g)
    TABLES["verify_%s" % _g] = {"abi": "TEXT", "grp": "TEXT", "cname": "TEXT"}
    TABLES["debug_%s" % _g] = {"abi": "TEXT", "grp": "TEXT", "cname": "TEXT",
                               "kk": "TEXT"}
# 护栏: schema.sql(建表权威) 与 TABLES(库自愈/ingest 白名单) 的列必须一致。下表
# 声明 schema.sql 中多出的主键列(比对时豁免)。只改一边 = 静默漂移, 见 schema_guard()。
SCHEMA_EXTRA_KEY = {"runs": set(), "env_wide": {"run_id"},
                    "field_dict": {"field_ref"}, "openssl": set()}


def schema_guard():
    """启动护栏: 比对 schema.sql 的实际列 与 TABLES 声明, 漂移则醒目告警。
    只告警不改权威来源(schema.sql 仍是建表唯一真源): 防"只改一边"造成
    ingest 白名单漏列或新库建表漏列这类静默故障。"""
    m = sqlite3.connect(":memory:")
    try:
        m.executescript(load_schema())
        for tn, extra in SCHEMA_EXTRA_KEY.items():
            have = {d[1] for d in m.execute("PRAGMA table_info(%s)" % tn)}
            want = set(TABLES[tn]) | extra
            miss_py = sorted(have - want)     # schema 有, py 无 -> 白名单/自愈会漏
            miss_sql = sorted(want - have)    # py 有, schema 无 -> 新库建表会漏
            if miss_py:
                eprint("!! schema 护栏: schema.sql 表 %s 有列 %s 未登记进 TABLES"
                       "(库自愈/ingest 白名单会漏)" % (tn, miss_py))
            if miss_sql:
                eprint("!! schema 护栏: TABLES 表 %s 有列 %s 未写进 schema.sql"
                       "(新库建表会漏)" % (tn, miss_sql))
    finally:
        m.close()

def bench_fix(grp):
    """bench_<grp> 固定列 = run_id + abi + grp + cname + rep_n(全组统一)。"""
    return ["run_id", "abi", "grp", "cname", "rep_n"]


# 结构列: 永远不是度量槽 —— rec 是行标签惯例列; cname 是身份列名(parse_seg 会带
# 一个 cname 键, 必须挡掉, 否则凭空多一列); extra/src 是传输/来源标记。
BENCH_STRUCT = ("rec", "cname", "extra", "src")


# 探针行记录类型: meta|field|label|data(性能)|func(功能)|dbg(详细)|group
RECORD_TYPES = {"meta", "field", "label", "data", "group", "func", "dbg"}
VERIFY_FIX = {"run_id", "abi", "grp", "cname"}
DEBUG_FIX = {"run_id", "abi", "grp", "cname", "kk"}

# openssl 表固定列(度量列 = 探针表头列名, 动态 ALTER; 列名 = 算法_尺寸)
OPENSSL_FIX = {"run_id", "abi", "os", "bits", "tput_ms", "openssl_ver"}


def bench_table(grp):
    """grp -> bench_<grp> 表名(一场 run 可带多组, 路由必须逐行)。"""
    tn = "bench_%s" % grp
    return tn if tn in BENCH_TABLES else "bench_%s" % GROUPS[0]


def table_cols(conn, tbl):
    """表物理列序(与 PRAGMA table_info 同序)。"""
    return [r[1] for r in conn.execute("PRAGMA table_info(%s)" % tbl)]


def verify_table(grp):
    """grp -> verify_<grp> 表名(功能表)。"""
    tn = "verify_%s" % grp
    return tn if tn in VERIFY_TABLES else "verify_%s" % GROUPS[0]


def debug_table(grp):
    """grp -> debug_<grp> 表名(详细表, 仅 --debug 时写)。"""
    tn = "debug_%s" % grp
    return tn if tn in DEBUG_TABLES else "debug_%s" % GROUPS[0]


def existing_tables(conn, names):
    """筛选出库里真实存在的表名(新库/未跑过的组可能尚未建表)。"""
    have = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    return [t for t in names if t in have]

def connect(db):
    """打开(必要时创建/自愈)宽 schema 库。
    版本自愈规则(升级版 isbench.py 直接跑旧库, 无需删库/指定):
      - 全新文件: 直接建宽表;
      - 已有宽表库(有固定表 env_wide/runs): 对 TABLES 中已存在的表 PRAGMA
        查现有列, 逐个 ALTER TABLE ADD COLUMN 补缺列(新版本加的字段自动
        补上, 列全为可空类型, 追加安全, 旧数据保留); 组表 bench_/verify_/
        debug_<grp> 按需创建 —— 未跑过的组没有该表, 宽表库刚建出、尚未跑过
        任何 run 时也没有, 跳过即可, **不据此判版本**;
      - 旧结构库(连 env_wide 都没有: 窄表时代): 整文件改名 *.old 备份后重建,
        旧数据原样留档(用户已弃用窄模型, 不迁移)。
    """
    os.makedirs(os.path.dirname(os.path.abspath(db)), exist_ok=True)
    fresh = not os.path.exists(db) or os.path.getsize(db) == 0
    c = sqlite3.connect(db, timeout=30)
    if not fresh:
        tabs = {r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        # 迁移: 旧 verify_x87 是明细表(in/gold/got); 新语义下 verify_<grp> = 功能表,
        # 明细改归 debug_<grp> —— 旧 verify_x87 直接改名 debug_x87(历史明细留档)。
        if "verify_x87" in tabs:
            vc = {d[1] for d in c.execute("PRAGMA table_info(verify_x87)")}
            if "gold_v0" in vc:
                c.execute("DROP TABLE IF EXISTS debug_x87")
                c.execute("ALTER TABLE verify_x87 RENAME TO debug_x87")
                eprint("== 迁移: 旧 verify_x87(明细) 改名 debug_x87; "
                       "新 verify_x87 = x87 功能表")
                c.commit()
                tabs = {r[0] for r in c.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")}
        # 迁移: 探针全链改名 ossl -> openssl(表 + 列 + runs.mode 取值), 旧库自动跟进。
        if "ossl" in tabs and "openssl" not in tabs:
            c.execute("ALTER TABLE ossl RENAME TO openssl")
            eprint("== 迁移: 旧表 ossl 改名 openssl")
            c.commit()
            tabs = {r[0] for r in c.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        if "openssl" in tabs:
            oc = {d[1] for d in c.execute("PRAGMA table_info(openssl)")}
            if "ossl_ver" in oc and "openssl_ver" not in oc:
                try:
                    c.execute("ALTER TABLE openssl "
                              "RENAME COLUMN ossl_ver TO openssl_ver")
                    eprint("== 迁移: 列 ossl_ver 改名 openssl_ver")
                except sqlite3.OperationalError:
                    eprint("!! 本库 sqlite 不支持 RENAME COLUMN(需>=3.25); "
                           "请手动把 openssl 表列 ossl_ver 改名为 openssl_ver")
        if "runs" in tabs:
            nmode = c.execute(
                "UPDATE runs SET mode = replace(mode,'ossl','openssl') "
                "WHERE mode LIKE 'ossl%'").rowcount
            if nmode:
                eprint("== 迁移: %d 个 runs.mode 取值 ossl* -> openssl*" % nmode)
            c.commit()
        # 版本判据锚在"必定存在的固定表"(宽表库的标志 = env_wide+runs),
        # 而不是"某类子表是否存在": 组表 bench_/verify_/debug_<grp> 按需创建,
        # 空库(刚建、未跑 run)同样没有 bench_ 表, 用 bench_ 判会把空库误判成旧结构库。
        if {"runs", "env_wide"} <= tabs:
            for tn, tdef in TABLES.items():
                if tn not in tabs:
                    # 组表按需创建(ensure_group_table), 未跑过的组本就无表; 拿不存在的表去 ALTER 会直接报错 -> 跳过
                    continue
                have = {d[1] for d in c.execute(
                    "PRAGMA table_info(%s)" % tn)}
                for col, typ in tdef.items():
                    if col not in have:
                        c.execute("ALTER TABLE %s ADD COLUMN %s %s"
                                  % (tn, col, typ))
                        eprint("== 库自愈: %s 补列 %s %s" % (tn, col, typ))
            c.commit()
        else:
            c.close()
            bak = db + ".old"
            n = 1
            while os.path.exists(bak):
                bak = "%s.old%d" % (db, n)
                n += 1
            try:
                os.rename(db, bak)
            except OSError:
                eprint("旧结构库 %s 无法改名(被占用?): 请手动移走该文件后重试"
                       % db)
                sys.exit(2)
            eprint("== 检测到旧结构库, 已备份为 %s, 重建空宽库" % bak)
            c = sqlite3.connect(db, timeout=30)
    c.executescript(load_schema())
    if os.path.exists(GROUP_DICT_FILE):
        c.executescript(open(GROUP_DICT_FILE, "r").read())
    c.commit()
    return c


def ingest(conn, runf, env_vals, benches, table=None):
    """写入一次运行(runs + env_wide 1 行 + 计时行, 一事务)。幂等 by key。
    env_vals: {列名: 值}。benches: [{abi,grp,身份列,方式槽...,extra:{新列}}]。
    列自增: 行中带探针新列(extra)而该组表无此列时, 只 ALTER 该组自己的表 ——
    分表后各组字段独立, 不再跨表统一(否则 pmul 的 <档>_* 列会灌进别的组)。
    路由: table=None 逐行按 bench_table(grp) 分(每组独立 bench_<grp> 表);
      必须逐行而不能一次判: 一场 run 可以带多组(混合)。显式给表名则全入该表。
    返回 ok/dup。"""
    key = runf["key"]
    if conn.execute("SELECT 1 FROM runs WHERE key=?", (key,)).fetchone():
        return "dup"
    cols = [c for c in ENV_COLS if c in env_vals]
    with conn:
        conn.execute(
            "INSERT INTO runs(key,mode,arch,abi,reps,tput_ms,started_at,"
            "done_note,py_ver,imported_at,push_src,warm_discards,check_note,"
            "hname,cpu_model,ip) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (key, runf.get("mode"), runf.get("arch"), runf.get("abi"),
             runf.get("reps"), runf.get("tput_ms"), runf.get("started_at"),
             runf.get("done_note"), runf.get("py_ver"),
             runf.get("imported_at"), runf.get("push_src"),
             runf.get("warm_discards"), runf.get("check_note"),
             runf.get("hname"), runf.get("cpu_model"), runf.get("ip")))
        conn.execute("INSERT INTO env_wide(run_id, %s) VALUES(?,%s)"
                     % (", ".join(cols), ",".join("?" * len(cols))),
                     [key] + [env_vals[c] for c in cols])
        # 列自增(探针列名驱动, **逐表独立**): 新列只补到本行所属的 bench_<grp>,
        # 数值列 REAL、其余 TEXT —— 新列无需在本脚本登记
        per_tbl = {}                   # tn -> {"fixset":set, "cols":{col:[vals]}}
        for b in benches:
            if table:
                tn, grp = table, table[len("bench_"):]
            else:
                grp = b.get("grp") or ""
                tn = bench_table(grp)
            fixset = set(bench_fix(grp))
            e = per_tbl.setdefault(tn, {"fixset": fixset, "cols": {}})
            src = dict(b)
            src.update(b.get("extra") or {})   # push 传输兼容形态
            for c2, v2 in src.items():
                # rec/cname/extra/src = 结构列(非度量槽), 不入库
                if (c2 in fixset or c2 in BENCH_STRUCT or v2 is None
                        or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,30}",
                                            c2)):
                    continue
                e["cols"].setdefault(c2, []).append(v2)
        for tn, e in per_tbl.items():
            ensure_group_table(conn, tn)   # 段级按需建表: data 段 -> bench_<grp>
            have = set(table_cols(conn, tn))
            need = {c2: ("REAL" if all(fnum(v) is not None for v in vs)
                         else "TEXT")
                    for c2, vs in e["cols"].items() if c2 not in have}
            for c2 in sorted(need):
                conn.execute("ALTER TABLE %s ADD COLUMN %s %s"
                             % (tn, c2, need[c2]))
            if need:
                eprint("== 列自增: %s 新增 %s" % (tn, ",".join(sorted(need))))
        for b in benches:
            if table:
                tn, grp = table, table[len("bench_"):]
            else:
                grp = b.get("grp") or ""
                tn = bench_table(grp)
            fixset = set(bench_fix(grp))
            extra = dict()
            # 自增列来源两种形态: agg 收在 b["extra"], push/SELECT * 传输在顶层
            for c2, v2 in sorted((b.get("extra") or {}).items()):
                if (re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,30}", c2)
                        and c2 not in fixset and c2 not in BENCH_STRUCT
                        and v2 is not None):
                    extra[c2] = v2
            for c2 in sorted(b):
                if (c2 not in fixset and c2 not in BENCH_STRUCT
                        and b.get(c2) is not None):
                    extra[c2] = b[c2]
            ins = bench_fix(grp) + sorted(extra)
            vals = [key]
            for c in ins[1:]:
                v = b.get(c)
                if v is None:
                    v = (b.get("extra") or {}).get(c)
                vals.append(v)
            conn.execute("INSERT INTO %s(%s) VALUES(%s)"
                         % (tn, ", ".join(ins), ",".join("?" * len(ins))),
                         vals)
    return "ok"


def ingest_openssl_metrics(conn, row):
    """写 openssl 一行(幂等 OR REPLACE by run_id)。row = 全键 dict(含固定列
    run_id/abi/os/bits/tput_ms/openssl_ver + 度量列)。度量列缺库列时按值类型动态
    ALTER(数值 REAL, 其余 TEXT), 全 NULL 列不建。返回 ok。"""
    key = row.get("run_id")
    if not key:
        return "no-key"
    have = {d[1] for d in conn.execute("PRAGMA table_info(openssl)")}
    dyn = {}
    for c, v in row.items():
        if c in OPENSSL_FIX or v is None:
            continue
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,30}", c):
            continue
        dyn[c] = v
    with conn:
        for c in sorted(dyn):
            if c not in have:
                col_t = "REAL" if fnum(dyn[c]) is not None else "TEXT"
                conn.execute("ALTER TABLE openssl ADD COLUMN %s %s" % (c, col_t))
                have.add(c)
                eprint("== 列自增: openssl 新增探针列 %s(%s)" % (c, col_t))
        ins = [c for c in ("run_id", "abi", "os", "bits", "tput_ms",
                           "openssl_ver") if c in row] + sorted(dyn)
        conn.execute("INSERT OR REPLACE INTO openssl(%s) VALUES(%s)"
                     % (", ".join(ins), ",".join("?" * len(ins))),
                     [row[c] for c in ins])
    return "ok"


def fetch_run(conn, key):
    r = conn.execute("SELECT * FROM runs WHERE key=?", (key,)).fetchone()
    if not r:
        return None
    cols = [d[0] for d in conn.execute("SELECT * FROM runs").description]
    return dict(zip(cols, r))


def resolve_key(conn, ref):
    """精确 key -> LIKE 前缀 -> LIKE 包含; 唯一才返回。"""
    if conn.execute("SELECT 1 FROM runs WHERE key=?", (ref,)).fetchone():
        return ref
    for pat in (ref + "%", "%" + ref + "%"):
        rows = conn.execute("SELECT key FROM runs WHERE key LIKE ? "
                            "ORDER BY started_at DESC", (pat,)).fetchall()
        if len(rows) == 1:
            return rows[0][0]
        if len(rows) > 1:
            eprint("run 标识 '%s' 匹配多个: %s"
                   % (ref, ", ".join(r[0] for r in rows[:5])))
            return None
    eprint("未找到 run: %s" % ref)
    return None


def bench_count_expr(conn):
    """runs 行数统计: 逐 bench_<grp> 表求和(不再有 bench_all 视图)。"""
    tabs = existing_tables(conn, BENCH_TABLES)
    if not tabs:
        return "0"
    return "+".join("(SELECT count(*) FROM %s WHERE run_id=runs.key)" % t
                    for t in tabs)


def list_runs(conn, mode=None, host=None):
    # 行数逐 bench_<grp> 表求和
    q = ("SELECT key,mode,arch,abi,reps,started_at,"
         "(%s),done_note,"
         "check_note,hname,cpu_model,ip FROM runs" % bench_count_expr(conn))
    w, a = [], []
    if mode:
        w.append("mode=?"); a.append(mode)
    if host:
        w.append("(hname LIKE ? OR cpu_model LIKE ?)"); a += ["%" + host + "%"] * 2
    if w:
        q += " WHERE " + " AND ".join(w)
    q += " ORDER BY started_at DESC"
    return conn.execute(q, a).fetchall()

def colname(s):
    """功能名/明细列名 -> 合法库列名: 非标识符字符换 '_', 首字符非字母加前缀。
    不合法(空/超长/重名风险由调用方容忍)返回 None -> 该列丢弃。"""
    c = re.sub(r"[^A-Za-z0-9_]", "_", str(s))
    if not c or not c[0].isalpha():
        c = "f_" + c
    c = c[:31]
    return c if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,30}", c) else None


def ingest_func(conn, run_id, funcs):
    """写 verify_<grp> 功能表: 一次测试一行, 列 = 该组每个功能名, 值 true/false。
    功能名(探针 func 段列名)现读现建; 值 None('-'/空) 写 NULL = 本轮没判(留空)。
    幂等: 同 (grp,abi,cname) 重复写取最后一次。返回写入行数。"""
    if not funcs:
        return 0
    n = 0
    with conn:
        for grp, abi, cname, feats in funcs:
            # 宽表组的 func 行是"一行 = 一组"(没有 cname 身份): 用占位 '-' 填主键
            cname = cname or "-"
            tn = verify_table(grp)
            keep = {}
            for fn in feats:
                if fn in VERIFY_FIX:
                    continue
                cn = colname(fn)
                if cn:
                    keep[cn] = feats[fn]
            ensure_group_table(conn, tn)   # 段级按需建表: func 段 -> verify_<grp>
            have = set(table_cols(conn, tn))
            for c in sorted(c for c in keep if c not in have):
                conn.execute('ALTER TABLE %s ADD COLUMN "%s" TEXT' % (tn, c))
            cols = ["run_id", "abi", "grp", "cname"] + sorted(keep)
            conn.execute(
                "INSERT OR REPLACE INTO %s(%s) VALUES(%s)"
                % (tn, ", ".join('"%s"' % c for c in cols),
                   ",".join("?" * len(cols))),
                [run_id, abi, grp, cname] + [keep[c] for c in sorted(keep)])
            n += 1
    return n


def ingest_debug(conn, run_id, rows):
    """写 debug_<grp> 详细表(仅 --debug 时调): 逐 (grp,abi,cname,kk) 一行,
    列现读现建。幂等: 同键重复写取最后一次。返回写入行数。"""
    if not rows:
        return 0
    n = 0
    with conn:
        for r in rows:
            grp, cname = r.get("grp"), r.get("cname")
            if not grp or not cname:
                continue
            kk = r.get("kk") if r.get("kk") is not None else "-"
            tn = debug_table(grp)
            keep = {}
            for c, v in r.items():
                if c in DEBUG_FIX or c == "grp":
                    continue
                cn = colname(c)
                if cn:
                    keep[cn] = v
            ensure_group_table(conn, tn)   # 段级按需建表: dbg 段 -> debug_<grp>
            have = set(table_cols(conn, tn))
            for c in sorted(c for c in keep if c not in have):
                conn.execute('ALTER TABLE %s ADD COLUMN "%s" TEXT' % (tn, c))
            cols = ["run_id", "abi", "grp", "cname", "kk"] + sorted(keep)
            conn.execute(
                "INSERT OR REPLACE INTO %s(%s) VALUES(%s)"
                % (tn, ", ".join('"%s"' % c for c in cols),
                   ",".join("?" * len(cols))),
                [run_id, r.get("abi"), grp, cname, kk]
                + [keep[c] for c in sorted(keep)])
            n += 1
    return n


def debug_summary(conn, run_id, grp="x87"):
    """详细表自证一行: 行数 / 不同 cname 数 / FAIL 数与首个差异行。
    debug_<grp> 列不固定, 只认通用状态列(标准组 st / pmul status)。"""
    tn = debug_table(grp)
    if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                        "AND name=?", (tn,)).fetchone():
        return dict(rows=0, cases=0, fails=0, first=None)
    cols = set(table_cols(conn, tn))
    stc = "st" if "st" in cols else ("status" if "status" in cols else None)
    tot, nst = conn.execute(
        "SELECT COUNT(*), COUNT(DISTINCT cname) FROM %s WHERE run_id=?" % tn,
        (run_id,)).fetchone()
    nf, first = 0, None
    if stc:
        nf = conn.execute(
            "SELECT COUNT(*) FROM %s WHERE run_id=? AND \"%s\" IN "
            "('FAIL','KATFAIL')" % (tn, stc), (run_id,)).fetchone()[0]
        first = conn.execute(
            "SELECT cname,kk,\"%s\" FROM %s WHERE run_id=? AND \"%s\" IN "
            "('FAIL','KATFAIL') ORDER BY cname,kk LIMIT 1" % (stc, tn, stc),
            (run_id,)).fetchone()
    return dict(rows=tot or 0, cases=nst or 0, fails=nf, first=first)

def load_run_bench(conn, key):
    """读 run 全部计时行: 逐 bench_<grp> 表读(各组列独立, 不齐平)。"""
    out = []
    for tn in existing_tables(conn, BENCH_TABLES):
        cur = conn.execute("SELECT * FROM %s WHERE run_id=?" % tn, (key,))
        cols = [d[0] for d in cur.description]
        for r in cur.fetchall():
            d = dict(zip(cols, r))
            d.setdefault("src", tn)
            out.append(d)
    return out


def load_tbl_rows(conn, tables, key):
    """逐表读某 run 的全部行, 行内补 grp=表名去掉前缀(verify_pmul -> pmul)。"""
    out = []
    for tn in existing_tables(conn, tables):
        cur = conn.execute("SELECT * FROM %s WHERE run_id=?" % tn, (key,))
        cs = [d[0] for d in cur.description]
        for r in cur.fetchall():
            d = dict(zip(cs, r))
            d.setdefault("grp", tn.split("_", 1)[1])
            out.append(d)
    return out

def _last_key(conn):
    r = conn.execute("SELECT key FROM runs ORDER BY started_at DESC LIMIT 1") \
        .fetchone()
    if not r:
        eprint("库为空, 无 run 可推")
        sys.exit(2)
    return r[0]
