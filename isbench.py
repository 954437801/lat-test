#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""isbench.py -- 企业微信 libcef 指令形态跨环境基准(py3 单入口, sqlite3 宽表入库)

宽表模型: 测试对象是指令(case)。单指令链(lat)/定时长(tput)/语义(sem)/
kat/diag 都是同一指令的测试方式, 在探针输出、库、导出三处都表现为
「一 (架构, 指令) 一行, 方式做列」; reps 多轮聚合为一行(数值取中位)。

子命令: run(native/latx/wine) / compare / ls / show / env-diff / export /
serve / push。探针 stdout 直接解析入库, 不生成 txt; 数据库为唯一产物
(默认 results/isbench.db, 单文件可拷可备份), 支持多台机器数据同库。

依赖: python3 >= 3.6, 仅标准库。README.txt 见详细说明。
"""
import argparse
import csv
import datetime
import io
import json
import os
import platform
import re
import shlex
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

DIR = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(DIR, "bin")
RES = os.path.join(DIR, "results")
DEF_DB = os.path.join(RES, "isbench.db")
# 组清单 = 产物名 = grp 列值(一可执行恰好一个含 ib.h 的 TU)。拆分维度 = LATX
# 成本结构 + 风险隔离(栈类/串类/原子类各自成组, 一崩不拖全族), 详见 README。
GROUPS = ["scalar", "sse", "avx", "crypto", "cpuid", "timer",
          "mov", "alu", "logic", "flag", "shift", "cc", "ctrl", "bits",
          "special", "vec", "x87", "pmul", "cfloat", "cint"]
# 组的 ABI 在册范围(与 build.sh 的 GRP_32ONLY / GRP_FORMS 同集): 缺省两 ABI 都在, 未列就按全集。
# x87 是唯一例外 —— 只有 -m32 的编译器会发射 x87 整型搬运, 给 x64 造 x87
# 探针是测一条不存在的路径; 而实测(见 src/isb_x87.c 取证 6)它编得出、跑得通、还
# 与 i386 逐字一致 => 运行期根本看不出不妥, 只能在登记层就限死。
# cfloat/cint 是三形态组: x64/i386 为 x86-under-LATX 对照, loongarch64 为原生基线。
GRP_ABIS = {"x87": ("i386",), "cfloat": ("x64", "i386", "loongarch64"),
            "cint": ("x64", "i386", "loongarch64")}
ALL_ABIS = ("x64", "i386")
# 身份列全组统一 cname: pmul 的用例身份 = "<实现>/<档族>"(如 hw/bit), 由探针打成一个
# cname 单元 —— 不再为 pmul 单开 (impl,family) 二维键。三族表主键都是
# (run_id, abi, grp, cname): bench_<grp> 性能 / verify_<grp> 功能 / debug_<grp> 详细。
def grp_ident(grp):
    """用例身份列(决定三族表主键与多 rep 聚合键): 全组统一 cname。"""
    return ("cname",)
LATX_FIXED = ["LATX64", "LATX32", "LATX_OPTS", "LATX_AOT", "LATX_VPAES",
              "LATX_SOFFPU", "LATX_DEBUG_AOT"]
# 预热哨兵: 每组选一条 lat/tput 均可跑的形态(名字必须原字命中表行)。
# pmul 的 --only 按"档名"前缀命中(它不是 ib_case 型, 没有 cname), 故填档名。
# 无哨兵的组走 run_warm 的 else 分支(--no-tput --time 200), 对 pmul(480 个测量点)
# 就要 ~96s, 白烧一轮 —— 给一个单档哨兵把预热压到几秒。
WARM_SENT = {"scalar": "x86_add_r64", "sse": "sse_movups_ld",
             "avx": "avx_vaddps_xmm", "crypto": "aesenc", "cpuid": "cpuid",
             "mov": "x86_mov__r_r_l", "alu": "x86_add__r_r_l",
             "logic": "x86_and__r_r_l", "flag": "x86_cmp__r_r_l",
             "shift": "x86_shl__r_i_l", "cc": "x86_jne___",
             "ctrl": "x86_leave___", "bits": "x86_bt__r_i_l",
             "special": "x86_nop", "vec": "sse2_psrlw",
             "x87": "x87_fild_fistp_q_rt", "pmul": "p00", "cfloat": "f32_add", "cint": "i32_add"}
# 一致性自校验哨兵(只收两 ABI 都在册的组)。
CHECK_SENT = [("scalar", "x86_add_r64"), ("crypto", "aesenc"),
              ("mov", "x86_mov__r_r_l"), ("alu", "x86_add__r_r_l")]
CHECK_TOL = 0.10
# 亚 ns 的行不参与跨 run 自校验: ±10% 对 0.3ns(= 1 周期)的行没有意义。
# 实测(box31 i3-4150, 同机三次 native run): x64/x86_add_r64 = 0.300 /
# 0.450 / 0.310 ns -> 连着两轮报 MISMATCH(150%、69%), 而 i386 同一行(0.670/
# 0.670/0.680)与 aesenc(2.13/2.01/2.02)全稳定 -> 不是内核不确定, 是这一行
# 本身就处在计时粒度上, 拿它当哨兵只会天天误报。
CHECK_MIN_NS = 1.0
RAT_LO, RAT_HI = 85.0, 115.0

# 探针 CSV 表头: 已废(旧 kind/T/D 协议)。新协议由 parse_seg 按 field 行现读现建:
# 三段 = 性能(data, 16 列) / 功能(func, 一组一行) / 详细(dbg, 仅 --debug)。
WIDE_HDR = None


def eprint(*a):
    print(*a, file=sys.stderr)


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
    """读 schema.sql。只含固定表(runs/env_wide/field_dict/ossl);
    组表 bench_/verify_/debug_<grp> 不预建, 由 ensure_group_table() 按段按需创建。"""
    with open(SCHEMA_FILE, "r") as f:
        return f.read()


def fnum(s):
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


def abi_scope(grp):
    """grp 在哪些 ABI 在册(不在册的形态既不构建也不跑也不自校验)。"""
    return GRP_ABIS.get(grp, ALL_ABIS)


def _read(path):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


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

SCHEMA_FILE = os.path.join(DIR, "schema.sql")
GROUP_DICT_FILE = os.path.join(DIR, "group_dict.sql")
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
# ossl 固定列(度量列无界, 不在此登记; 本表只给补列/哨兵用)
OSSL_T = {"run_id": "TEXT", "abi": "TEXT", "os": "TEXT", "bits": "INT",
          "tput_ms": "INT", "ossl_ver": "TEXT"}
# 三族表(每组一套, 主键统一 (run_id,abi,grp,cname)): 度量/功能/明细列全部由探针
# field 行现读现建, 逐表独立(不跳表统一)。debug_<grp> 明细行第二键 = kk。
BENCH_TABLES = tuple("bench_%s" % g for g in GROUPS)
VERIFY_TABLES = tuple("verify_%s" % g for g in GROUPS)
DEBUG_TABLES = tuple("debug_%s" % g for g in GROUPS)
TABLES = {"runs": RUNS_T, "env_wide": ENV_T,
          "field_dict": FIELD_DICT_T, "ossl": OSSL_T}
for _g in GROUPS:
    TABLES["bench_%s" % _g] = _bench_t(_g)
    TABLES["verify_%s" % _g] = {"abi": "TEXT", "grp": "TEXT", "cname": "TEXT"}
    TABLES["debug_%s" % _g] = {"abi": "TEXT", "grp": "TEXT", "cname": "TEXT",
                               "kk": "TEXT"}


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

# ossl 表固定列(度量列 = 探针表头列名, 动态 ALTER; 列名 = 算法_尺寸)
OSSL_FIX = {"run_id", "abi", "os", "bits", "tput_ms", "ossl_ver"}


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
      - 已有库(env_wide/bench/runs 齐全): 对每张表 PRAGMA 查现有列,
        按 TABLES 声明逐个 ALTER TABLE ADD COLUMN 补缺列(新版本加的
        字段自动补上, 列全为可空类型, 追加安全, 旧数据保留);
      - 旧结构库(无 env_wide: 窄表时代): 整文件改名 *.old 备份后重建,
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
        if any(t.startswith("bench_") for t in tabs) and "runs" in tabs:
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


def ingest_ossl_metrics(conn, row):
    """写 ossl 一行(幂等 OR REPLACE by run_id)。row = 全键 dict(含固定列
    run_id/abi/os/bits/tput_ms/ossl_ver + 度量列)。度量列缺库列时按值类型动态
    ALTER(数值 REAL, 其余 TEXT), 全 NULL 列不建。返回 ok。"""
    key = row.get("run_id")
    if not key:
        return "no-key"
    have = {d[1] for d in conn.execute("PRAGMA table_info(ossl)")}
    dyn = {}
    for c, v in row.items():
        if c in OSSL_FIX or v is None:
            continue
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,30}", c):
            continue
        dyn[c] = v
    with conn:
        for c in sorted(dyn):
            if c not in have:
                col_t = "REAL" if fnum(dyn[c]) is not None else "TEXT"
                conn.execute("ALTER TABLE ossl ADD COLUMN %s %s" % (c, col_t))
                have.add(c)
                eprint("== 列自增: ossl 新增探针列 %s(%s)" % (c, col_t))
        ins = [c for c in ("run_id", "abi", "os", "bits", "tput_ms",
                           "ossl_ver") if c in row] + sorted(dyn)
        conn.execute("INSERT OR REPLACE INTO ossl(%s) VALUES(%s)"
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


# ---------------- 探针输出解析(单表宽 CSV, 列数动态: 以表头为准) ----------------

def parse_seg(out, grp_hint=None):
    """解析一次 exec 的探针输出 = 多段宽 CSV(新协议: rec=field 分段)。
    协议格式(每段):
      meta,cpu=...;host=...;...      -- 运行环境标识(k=v 对, 分号分隔)
      field,group,abi,os,...        -- 英文列名行(段的起点)
      label,测试组名,指令集架构,...   -- 中文列名行(与 field 严格同列序)
      data,...                      -- 性能数据行(每用例一行: 指标+状态)
      func,...                      -- 功能结果行(一组一行: 列 = 每个功能, 值 true/false)
      dbg,...                       -- 详细明细行(仅 --debug)
      group,scalar,ok,total         -- 组尾汇总行
    三段按 rec 标签分流: data->性能, func->功能, dbg->详细。列名从 field 行现读现建。
    grp_hint: 本段所属组(exec 是按组跑的); field 行自带 group 列时以它为准。
    返回 (rows, funcs, dbgs, done):
      rows  = 性能行(每行含 rec/abi/grp/cname + 各度量列槽);
      funcs = [(grp, abi, cname, {功能名: 值})];
      dbgs  = 详细原始行(含 grp/abi/cname + 明细列), 合并由 dbg_rows() 做;
      done  = 组尾组名(或 None)。"""
    rows, funcs, dbgs = [], [], []
    done = None
    field_cols = None   # 当前段的列名列表(rec 已含)
    for r in csv.reader(out.splitlines()):
        if not r or not r[0]:
            continue
        tag = r[0].strip()
        if tag == "meta":
            continue
        if tag == "field":           # 段的起点
            field_cols = ["rec"] + [c.strip() for c in r[1:]]
            continue
        if tag == "label":
            continue
        if field_cols is None:        # field 行还没出现: 丢弃
            continue
        idx = {name: i for i, name in enumerate(field_cols)}

        def f(col):
            i = idx.get(col)
            if i is None or i >= len(r):
                return None
            v = r[i].strip()
            return None if v == "-" or v == "" else v

        if tag == "data":
            cname = f("case") or ""
            if not cname:
                continue
            row = dict(rec="data", abi=f("abi"),
                       grp=f("group") or grp_hint or "", cname=cname)
            for cn in field_cols:
                if cn in ("rec", "group", "abi", "case"):
                    continue
                row[cn] = f(cn)
            rows.append(row)
            continue
        if tag == "func":             # 功能结果行: 列 = 每个功能名
            feats = {}
            for cn in field_cols:
                if cn in ("rec", "group", "abi", "case"):
                    continue
                feats[cn] = f(cn)
            funcs.append((f("group") or grp_hint or "", f("abi"),
                          f("case") or "", feats))
            continue
        if tag == "dbg":              # 详细明细行
            d = dict(grp=f("group") or grp_hint or "", abi=f("abi"),
                     cname=f("case") or "")
            for cn in field_cols:
                if cn in ("rec", "group", "abi", "case"):
                    continue
                d[cn] = f(cn)
            dbgs.append(d)
            continue
        if tag == "group":            # 组尾汇总行(只取组名)
            done = f("group") or grp_hint or ""
    return rows, funcs, dbgs, done


# 详细段(dbg) 的 in/out 字段 -> debug_<grp> 列名(in_/gold_/got_ 三组同名对齐)
K_TO_V = {"i0": "v0", "i1": "v1", "i2": "v2", "i3": "v3", "inf": "flag",
          "o0": "v0", "o1": "v1", "o2": "v2", "o3": "v3", "outf": "flag"}
# expect_by 默认 = collected: P1 的真值就是由 x86 真机(box31)采集后回填的(用户定
# 案: 输入输出的数用 x64 机器采集、填入输出表, 别的机器比对正确性)。
# 将来某词干属于"只能档间互推"类, 在这里按词干登记 cross-arm —— 判据强度必须明写
# 在库里, 不能让人把"两边相等"误读成"两边都对"。
# P3(精度控制)当初被列进这个候选, 依据是"现代 Intel 忽略 PC、只有 AMD/龙芯 honor"
# (计划第 39/41 行) -> 若真如此, x86 参考机给不出 PC 各档的基准值, 只能拿档间差分当
# 判据。两台 x86 真机(本机 PE + box31 i3-4150)的实测把这条依据否了: PC(控制字位 8-9)
# 真被 honor, 且 pc24 vs pc53 的 8 行差别逐行合于 prec 舍入模型(kat_audit.py 的
# pc_arm_relation) -> P3 有真机基准, 不登记 cross-arm。偏差留痕见过程报告。
# (P2 舍入模式同理: RC 两档以上在两台机上行为不同且与纯整数推导式等值, 也是 collected。)
X87_EXPECT_BY = {}


def dbg_rows(raws):
    """详细段原始行 -> debug_<grp> 行(每行含 grp/abi/cname/kk + 明细列)。
    两种形态:
      - 标准组(带 src): exp/got 两条合一行 -> in_v0..v3/in_flag +
        gold_*/got_*/st/diff_cols/expect_by(与旧 verify_x87 同口径);
      - pmul(带 tier): 一条即一行 -> in/gold/got/status/inbits/minpop。
    判等在本函数里做(十六进制串全字比, 不做数值转换)。"""
    out = []
    got = {}
    for d in raws:
        if not d.get("cname"):
            continue
        if d.get("tier"):              # pmul 形态: 行已自成一条
            out.append(dict(grp=d.get("grp"), abi=d.get("abi"),
                            cname=d.get("cname"), kk=d.get("tier"),
                            **{k: d.get(k) for k in
                               ("in", "gold", "got", "status", "inbits",
                                "minpop")}))
            continue
        if "src" not in d:             # 非以上两种形态: 丢
            continue
        kk = d.get("kk")
        if kk is None or not str(kk).strip().lstrip("-").isdigit():
            continue
        if d.get("src") not in ("exp", "got"):
            continue
        key = (d.get("grp"), d.get("abi"), d.get("cname"), d.get("stem"), kk)
        row = got.setdefault(key, dict(
            grp=d.get("grp"), abi=d.get("abi"), cname=d.get("cname"),
            kk=kk, stem=d.get("stem") or "-", st="", diff_cols="",
            expect_by="", note=""))
        for sf in ("i0", "i1", "i2", "i3", "inf"):
            row["in_" + K_TO_V[sf]] = d.get(sf)
        dst = "gold_" if d.get("src") == "exp" else "got_"
        for sf in ("o0", "o1", "o2", "o3", "outf"):
            row[dst + K_TO_V[sf]] = d.get(sf)
        if d.get("src") == "exp":
            row["_has_exp"] = 1
        else:
            row["_has_got"] = 1
    for key in sorted(got):
        row = got[key]
        has_e, has_g = row.pop("_has_exp", 0), row.pop("_has_got", 0)
        if not has_e:
            # 采集模式(表未回填)或探针只打了实测侧: 没有基准就不能判 OK
            row["st"] = "NOGOLD"
            row["expect_by"] = "-"
            row["note"] = "dbg 行无 src=exp 配对(采集模式或基准缺失)"
        else:
            diff = [K_TO_V[f] for f, g in
                    (("o0", "gold_v0"), ("o1", "gold_v1"), ("o2", "gold_v2"),
                     ("o3", "gold_v3"), ("outf", "gold_flag"))
                    if has_g and row.get(g) != row.get(g.replace("gold_", "got_"))]
            if not has_g:
                diff = []
                row["note"] = "只打了 exp(未带实测值), got_*=gold_*"
            for fld in ("v0", "v1", "v2", "v3", "flag"):
                if row.get("got_" + fld) is None:
                    row["got_" + fld] = row.get("gold_" + fld)
            row["st"] = "FAIL" if diff else "OK"
            row["diff_cols"] = ",".join(diff)
            row["expect_by"] = X87_EXPECT_BY.get(row["stem"], "collected")
        out.append(row)
    return out


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


def parse_ossl(out):
    """解析 ossl 探针 stdout(3 行): '# ossl_ver=...' 注释 / 表头(纯度量列名
    CSV) / 值行。值 '-'/空 -> None(数值化在入库层按值判类型)。
    返回 (cols dict {列名: 值}, ver 或 None); 结构坏/列数不等返回 (None, ver)。"""
    lines = [ln for ln in out.splitlines() if ln.strip()]
    ver = None
    if lines and lines[0].lstrip().startswith("#"):
        ver = lines[0].split("=", 1)[1].strip() if "=" in lines[0] else None
        lines = lines[1:]
    if len(lines) < 2:
        return None, ver
    hdr = next(csv.reader(io.StringIO(lines[0])))
    val = next(csv.reader(io.StringIO(lines[1])))
    if not hdr or not val or len(hdr) != len(val):
        return None, ver
    d = {}
    for c, v in zip(hdr, val):
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,30}", c):
            continue
        d[c] = None if v in ("", "-") else v
    return d, ver


def median(vals):
    if not vals:
        return None
    s = sorted(vals)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0


def agg_status(states):
    """多 rep 状态聚合: 有 OK 取 OK(其余波动入注记), 否则多数状态。"""
    if not states:
        return None
    if "OK" in states:
        return "OK"
    from collections import Counter
    return Counter(states).most_common(1)[0][0]


def agg_bench(rows, notes, grp):
    """同 (abi, grp, 身份列) 的多 rep 宽行 -> 一行聚合。返回 bench 行 dict。
    身份列: 标准组 = cname; pmul = impl/family(见 grp_ident)。
    列全动态(键集 = 探针表头数据列, 见 parse_seg), 聚合规则按列名后缀启发:
      *_status 状态列: 有 OK 取 OK(部分 rep 非 OK 记注记), 否则多数状态;
      *_sig  签名列: 只取 OK rep 的唯一值(跨 rep 波动记注记);
      数值列(*_ns/_iters/_ops_s/_mb_s, 与同前缀 *_status 同现时仅用其 OK rep): 取中位;
      其余文本槽: 取 OK rep 首值(波动记注记)。
    无有效值的槽(行不适合/全 CRASH): 不设键 -> 入库 NULL。"""
    ident = grp_ident(grp)
    b = dict(abi=rows[0]["abi"], grp=rows[0]["grp"], rep_n=len(rows))
    for c in ident:
        b[c] = rows[0].get(c)
    label = b.get("cname") or "/".join(
        str(b.get(c)) for c in ident) or b.get("grp") or "?"
    cols = set()
    for r in rows:
        cols.update(r.keys())
    numsuf = ("_ns", "_iters", "_ops_s", "_mb_s")

    def st_of(c):              # 数值槽的同前缀状态列(无则 None)
        for s in numsuf:
            if c.endswith(s) and (c[:-len(s)] + "_status") in cols:
                return c[:-len(s)] + "_status"
        return None

    def good_of(c):            # 有效 rep: 槽有值, 且(若有同前缀状态列)其状态为 OK
        stc = st_of(c)
        return [r for r in rows
                if r.get(c) is not None
                and (not stc or r.get(stc) == "OK")]

    for ck in sorted(cols - {"abi", "grp"} - set(ident)):
        if ck.endswith("_status"):
            sts = [r[ck] for r in rows if r.get(ck)]
            if not sts:
                continue
            b[ck] = agg_status(sts)
            if len(set(sts)) > 1:
                notes.append("%s: %s 部分 rep 非 OK [%s]" % (
                    label, ck, ",".join(sorted(set(sts)))))
            continue
        good = good_of(ck)
        if not good:
            continue
        if ck.endswith("_sig"):
            sv = sorted({r[ck] for r in good})
            b[ck] = sv[0]
            if len(sv) > 1:
                notes.append("%s %s 波动" % (label, ck))
            continue
        nums = [fnum(r[ck]) for r in good]
        if all(x is not None for x in nums):
            b[ck] = nums[0] if len(set(nums)) == 1 else median(nums)
            continue
        b[ck] = good[0][ck]
        if len({r[ck] for r in good}) > 1:
            notes.append("%s %s 波动, 取首值" % (label, ck))
    return b


def agg_ossl(rows):
    """多 rep ossl 行(dict 列->值)聚合为一行: 数值列取有效 rep 中位,
    文本列取首值, 全无效列删除(不入库)。列集取并集。"""
    cols = set()
    for r in rows:
        cols.update(r)
    out = {}
    for c in sorted(cols):
        vals = [r[c] for r in rows if r.get(c) is not None]
        if not vals:
            continue
        nums = [fnum(v) for v in vals]
        if all(x is not None for x in nums):
            out[c] = nums[0] if len(set(nums)) == 1 else median(nums)
        else:
            out[c] = vals[0]
    return out


# ---------------- 环境采集(Linux) ----------------

def _sh(cmd):
    try:
        p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=5)
        return p.stdout.decode("utf-8", "replace").strip()
    except Exception:
        return ""


# ---------------- 翻译器指纹(LATX) ----------------

def _resolve_latx(bits):
    """解析实际生效的翻译器路径: $LATX64/$LATX32(显式设置即用) -> PATH 中
    latx-x86_64/latx-i386 -> /usr/bin 默认。返回路径或 None。"""
    v = os.environ.get("LATX64" if bits == 64 else "LATX32")
    if v:
        return v                        # 显式指定(含不存在: 指纹函数置 na 留痕)
    name = "latx-x86_64" if bits == 64 else "latx-i386"
    p = _sh("command -v %s 2>/dev/null" % name)
    if p:
        return p.splitlines()[0].strip()
    d = "/usr/bin/%s" % name           # 默认安装位置
    return d if os.path.isfile(d) else None


def _tr_fingerprint(path):
    """翻译器文件指纹: (size, mtime, sha256, ver)。不可得置 na; ver 取
    '<path> --version' 首行(3s 超时; 翻译器不识别选项时看输出是否带版本)。"""
    if not path or not os.path.isfile(path):
        return "na", "na", "na", "na"
    size = mtime = "na"
    try:
        st = os.stat(path)
        size = str(st.st_size)
        mtime = datetime.datetime.fromtimestamp(
            st.st_mtime).isoformat(timespec="seconds")
    except OSError:
        pass
    h = "na"
    try:
        import hashlib
        hh = hashlib.sha256()
        with open(path, "rb") as f:
            for blk in iter(lambda: f.read(1 << 20), b""):
                hh.update(blk)
        h = hh.hexdigest()
    except OSError:
        pass
    ver = "na"
    try:
        p = subprocess.run([path, "--version"], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=3)
        out = p.stdout.decode("utf-8", "replace").strip()
        ver = out.splitlines()[0][:120] if out else "na"
    except Exception:
        ver = "na"
    return size, mtime, h, ver


def _ps_latx():
    """ps 观测活跃 latx 翻译进程(直接指定路径启动时以进程为准, 如
    /home/loongson/latx-opt/lat/build64/latx-x86_64)。
    仅收 argv0 自身含 latx 的进程(shell/ps 等仅命令行带关键词的排除)。
    返回 (去重路径列表, 进程数)。"""
    out = _sh("ps -eo pid=,args= 2>/dev/null")
    paths, n = [], 0
    for ln in out.splitlines():
        m = re.match(r"\s*(\d+)\s+(.*)$", ln)
        if not m:
            continue
        tok = m.group(2).strip().split()[0]
        if not re.search(r"latx[-_]", tok):
            continue
        n += 1
        if tok not in paths:
            paths.append(tok)
    return paths, n


def env_collect(mode):
    """返回 (envs dict {machine_arch 等固定键}, run 机器列 dict)。容错。"""
    e = {}
    u = os.uname()
    cpuinfo = _read("/proc/cpuinfo")
    cpu = ""
    for ln in cpuinfo.splitlines():
        m = re.match(r"^(model name|cpu model|Processor|Hardware)\s*:\s*(.*)$",
                     ln)
        if m:
            cpu = m.group(2).strip()
            break
    ip = _sh("hostname -I 2>/dev/null") or ""
    ip = next((t for t in ip.split() if ":" not in t), "") or "noip"
    e.update(machine_arch=u.machine, machine_hname=u.nodename,
             machine_cpu=cpu or u.machine, machine_ip=ip)
    distro = ""
    for ln in _read("/etc/os-release").splitlines():
        m = re.match(r'PRETTY_NAME="?(.*?)"?$', ln)
        if m:
            distro = m.group(1)
            break
    e.update(os_distro=distro or _sh("lsb_release -d 2>/dev/null") or "na",
             os_kernel=u.release,
             os_libc=_sh("getconf GNU_LIBC_VERSION 2>/dev/null") or "na")
    cores = cpuinfo.count("processor") if cpuinfo else 0
    e["cpu_logical_cores"] = str(cores) if cores else "na"
    base = "/sys/devices/system/cpu/cpu0/cpufreq"
    for name, key in (("scaling_cur_freq", "cpu_freq_cur_mhz"),
                      ("scaling_governor", "cpu_governor"),
                      ("cpuinfo_max_freq", "cpu_max_freq_mhz")):
        v = _read(os.path.join(base, name)).strip()
        from_khz = True
        if not v:
            m = re.search(r"cpu MHz\s*:\s*([0-9.]+)", cpuinfo)
            if m and name == "scaling_cur_freq":
                v, from_khz = m.group(1), False
            else:
                v = ""
        if v and from_khz and name != "scaling_governor":
            try:
                v = "%.1f" % (float(v) / 1000.0)
            except ValueError:
                pass
        e[key] = v or "na"
    mem = {}
    for ln in _read("/proc/meminfo").splitlines():
        m = re.match(r"(MemTotal|MemAvailable):\s+(\d+) kB", ln)
        if m:
            mem[m.group(1)] = int(m.group(2)) / 1048576.0
    e["sys_mem_total_gb"] = "%.1f" % mem["MemTotal"] if "MemTotal" in mem else "na"
    e["sys_mem_avail_gb"] = "%.1f" % mem["MemAvailable"] if "MemAvailable" in mem else "na"
    la = _read("/proc/loadavg").split()
    for i, k in ((0, "sys_load1"), (1, "sys_load5"), (2, "sys_load15")):
        e[k] = la[i] if len(la) > i else "na"
    e["sys_date_iso"] = datetime.datetime.now().isoformat(timespec="seconds")
    for v in LATX_FIXED:
        e["latx_" + v] = os.environ.get(v) or "(unset)"
    oth = sorted(k for k in os.environ
                 if k.startswith("LATX") and k not in LATX_FIXED)
    e["latx_other"] = " ".join(oth) if oth else "-"
    # 翻译器指纹: 实际生效路径 = $LATX64/32 -> PATH -> /usr/bin 默认
    for bits, tag in ((64, "tr64"), (32, "tr32")):
        pth = _resolve_latx(bits)
        e["latx_%s_effective" % tag] = pth or "na"
        if pth:
            sz, mt, h, ver = _tr_fingerprint(pth)
            e["latx_%s_size" % tag] = sz
            e["latx_%s_mtime" % tag] = mt
            e["latx_%s_sha256" % tag] = h
            e["latx_%s_ver" % tag] = ver
    pp, pn = _ps_latx()
    e["latx_proc_paths"] = " | ".join(pp) if pp else "-"
    e["latx_proc_count"] = str(pn)
    ad = os.environ.get("LATX_DEBUG_AOT")
    if ad and os.path.isdir(ad):
        try:
            fs = os.listdir(ad)
            latest = max((os.path.getmtime(os.path.join(ad, f)) for f in fs),
                         default=0)
            e["latx_aot_dir_entries"] = str(len(fs))
            if latest:
                e["latx_aot_dir_latest_mtime"] = datetime.datetime.fromtimestamp(
                    latest).isoformat(timespec="seconds")
        except OSError:
            pass
    if mode == "wine":
        for v in ("WINE", "WINEPREFIX", "WINEARCH"):
            e["wine_" + v] = os.environ.get(v) or "(unset)"
        w = os.environ.get("WINE") or _sh("command -v kylin-wine 2>/dev/null") \
            or _sh("command -v wine 2>/dev/null")
        if w:
            e["wine_wine_ver"] = _sh('"%s" --version 2>&1' % w) \
                .splitlines()[0][:120] or "na"
            pre = os.environ.get("WINEPREFIX")
            e["wine_prefix_exists"] = "1" if pre and os.path.isdir(pre) else "0"
    sha = os.path.join(DIR, "SHA256SUMS")
    e["run_sha256sums_mtime"] = (datetime.datetime.fromtimestamp(
        os.path.getmtime(sha)).isoformat(timespec="seconds")
        if os.path.isfile(sha) else "na")
    run_m = dict(arch=e["machine_arch"], hname=e["machine_hname"],
                 cpu_model=e["machine_cpu"], ip=e["machine_ip"])
    return e, run_m


# ---------------- 探针执行 ----------------

def killw():
    for c in ("pkill -9 -f '\\.exe'", "pkill -9 -x winedbg",
              "pkill -9 -f wine-preloader", "pkill -9 -x wineserver"):
        _sh(c)
    time.sleep(0.3)
    _sh("wineserver -k 2>/dev/null")
    time.sleep(0.3)


def _brief(raw, n=200):
    """stderr bytes -> 一行诊断文本。只进 notes/诊断列, 绝不进数据解析通道。"""
    if not raw:
        return ""
    s = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    lines = [x.strip() for x in s.splitlines() if x.strip()]
    if not lines:
        return ""
    t = " | ".join(lines[-3:])
    return t[:n] + ("..." if len(t) > n else "")


def execp(cmd, timeout, env=None):
    """执行一次探针, 返回 (rc, stdout, 诊断串)。
    数据通道纪律(2026-09-06 定): **stdout 独占给探针 CSV**, stderr 单独捕获后只
    作为诊断文本返回。旧写法是 stderr=subprocess.STDOUT 合流, 等于把被测环境的
    输出灌进数据流 —— 实测 wine 的 "MESA-INTEL: warning: Haswell Vulkan support
    is incomplete" 占掉首行就令 parse_seg 判整轮 0 行, 而被测产物本身是好的
    (同一 exe 在 Windows 本机直跑 = 27 行 T / KAT 全 OK)。外部环境的毛病不许
    倒逼工具改解析判据, 故在采集端就把两通道分开。"""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, env=env)
        return (p.returncode, p.stdout.decode("utf-8", "replace"),
                _brief(p.stderr))
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode("utf-8", "replace") if e.stdout else ""
        return 124, out, _brief(e.stderr) or "timeout"
    except OSError as e:
        return 126, "", "exec error: %s" % e


def probe_exec(binp, prefix, args, timeout, env=None):
    """执行探针一次。返回 (rc, stdout, 诊断串)。产物缺失 rc=-1。"""
    if not os.path.isfile(binp):
        return -1, "", ""
    if not os.access(binp, os.X_OK):
        try:
            os.chmod(binp, 0o755)
        except OSError:
            pass
    return execp(list(prefix) + [binp] + list(args), timeout, env=env)


def run_warm(binp, prefix, grp, tsec, timeout, env):
    """(grp,abi) 正式测量前 discard pass: 只跑哨兵用例, 输出丢弃。"""
    sent = WARM_SENT.get(grp)
    args = ["--time", str(tsec)]
    if sent:
        args += ["--only=" + sent]
    else:
        args += ["--no-tput", "--time", "200"]
    probe_exec(binp, prefix, args, timeout, env=env)
    return 1


def consistency_check(conn, runf, benches):
    """与本机(同 hname+cpu_model)最近一次 run 对拍哨兵指令 lat 列。
    返回 check_note。亚 ns 的哨兵行按 CHECK_MIN_NS 滤掉(只计数, 不计差)。"""
    prev = conn.execute(
        "SELECT key FROM runs WHERE hname=? AND cpu_model=? AND key<>? "
        "ORDER BY started_at DESC LIMIT 1",
        (runf.get("hname"), runf.get("cpu_model"), runf["key"])).fetchone()
    if not prev:
        return "no-prev"
    pk = prev[0]
    notes = []
    thin = 0
    for g, c in CHECK_SENT:
        # 逐组的 bench_<grp> 表(分表后不再有 bench 总表); 该组没有 lat 列就跳过
        tn = bench_table(g)
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                            "AND name=?", (tn,)).fetchone():
            continue
        have = set(table_cols(conn, tn))
        if "latency_status" not in have or "latency_ns" not in have:
            continue
        # 只查该组在册的 ABI, 且只查本场跑了的 ABI: 拿一个没跑过的 abi 去查 lat
        # 会命中下面的 `continue` = 静默落空(就是 mov/alu/logic 踩过的那个坑)
        for abi in [x for x in abi_scope(g)
                    if runf.get("abi", "all") == "all"
                    or x == runf.get("abi")]:
            def lat_of(run_id):
                r = conn.execute(
                    "SELECT latency_ns FROM %s WHERE run_id=? AND abi=? AND "
                    "grp=? AND cname=? AND latency_status='OK' "
                    "AND latency_ns IS NOT NULL" % tn,
                    (run_id, abi, g, c)).fetchone()
                return r[0] if r else None
            a, b = lat_of(runf["key"]), lat_of(pk)
            if a is None or b is None or b == 0:
                continue
            if min(a, b) < CHECK_MIN_NS:
                thin += 1                       # 太短, 不判(见 CHECK_MIN_NS 注)
                continue
            r = a / b
            if r < 1 - CHECK_TOL or r > 1 + CHECK_TOL:
                notes.append("%s_%s %.0f%%" % (abi, c, r * 100))
    tail = "" if not thin else "(亚ns跳过%d)" % thin
    if not notes:
        return "consistent" + tail
    return "MISMATCH(%s)" % ";".join(notes) + tail


# ---------------- run ----------------

def do_run(args):
    if sys.platform.startswith("win"):
        eprint("run 需在 Linux 主机执行")
        sys.exit(2)
    mode = args.mode
    groups = args.groups or list(GROUPS)
    abi = args.abi or "all"
    if abi not in ("x64", "i386", "loongarch64", "all"):
        eprint("非法 --abi: %s" % abi)
        sys.exit(2)
    reps = args.reps or 1
    tsec = args.time
    only_arg = ["--only=" + args.only] if args.only else []
    timeout = int(os.environ.get("TIMEOUT", "120"))
    os.makedirs(RES, exist_ok=True)
    conn = connect(args.db)

    ev, run_m = env_collect(mode)
    ev["run_reps"] = str(reps)
    ev["run_tput_ms"] = "%d" % tsec
    ev["run_only"] = args.only or "-"
    # ISB_VERIFY 回显: 存原值不存布尔(布尔是探针单侧规则, 在此重推 = 第二份实现)
    ev["run_verify"] = os.environ.get("ISB_VERIFY") or "-"
    ts = datetime.datetime.now()
    key = build_key(mode, run_m["arch"], run_m["cpu_model"], run_m["ip"], ts)
    print("== run key: %s" % key)

    # native i386 探测(整轮开关)
    i386_ok = True
    if mode == "native" and abi != "x64":
        rc, _, _ = probe_exec(os.path.join(BIN, "timer-i386_linux"), [], [], 15)
        i386_ok = rc == 0

    is_loong = os.uname().machine == "loongarch64"
    wcmd = os.environ.get("WINE") or ""
    if not wcmd:
        wcmd = _sh("command -v kylin-wine 2>/dev/null") or \
               _sh("command -v wine 2>/dev/null")
    env0 = dict(os.environ)
    # loongarch64 只在 abi_scope 含它的组(目前只 cfloat)才会真正进入;
    # 其余组因 abi_scope 默认 (x64,i386) 在下方被静默跳过。
    abi_list = (["x64", "i386", "loongarch64"] if abi == "all" else [abi])
    agg_rows, notes, dones = [], [], []
    v_rows, f_rows = [], []   # 详细明细行(dbg) / 功能结果行(func)
    dbg_arg = ["--debug"] if getattr(args, "debug", False) else []
    warm_n = 0

    for g in groups:
        for a in abi_list:
            if a not in abi_scope(g):
                # 静默跳过(设计而非缺件): 这组在该 ABI 本来就不在册, 记进 notes
                # 只会淹掉真告警(与 SKIP: 缺产物 长一个样)。
                # 也不允许反向"修": 实测拿 x64 编一份 x87 探针它跑得通还全绿
                # (见 isb_x87.c 取证 6), 所以护栏在源码 #error 与 build.sh 的
                # GRP_32ONLY, 不在这里。
                continue
            # loongarch64 原生二进制只能在 loongarch64 机上跑(非 x86 主机直执
            # 行会 Exec format error); 非本机时静默跳过, 不当缺件告警。
            if a == "loongarch64" and not is_loong:
                continue
            # WSL i386 已能采集: wine/native/latx 统一跑 _linux ELF(不绕 .exe)
            if mode in ("native", "latx", "wine"):
                binp = os.path.join(BIN, "%s-%s_linux" % (g, a))
                env = None
            else:  # 保留纯 Windows 侧(.exe) 通道(如真要跑)
                binp = os.path.join(BIN, "%s-%s_windows.exe" % (g, a))
                env = env0
            prefix = []
            if mode == "wine" and wcmd:
                prefix = [wcmd]
                env = dict(env0)
                env["WINEDEBUG"] = "-all"
            elif mode == "latx" and not is_loong:
                tr = os.environ.get("LATX64" if a == "x64" else "LATX32")
                if tr:
                    prefix = [tr] + shlex.split(os.environ.get("LATX_OPTS", ""))
            if a == "loongarch64":
                # loongarch64 是原生参照二进制(cfloat 组), 不经 wine/translator 前缀,
                # 无论 mode 如何都直接本机执行(上方已保证只在 is_loong 时到达此处)。
                prefix = []
                env = None
            need_latx_tr = (mode == "latx" and not is_loong
                            and not os.environ.get(
                                "LATX64" if a == "x64" else "LATX32"))
            if need_latx_tr:
                notes.append("SKIP: %s-%s 需在 loongarch64 或设 LATX64/LATX32"
                             % (g, a))
                continue
            if mode == "native" and a == "i386" and not i386_ok:
                notes.append("SKIP: %s-%s native i386 不可执行(无 ia32)"
                             % (g, a))
                continue
            if mode == "wine" and not wcmd:
                notes.append("SKIP: %s-%s 无 wine/kylin-wine" % (g, a))
                continue
            if args.warm:
                if mode == "wine":
                    killw()
                run_warm(binp, prefix, g, tsec, timeout, env)
                warm_n += 1
            # 多 rep: 每次 exec 单独解析, 同身份列归并聚合(入库一行)
            ident = grp_ident(g)
            raw = {}
            for r in range(1, reps + 1):
                if mode == "wine":
                    killw()
                rc, out, err = probe_exec(binp, prefix,
                                          ["--time", str(tsec)] + only_arg
                                          + dbg_arg,
                                          timeout, env=env)
                if rc == -1:
                    notes.append("SKIP: %s-%s 缺产物" % (g, a))
                    continue
                if rc == 124:
                    notes.append("TIMEOUT(%ds): %s-%s%s"
                                 % (timeout, g, a, " [%s]" % err if err else ""))
                    continue
                if rc != 0:
                    notes.append("EXIT(%d): %s-%s%s"
                                 % (rc, g, a, " [%s]" % err if err else ""))
                    continue
                rows, funcs, dbgs, done = parse_seg(out, g)
                f_rows += funcs          # 功能结果 -> verify_<grp>
                if dbgs:                 # 详细明细(只有 --debug 时探针才吐)
                    v_rows += dbg_rows(dbgs)
                if not rows and done is None:
                    # stdout 不是以 kind 表头开头的 CSV。诊断串走 stderr 通道,
                    # 能区分"真 0 输出"与"探针把话说到 stderr 里去了"。
                    notes.append("输出无 T/D: %s-%s (rc=%d, %d 字节%s)"
                                 % (g, a, rc, len(out),
                                    ", err: " + err if err else ""))
                    continue
                if done:
                    dones.append(done)
                else:
                    notes.append("缺 D 行: %s-%s" % (g, a))
                for row in rows:
                    raw.setdefault(
                        (row["abi"],) + tuple(row.get(c) for c in ident),
                        []).append(row)
            for kk, rrs in raw.items():
                agg_rows.append(agg_bench(rrs, notes, g))
    if not i386_ok and mode == "native" and abi != "x64":
        notes.append("i386 探测不可执行(内核无 IA32_EMULATION), 本场整轮 SKIP")
    done_note = "# DONE 哨兵: 期望[%s] 实得[%s]" % (
        " ".join(sorted(set(groups))), " ".join(sorted(set(dones))))
    ev["probe_notes"] = "\n".join("# %s" % n for n in notes) if notes else "-"

    runf = dict(key=key, mode=mode, arch=run_m["arch"], abi=abi, reps=reps,
                tput_ms=tsec, started_at=ts.isoformat(timespec="seconds"),
                py_ver=platform.python_version(),
                imported_at=datetime.datetime.now()
                .isoformat(timespec="seconds"),
                warm_discards=warm_n, hname=run_m["hname"],
                cpu_model=run_m["cpu_model"], ip=run_m["ip"],
                done_note=done_note)
    st = ingest(conn, runf, ev, agg_rows)
    if f_rows:
        nfun = ingest_func(conn, key, f_rows)
        print("== verify_<grp> 功能: %d 行(列 = 各功能, 值 true/false; 空 = 本轮没判)"
              % nfun)
    if args.debug and v_rows:
        nd = ingest_debug(conn, key, v_rows)
        print("== debug_<grp> 详细: %d 行(仅 --debug 采集)" % nd)
    if args.check:
        cnote = consistency_check(conn, runf, agg_rows)
        conn.execute("UPDATE runs SET check_note=? WHERE key=?", (cnote, key))
        conn.commit()
        print("== 一致性自校验: %s" % cnote)
    print("== 入库: %s (%d 指令行) db=%s" % (st, len(agg_rows), args.db))
    for n in notes:
        print("   probe 注记: %s" % n)
    if args.push:
        push_run(key, args.push, args.db)


def do_ossl(args):
    """独立 openssl 测速探针(ossl/ossl_probe.c, 与指令探针分离编译):
    每 (mode,abi) 一个 run key, reps 聚合为一行入 ossl 表(列 = 算法_尺寸);
    runs/env_wide 复用现有 ingest(空 bench)。不参与哨兵/compare。
    --ver 11 = 测 1.1.1w(ossl11_* 二进制), 与 3.x 同 ossl 表按 ossl_ver 共存。"""
    if sys.platform.startswith("win"):
        eprint("ossl 需在 Linux 主机执行")
        sys.exit(2)
    mode = args.mode
    reps = args.reps or 1
    tsec = args.time
    timeout = int(os.environ.get("TIMEOUT", "900"))
    os.makedirs(RES, exist_ok=True)
    conn = connect(args.db)
    # --ver 11 = openssl 1.1.1w(ossl11_* 二进制), 3 = 3.x(ossl_*): 同 ossl 表
    # ossl_ver 列分版本; 1.1.1 无 sm4-gcm, 探针动态枚举自动少该组列
    lib = "11" if getattr(args, "ver", 3) == 11 else "3"
    mpre = "ossl11-" if lib == "11" else "ossl-"
    bsuf = "build-ossl11.sh" if lib == "11" else "build-ossl.sh"
    abi_list = ["x64", "i386"] if args.abi == "all" else [args.abi]
    is_loong = os.uname().machine == "loongarch64"
    for a in abi_list:
        binp = os.path.join(BIN, "%s%s_linux" % (mpre, a))
        if not os.path.isfile(binp):
            eprint("SKIP: %s 缺产物(先跑 %s)" % (binp, bsuf))
            continue
        prefix = []
        if mode == "latx" and not is_loong:
            tr = os.environ.get("LATX64" if a == "x64" else "LATX32")
            if tr:
                prefix = [tr] + shlex.split(os.environ.get("LATX_OPTS", ""))
        if mode == "latx" and not is_loong and not prefix:
            eprint("SKIP: latx %s 需在 loongarch64 或设 LATX64/LATX32" % a)
            continue
        if mode == "native" and a == "i386":
            rc, _, _ = probe_exec(binp, [], ["--time", "20", "--sizes", "16"],
                                  30)
            if rc != 0:
                eprint("SKIP: native %s 不可执行(rc=%d, 无 ia32?)" % (a, rc))
                continue
        if mode == "wine":
            eprint("SKIP: ossl 无 wine 形态产物")
            continue
        ev, run_m = env_collect(mode)
        ts = datetime.datetime.now()
        # key 不带 abi(ossl 表已有 abi 列); abi 循环内 ts 逐次重取, 天然区分两形态
        key = build_key(mpre + mode, run_m["arch"], run_m["cpu_model"],
                        run_m["ip"], ts)
        print("== ossl run key: %s" % key)
        ev["run_reps"] = str(reps)
        ev["run_tput_ms"] = "%d" % tsec
        ev["run_only"] = "ossl11" if lib == "11" else "ossl"
        notes = []
        if args.warm:
            probe_exec(binp, prefix,
                       ["--algo", "aes-128-cbc", "--sizes", "8192",
                        "--time", "200"], timeout)
        raw = []
        for _ in range(reps):
            rc, out, err = probe_exec(binp, prefix, ["--time", str(tsec)], timeout)
            if rc != 0:
                notes.append("EXIT(%d): %s%s"
                             % (rc, os.path.basename(binp),
                                " [%s]" % err if err else ""))
                continue
            d, ver = parse_ossl(out)
            if d is None:
                notes.append("输出结构异常: %s" % os.path.basename(binp))
                continue
            raw.append((d, ver))
        if not raw:
            eprint("SKIP: %s 无有效输出" % os.path.basename(binp))
            continue
        agg = agg_ossl([d for d, _ in raw])
        ver = raw[0][1]
        runf = dict(key=key, mode="ossl-" + mode, arch=run_m["arch"], abi=a,
                    reps=reps, tsec=tsec,
                    started_at=ts.isoformat(timespec="seconds"),
                    py_ver=platform.python_version(),
                    imported_at=datetime.datetime.now()
                    .isoformat(timespec="seconds"),
                    warm_discards=1 if args.warm else 0,
                    hname=run_m["hname"], cpu_model=run_m["cpu_model"],
                    ip=run_m["ip"], done_note="")
        st = ingest(conn, runf, ev, [])
        row = dict(run_id=key, abi=a, os="linux",
                   bits=64 if a == "x64" else 32, tsec=tsec,
                   ossl_ver=ver)
        row.update(agg)
        st2 = ingest_ossl_metrics(conn, row)
        print("== 入库: runs=%s ossl=%s (%d 度量列) db=%s"
              % (st, st2, len(agg), args.db))
        for n in notes:
            print("   probe 注记: %s" % n)
        if args.push:
            push_run(key, args.push, args.db)


def build_key(mode, arch, cpu_model, ip, ts):
    def slug(s, n=40):
        s = re.sub(r"[^A-Za-z0-9._-]", "_", s or "unknown")
        return s[:n] or "unknowncpu"
    return "%s_%s_%s_%s_%s" % (mode, arch, slug(cpu_model), slug(ip, 24),
                               ts.strftime("%Y%m%d-%H%M%S"))


# ---------------- compare ----------------

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


def sig_match(a, b):
    return bool(a and b and a != "-" and b != "-" and a == b)


def cmd_compare(args):
    conn = connect(args.db)
    ta = resolve_key(conn, args.truth)
    ra = resolve_key(conn, args.run)
    if not ta or not ra:
        sys.exit(2)
    for k, tag in ((ta, "truth"), (ra, "run")):
        r = fetch_run(conn, k)
        if r and r.get("check_note"):
            print("# %s check_note: %s" % (tag, r["check_note"]))
    # 键 = (abi, cname): 同一个 run 里两 ABI 会各带同名 case(新组按 ABI 条件注
    # 册, 如 x86_mov__r_m_l_base 在 x64/i386 两侧都存在), 单 cname 做键会让后读
    # 的一 ABI 覆盖前一个(实测: 入库 50 行只对上 34 行)。下游 k[0]=abi/k[1]=cname。
    ti = {(b["abi"], b["cname"]): b for b in load_run_bench(conn, ta)}
    ri = {(b["abi"], b["cname"]): b for b in load_run_bench(conn, ra)}
    # 逐方式对拍(lat/tput/sem/kat/diag 各自成一行明细)
    ways = [("latency", "latency_status", "latency_ns", None),
            ("throughput", "throughput_status", "throughput_ops_s", None),
            ("block8", "block8_status", "block8_ns", None),
            ("diag", "diag_status", "diag_value", None)]
    keys = sorted(set(ti) | set(ri), key=lambda c: (c[0], c[1]))
    dev = miss_r = miss_t = n = 0
    for k in keys:
        abi, g = ti[k]["abi"] if k in ti else ri[k]["abi"], \
                 ti[k]["grp"] if k in ti else ri[k]["grp"]
        if k not in ti:
            miss_t += 1
            continue
        if k not in ri:
            miss_r += 1
            for wname, stk, _, _ in ways:
                t = ti[k]
                if t.get(stk):
                    print("%-6s %-8s %-30s %-5s %-10s %s" % (
                        abi, g, k[1], wname, "MISSING-run", "-"))
            continue
        t, r = ti[k], ri[k]
        for wname, stk, vk, sigk in ways:
            tst, rst = t.get(stk), r.get(stk)
            if not tst and not rst:
                continue
            st, why = "OK", ""
            if rst != tst:
                st, why = "DEVIATION", "status %s->%s" % (tst, rst)
            elif rst == "OK":
                if sigk and t.get(sigk) != "-" and r.get(sigk) != "-" and \
                        t.get(sigk) != r.get(sigk):
                    st, why = "DEVIATION", "sig %s!=%s" % (t.get(sigk),
                                                           r.get(sigk))
            rat = 0.0
            if vk and tst == "OK" and rst == "OK":
                tv, rv = t.get(vk), r.get(vk)
                if tv is not None and rv is not None and tv > 0:
                    rat = 100.0 * rv / tv
                    if rat < RAT_LO or rat > RAT_HI:
                        st, why = "DEVIATION", "ratio %.6g%%" % rat
            sf = "-"
            if sigk and sig_match(t.get(sigk), r.get(sigk)):
                sf = "MATCH"
            print("%-6s %-8s %-30s %-5s %-10s %-9s %8.1f%% %s"
                  % (abi, g, k[1], wname, st, sf, rat, why))
            n += 1
            if st == "DEVIATION":
                dev += 1
    print("== 汇总: 对拍 %d 方式行, DEVIATION %d, run 侧多余 %d, "
          "truth 侧缺失 %d" % (n, dev, miss_r, miss_t))
    sys.exit(1 if (dev > 0 or miss_t > 0) else 0)


def ways_st(wname):
    return {"latency": "latency_status", "throughput": "throughput_status",
            "block8": "block8_status", "diag": "diag_status"}[wname]


# ---------------- push / serve ----------------

def push_run(key, url, db):
    conn = connect(db)
    key = resolve_key(conn, key)
    if not key:
        return 1
    runf = fetch_run(conn, key)
    ev = conn.execute("SELECT * FROM env_wide WHERE run_id=?",
                      (key,)).fetchone()
    evcols = [d[0] for d in conn.execute("SELECT * FROM env_wide").description]
    evd = dict(zip(evcols, ev)) if ev else {}
    bench = load_run_bench(conn, key)
    # ossl 行(run 可能为 ossl 探针 run; 普通 bench run 无此行 -> payload 里 None)
    orow = conn.execute("SELECT * FROM ossl WHERE run_id=?",
                        (key,)).fetchone()
    ocols = [d[0] for d in conn.execute("SELECT * FROM ossl").description]
    ossl = dict(zip(ocols, orow)) if orow else None
    # 功能表(verify_<grp>)与详细表(debug_<grp>)也一并推送: 只带计时行会让中心库
    # 拿到"跑了 N 个 case"却拿不到"哪个功能判负 / 哪一组输入错在哪个字段"。
    # 空则不带键(两向兼容): 老客户端不送 -> 服务端缺省不写。
    frows = load_tbl_rows(conn, VERIFY_TABLES, key)
    vrows = load_tbl_rows(conn, DEBUG_TABLES, key)
    payload = dict(run=runf, env=evd, bench=bench, ossl=ossl,
                   func=frows or None, debug=vrows or None,
                   token=os.environ.get("ISBENCH_TOKEN") or "")
    data = json.dumps(payload, default=str).encode("utf-8")
    try:
        req = urllib.request.Request(url.rstrip("/") + "/push", data=data,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read().decode("utf-8", "replace")
        print("== push %s -> %s" % (key, body))
        return 0
    except urllib.error.URLError as e:
        eprint("push 失败(仅警告, 可用 push --last 补推): %s" % e)
        return 1


class _Handler(BaseHTTPRequestHandler):
    server_version = "isbench-serve/1.0"

    def _reply(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/push":
            self._reply(404, dict(status="error", msg="not found"))
            return
        try:
            n = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception as e:
            self._reply(400, dict(status="error", msg="bad json: %s" % e))
            return
        tok = self.server.token
        if tok and payload.get("token") != tok:
            self._reply(403, dict(status="error", msg="bad token"))
            return
        runf = dict(payload.get("run") or {})
        if not runf.get("key"):
            self._reply(400, dict(status="error", msg="no run.key"))
            return
        envd = dict(payload.get("env") or {})
        bench = []
        for b in payload.get("bench", []):
            if isinstance(b, dict):
                bench.append(b)
            else:
                eprint("serve: 忽略非 dict bench 行(旧版 push 客户端?)")
        conn = connect(self.server.db)
        st = ingest(conn, runf, envd, bench)
        # ossl run 载荷: 行 dict 含全部列(固定 + 度量), 幂等 OR REPLACE by run_id
        ossl = payload.get("ossl")
        if isinstance(ossl, dict) and ossl.get("run_id"):
            ingest_ossl_metrics(conn, ossl)
        # 功能表/详细表: 与 push_run 侧同名键; 老客户端无这些键 -> 计数为 0(不谎报)
        funcs = []
        for f in (payload.get("func") or []):
            if isinstance(f, dict):
                funcs.append((f.get("grp"), f.get("abi"), f.get("cname"),
                              dict(f)))
        nfun = ingest_func(conn, runf["key"], funcs)
        dlist = [d for d in (payload.get("debug") or [])
                 if isinstance(d, dict)]
        ndbg = ingest_debug(conn, runf["key"], dlist)
        conn.close()
        self._reply(200, dict(status=st, run=runf["key"],
                              rows=len(bench), func=nfun, debug=ndbg))

    def log_message(self, fmt, *a):
        sys.stderr.write("[serve] " + (fmt % a) + "\n")


class _ThreadingServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

    def __init__(self, addr, db, token):
        self.db = db
        self.token = token
        HTTPServer.__init__(self, addr, _Handler)


def cmd_serve(args):
    srv = _ThreadingServer((args.host, args.port), args.db, args.token or "")
    print("== serve 监听 %s:%d -> db=%s (Ctrl-C 停止)"
          % (args.host, args.port, args.db))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n== 停止")
    srv.server_close()


# ---------------- ls/show/env-diff/export ----------------

def cmd_ls(args):
    conn = connect(args.db)
    rows = list_runs(conn, mode=args.mode, host=args.host)
    if not rows:
        print("(空库)")
        return
    print("%-4s %-58s %-11s %-6s %-4s %-19s %-6s %s"
          % ("id", "key", "mode", "abi", "rep", "started", "rows",
             "check"))
    for i, r in enumerate(rows, 1):
        note = r[8] or ""
        if note.startswith("MISMATCH"):
            note = "!! " + note
        print("%-4d %-58s %-11s %-6s %-4s %-19s %-6d %s"
              % (i, r[0], r[1], r[3], r[4], (r[5] or "")[:19], r[6] or 0,
                 note))


def cmd_show(args):
    conn = connect(args.db)
    key = resolve_key(conn, args.run)
    if not key:
        sys.exit(2)
    runf = fetch_run(conn, key)
    for k, v in runf.items():
        if v is not None:
            print("%-12s %s" % (k, v))
    print("-- env_wide(每 run 一行) --")
    row = conn.execute("SELECT * FROM env_wide WHERE run_id=?", (key,)).fetchone()
    if row:
        cols = [d[0] for d in conn.execute(
            "SELECT * FROM env_wide").description]
        for c, v in zip(cols, row):
            if c == "run_id":
                continue
            if v not in (None, "", "-"):
                print("%-28s %s" % (c, v))
    print("-- 三族表分布(逐 bench_/verify_/debug_<grp> 统计) --")
    by = {}
    for r in load_run_bench(conn, key):
        by.setdefault((r.get("abi"), r.get("src")), []).append(r)
    for (abi, tn), rs in sorted(by.items()):
        print("  %-6s %s: %d 行(聚合 rep_n=%d)"
              % (abi, tn, len(rs), sum(x.get("rep_n") or 0 for x in rs)))
    for fam, nm in ((VERIFY_TABLES, "功能表 verify_*"),
                    (DEBUG_TABLES, "详细表 debug_*")):
        n = 0
        for tn in existing_tables(conn, fam):
            n += conn.execute("SELECT count(*) FROM %s WHERE run_id=?" % tn,
                              (key,)).fetchone()[0]
        print("  %s: %d 行" % (nm, n))
    print("-- ossl(openssl 探针, 每 run 一行, 列=算法_尺寸) --")
    row = conn.execute("SELECT * FROM ossl WHERE run_id=?",
                       (key,)).fetchone()
    if row:
        cols = [d[0] for d in conn.execute("SELECT * FROM ossl").description]
        od = dict(zip(cols, row))
        met = [(c, v) for c, v in od.items()
               if c not in OSSL_FIX and v not in (None, "")]
        print("  固定: abi=%s os=%s bits=%s tsec=%s ossl_ver=%s"
              % (od.get("abi"), od.get("os"), od.get("bits"),
                 od.get("tsec"), (od.get("ossl_ver") or "")[:40]))
        print("  度量列 %d 非空/%d: %s%s" % (
            len(met), sum(1 for c in cols if c not in OSSL_FIX),
            ", ".join("%s=%s" % (c, v) for c, v in met[:6]),
            " ..." if len(met) > 6 else ""))
    else:
        print("  (本 run 非 ossl)")


def cmd_envdiff(args):
    conn = connect(args.db)
    keys = []
    for ref in (args.a, args.b):
        key = resolve_key(conn, ref)
        if not key:
            sys.exit(2)
        keys.append(key)
    got = {}
    for key in keys:
        row = conn.execute("SELECT * FROM env_wide WHERE run_id=?",
                           (key,)).fetchone()
        cols = [d[0] for d in
                conn.execute("SELECT * FROM env_wide").description]
        got[key] = dict(zip(cols, row)) if row else {}
    ka, kb = keys[0], keys[1]
    ea, eb = got[ka], got[kb]
    n = 0
    for k in sorted(set(ea) | set(eb)):
        if k == "run_id":
            continue
        va, vb = ea.get(k), eb.get(k)
        va2 = va if va not in (None, "") else "(缺)"
        vb2 = vb if vb not in (None, "") else "(缺)"
        if va2 != vb2:
            n += 1
            print("%-28s %s=%s  |  %s=%s" % (k, ka, va2, kb, vb2))
    if not n:
        print("(环境一致)")


def cmd_export(args):
    """导出性能表 CSV: 表头 = 各 bench_<grp> 列并集(去 run_id/src)。"""
    conn = connect(args.db)
    key = resolve_key(conn, args.run)
    if not key:
        sys.exit(2)
    runf = fetch_run(conn, key)
    if (runf.get("mode") or "").startswith(("ossl-", "ossl11-")):
        export_ossl(conn, key)
        return
    rows = load_run_bench(conn, key)
    # 各组列独立 -> 表头 = 本次导出覆盖到的表列并集(首次出现序); 缺列打 '-'
    out_cols, seen = [], set()
    for r in rows:
        for c in r:
            if c in ("run_id", "src") or c in seen:
                continue
            seen.add(c)
            out_cols.append(c)
    w = csv.writer(sys.stdout)
    w.writerow(out_cols)
    for r in rows:
        w.writerow(["-" if r.get(c) is None else r[c] for c in out_cols])
    eprint("# rows=%d (run %s)" % (len(rows), key))


def export_ossl(conn, key):
    """ossl run 导出: 该行宽 CSV(表头 = 库实列序, 去 run_id), 每 run 1 行。"""
    row = conn.execute("SELECT * FROM ossl WHERE run_id=?",
                       (key,)).fetchone()
    if not row:
        eprint("# ossl: run %s 无 ossl 行" % key)
        return
    cols = [d[0] for d in conn.execute("SELECT * FROM ossl").description]
    pcols = [c for c in cols if c != "run_id"]
    w = csv.writer(sys.stdout)
    w.writerow(pcols)
    w.writerow(["-" if row[cols.index(c)] is None else row[cols.index(c)]
                for c in pcols])
    eprint("# rows=1 (ossl run %s)" % key)


# ---------------- CLI ----------------

def build_parser():
    ap = argparse.ArgumentParser(prog="isbench.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")

    def add_db(p, help="库文件(默认 %s)" % DEF_DB):
        p.add_argument("--db", default=DEF_DB, help=help)

    p = sub.add_parser("run", help="执行一轮测试并入库(宽表: 一指令一行)")
    p.add_argument("mode", choices=["native", "latx", "wine"])
    p.add_argument("groups", nargs="*",
                   help="组(默认全部: %s)" % " ".join(GROUPS))
    p.add_argument("--abi", choices=["x64", "i386", "all"], default="all")
    p.add_argument("--reps", type=int, default=1,
                   help="每 (组,abi) 执行轮数, 入库聚合一行(中位)")
    p.add_argument("--time", type=int, default=100, dest="time",
                   help="探针内计时窗口毫秒(默认 100)")
    p.add_argument("--only", default="")
    p.add_argument("--push", default="", help="完成后推送 URL")
    p.add_argument("--warm", type=int, default=1, help="预热丢弃(默认 1)")
    p.add_argument("--check", type=int, default=1, help="一致性自校验(默认 1)")
    p.add_argument("--debug", action="store_true",
                   help="采详细明细(透传探针 --debug, 写入 debug_<grp> 表)")
    add_db(p)
    p.set_defaults(fn=do_run)

    p = sub.add_parser("compare", help="对拍两个库内 run(逐方式列比)")
    p.add_argument("truth")
    p.add_argument("run")
    add_db(p)
    p.set_defaults(fn=cmd_compare)

    p = sub.add_parser("ls", help="列出库内 runs")
    p.add_argument("--mode")
    p.add_argument("--host", help="按机器名/型号子串过滤")
    add_db(p)
    p.set_defaults(fn=cmd_ls)

    p = sub.add_parser("show", help="查看单 run 详情(env_wide 宽行 + bench)")
    p.add_argument("run")
    add_db(p)
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("env-diff", help="两 run 环境差异(env_wide 逐列)")
    p.add_argument("a")
    p.add_argument("b")
    add_db(p)
    p.set_defaults(fn=cmd_envdiff)

    p = sub.add_parser("export", help="导出宽表 CSV(与探针同表头, xlsx 导入)")
    p.add_argument("run")
    add_db(p)
    p.set_defaults(fn=cmd_export)

    p = sub.add_parser("serve", help="常驻接收 push")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8770)
    p.add_argument("--token", default="")
    add_db(p)
    p.set_defaults(fn=cmd_serve)

    p = sub.add_parser("push", help="推送指定 run(缺省/--last = 最近一次)")
    p.add_argument("run", nargs="?", default=None)
    p.add_argument("--last", action="store_true",
                   help="推送最近一次 run(缺省行为)")
    p.add_argument("--url", default=os.environ.get("ISBENCH_PUSH", ""),
                   help="目标 URL(默认 $ISBENCH_PUSH)")
    add_db(p)
    p.set_defaults(fn=lambda a: push_run(
        a.run if a.run else _last_key(connect(a.db)), a.url, a.db) and None)

    p = sub.add_parser("ossl",
                       help="独立 openssl 测速探针(ossl 表, 列=算法_尺寸; 3.x/1.1.1 共存)")
    p.add_argument("mode", choices=["native", "latx", "wine"])
    p.add_argument("--ver", type=int, choices=[3, 11], default=3,
                   help="被测 libcrypto 主版本: 3=3.x(ossl-*), 11=1.1.1w(ossl11-*; "
                        "同表 ossl_ver 列分版本)")
    p.add_argument("--abi", choices=["x64", "i386", "all"], default="all",
                   help="形态(默认 all: x64+i386 各一 run)")
    p.add_argument("--reps", type=int, default=1,
                   help="每 (mode,abi) 执行轮数, 数值列取中位聚合一行")
    p.add_argument("--time", type=int, default=100, dest="time",
                   help="探针内每(算法,尺寸)计时窗口毫秒(默认 100; 约 20 算法x6 尺寸)")
    p.add_argument("--push", default="", help="完成后推送 URL")
    p.add_argument("--warm", type=int, default=1, help="预热丢弃(默认 1)")
    add_db(p)
    p.set_defaults(fn=do_ossl)
    return ap


def _last_key(conn):
    r = conn.execute("SELECT key FROM runs ORDER BY started_at DESC LIMIT 1") \
        .fetchone()
    if not r:
        eprint("库为空, 无 run 可推")
        sys.exit(2)
    return r[0]


def main():
    if len(sys.argv) < 2:
        build_parser().print_help()
        sys.exit(1)
    ap = build_parser()
    args = ap.parse_args()
    if not getattr(args, "fn", None):
        ap.print_help()
        sys.exit(1)
    args.fn(args)


if __name__ == "__main__":
    main()
