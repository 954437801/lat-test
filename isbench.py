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
GROUPS = ["scalar", "sse", "avx", "crypto", "cpuid", "timer"]
LATX_FIXED = ["LATX64", "LATX32", "LATX_OPTS", "LATX_AOT", "LATX_VPAES",
              "LATX_SOFFPU", "LATX_DEBUG_AOT"]
# 预热丢弃/一致性自校验哨兵(宽表按 cname 取 lat 列)
WARM_SENT = {"scalar": "x86_add_r64", "sse": "sse_movups_ld",
             "avx": "avx_vaddps_xmm", "crypto": "aesenc", "cpuid": "cpuid"}
CHECK_SENT = [("scalar", "x86_add_r64"), ("crypto", "aesenc")]
CHECK_TOL = 0.10
RAT_LO, RAT_HI = 85.0, 115.0

# 探针单表 CSV 表头(26 列; kind=T 用例行 / kind=D 组尾行)
WIDE_HDR = ["kind", "group", "abi", "os", "bits", "tput_sec", "lat_iters",
            "case", "lat_st", "lat_ns", "lat_sig", "tput_st", "tput_ops",
            "tput_mbs", "tput_sig", "sem_st", "sem_sig", "sem_tag",
            "kat_st", "kat_det", "diag_st", "diag_v", "diag_u", "diag_det",
            "ok", "total"]


def eprint(*a):
    print(*a, file=sys.stderr)


def fnum(s):
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


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
    # 翻译器指纹(实际生效路径 = $LATX64/32 -> PATH -> /usr/bin 默认;
    # ps -ef 观测的活跃进程路径另列 latx_proc_*)
    "latx_tr64_effective", "latx_tr64_size", "latx_tr64_mtime",
    "latx_tr64_sha256", "latx_tr64_ver",
    "latx_tr32_effective", "latx_tr32_size", "latx_tr32_mtime",
    "latx_tr32_sha256", "latx_tr32_ver",
    "latx_proc_paths", "latx_proc_count", "latx_aot_dir_entries",
    "latx_aot_dir_latest_mtime",
    "wine_WINE", "wine_WINEPREFIX", "wine_WINEARCH", "wine_wine_ver",
    "wine_prefix_exists",
    "run_reps", "run_tsec", "run_only", "run_sha256sums_mtime",
    "probe_notes",
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(
 key TEXT PRIMARY KEY, mode TEXT, arch TEXT, abi TEXT, reps INT,
 tsec REAL, started_at TEXT, done_note TEXT, py_ver TEXT,
 imported_at TEXT, push_src TEXT, warm_discards INT, check_note TEXT,
 hname TEXT, cpu_model TEXT, ip TEXT);
CREATE TABLE IF NOT EXISTS env_wide(
 run_id TEXT PRIMARY KEY REFERENCES runs(key),
 %s);
CREATE TABLE IF NOT EXISTS bench(
 run_id TEXT REFERENCES runs(key), abi TEXT, grp TEXT, cname TEXT,
 rep_n INT, lat_st TEXT, lat_ns REAL, lat_sig TEXT,
 tput_st TEXT, tput_ops REAL, tput_mbs REAL, tput_sig TEXT,
 sem_st TEXT, sem_sig TEXT, sem_tag TEXT,
 kat_st TEXT, kat_det TEXT,
 diag_st TEXT, diag_v REAL, diag_u TEXT, diag_det TEXT,
 PRIMARY KEY(run_id, abi, grp, cname));
CREATE INDEX IF NOT EXISTS idx_bench_key ON bench(abi, grp, cname);
CREATE INDEX IF NOT EXISTS idx_runs_mach ON runs(mode, hname);
""" % (",\n ".join("%s TEXT" % c for c in ENV_COLS))

# 各表列类型声明(与上方 SCHEMA 同源: 新增字段须两处同步)。
# 供 connect() 版本自愈: 旧库缺列时 ALTER TABLE ADD COLUMN 补齐。
RUNS_T = {"key": "TEXT", "mode": "TEXT", "arch": "TEXT",
          "abi": "TEXT", "reps": "INT", "tsec": "REAL",
          "started_at": "TEXT", "done_note": "TEXT", "py_ver": "TEXT",
          "imported_at": "TEXT", "push_src": "TEXT",
          "warm_discards": "INT", "check_note": "TEXT",
          "hname": "TEXT", "cpu_model": "TEXT", "ip": "TEXT"}
ENV_T = dict((c, "TEXT") for c in ENV_COLS)
BENCH_T = {"abi": "TEXT", "grp": "TEXT", "cname": "TEXT", "rep_n": "INT",
           "lat_st": "TEXT", "lat_ns": "REAL", "lat_sig": "TEXT",
           "tput_st": "TEXT", "tput_ops": "REAL", "tput_mbs": "REAL",
           "tput_sig": "TEXT", "sem_st": "TEXT", "sem_sig": "TEXT",
           "sem_tag": "TEXT", "kat_st": "TEXT", "kat_det": "TEXT",
           "diag_st": "TEXT", "diag_v": "REAL", "diag_u": "TEXT",
           "diag_det": "TEXT"}
TABLES = {"runs": RUNS_T, "env_wide": ENV_T, "bench": BENCH_T}

# bench 固定列(run_id + 键 + 16 方式槽, 与 SCHEMA/INSERT 同步)
BENCH_FIX = ["run_id", "abi", "grp", "cname", "rep_n"] + WIDE_HDR[8:24]
BENCH_FIX_SET = set(BENCH_FIX)
# 探针表头中非数据列(不参与值槽)
META_COLS = {"kind", "group", "abi", "os", "bits", "tput_sec",
             "lat_iters", "case", "ok", "total"}


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
        if all(t in tabs for t in ("runs", "env_wide", "bench")):
            for tn, tdef in TABLES.items():
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
    c.executescript(SCHEMA)
    return c


def ingest(conn, runf, env_vals, benches):
    """写入一次运行(runs + env_wide 1 行 + bench 宽行, 一事务)。幂等 by key。
    env_vals: {列名: 值}。benches: [{abi,grp,cname,方式槽...,extra:{新列}}]。
    列自增: bench 行中带探针新列(extra)而库无此列时, 自动 ALTER ADD 后入库。
    返回 ok/dup。"""
    key = runf["key"]
    if conn.execute("SELECT 1 FROM runs WHERE key=?", (key,)).fetchone():
        return "dup"
    cols = [c for c in ENV_COLS if c in env_vals]
    have = {d[1] for d in conn.execute("PRAGMA table_info(bench)")}
    with conn:
        conn.execute(
            "INSERT INTO runs(key,mode,arch,abi,reps,tsec,started_at,"
            "done_note,py_ver,imported_at,push_src,warm_discards,check_note,"
            "hname,cpu_model,ip) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (key, runf.get("mode"), runf.get("arch"), runf.get("abi"),
             runf.get("reps"), runf.get("tsec"), runf.get("started_at"),
             runf.get("done_note"), runf.get("py_ver"),
             runf.get("imported_at"), runf.get("push_src"),
             runf.get("warm_discards"), runf.get("check_note"),
             runf.get("hname"), runf.get("cpu_model"), runf.get("ip")))
        conn.execute("INSERT INTO env_wide(run_id, %s) VALUES(?,%s)"
                     % (", ".join(cols), ",".join("?" * len(cols))),
                     [key] + [env_vals[c] for c in cols])
        for b in benches:
            extra = dict()
            # 自增列来源两种形态: agg 收在 b["extra"], push/SELECT * 传输在顶层
            for c2, v2 in sorted((b.get("extra") or {}).items()):
                if (re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,30}", c2)
                        and c2 not in BENCH_FIX_SET and v2 is not None):
                    extra[c2] = v2
            for c2 in sorted(b):
                if (c2 not in BENCH_FIX_SET and c2 != "extra"
                        and b.get(c2) is not None):
                    extra[c2] = b[c2]
            for c2 in sorted(extra):
                if c2 not in have:
                    conn.execute("ALTER TABLE bench ADD COLUMN %s TEXT" % c2)
                    have.add(c2)
                    eprint("== 列自增: bench 新增探针列 %s" % c2)
            ins = BENCH_FIX + sorted(extra)
            vals = [key]
            for c in ins[1:]:
                v = b.get(c)
                if v is None:
                    v = (b.get("extra") or {}).get(c)
                vals.append(v)
            conn.execute("INSERT INTO bench(%s) VALUES(%s)"
                         % (", ".join(ins), ",".join("?" * len(ins))),
                         vals)
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


def list_runs(conn, mode=None, host=None):
    q = ("SELECT key,mode,arch,abi,reps,started_at,"
         "(SELECT count(*) FROM bench WHERE run_id=runs.key),done_note,"
         "check_note,hname,cpu_model,ip FROM runs")
    w, a = [], []
    if mode:
        w.append("mode=?"); a.append(mode)
    if host:
        w.append("(hname LIKE ? OR cpu_model LIKE ?)"); a += ["%" + host + "%"] * 2
    if w:
        q += " WHERE " + " AND ".join(w)
    q += " ORDER BY started_at DESC"
    return conn.execute(q, a).fetchall()


# ---------------- 探针输出解析(26 列宽行) ----------------

def parse_seg(out):
    """解析一次 exec 的探针输出 = 单表宽 CSV:
    1 表头(26 列) + N 行 kind=T(每 case 一行, 方式做列) + 1 行 kind=D。
    版本容错: 表头缺列(旧探针)该槽按未测; 表头多列(未来探针)多余列
    忽略——协议演进只加列, 新列由新版解析器认领, 旧版不崩不丢旧语义。
    返回 (rows[], done_grp 或 None)。rows 元素含 cname 与各方式槽。"""
    rows, done = [], None
    rd = csv.reader(io.StringIO(out))
    first = next(rd, None)
    if not first or first[0].strip() != "kind":
        return rows, None
    idx = {name: i for i, name in enumerate(first)}
    for r in rd:
        if not r or not r[0]:
            continue
        k = r[idx["kind"]].strip() if idx["kind"] < len(r) else ""
        if k != "T" and k != "D":
            continue
        def f(col):
            i = idx.get(col)
            if i is None or i >= len(r):
                return None          # 表头缺该列/行被截断: 按未测
            v = r[i].strip()
            return None if v == "-" or v == "" else v
        if k == "T":
            cname = f("case") or ""
            if not cname:
                continue          # 截断/异常行(无 case 名)直接丢弃
            extra = {}            # 表头新增列(协议自增): 按列名保留
            for cn in sorted(idx):
                if cn in WIDE_HDR or cn == "kind":
                    continue
                v = f(cn)
                if v is not None:
                    extra[cn] = v
            rows.append(dict(
                abi=f("abi"), grp=f("group") or "", cname=cname,
                lat_st=f("lat_st"), lat_ns=fnum(f("lat_ns")),
                lat_sig=f("lat_sig"),
                tput_st=f("tput_st"), tput_ops=fnum(f("tput_ops")),
                tput_mbs=fnum(f("tput_mbs")), tput_sig=f("tput_sig"),
                sem_st=f("sem_st"), sem_sig=f("sem_sig"),
                sem_tag=f("sem_tag"),
                kat_st=f("kat_st"), kat_det=f("kat_det"),
                diag_st=f("diag_st"), diag_v=fnum(f("diag_v")),
                diag_u=f("diag_u"), diag_det=f("diag_det"),
                extra=extra))
        elif k == "D":
            done = f("group") or ""
    return rows, done


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


def agg_bench(rows, notes):
    """同 (abi,grp,cname) 的多 rep 宽行 -> 一行聚合。返回 bench 行 dict。"""
    b = dict(abi=rows[0]["abi"], grp=rows[0]["grp"], cname=rows[0]["cname"],
             rep_n=len(rows))
    sigs = set(r["lat_sig"] for r in rows if r["lat_sig"])
    okv = [r["lat_ns"] for r in rows if r["lat_st"] == "OK" and r["lat_ns"]]
    b["lat_st"] = agg_status([r["lat_st"] for r in rows if r["lat_st"]])
    b["lat_ns"] = median(okv)
    b["lat_sig"] = next(iter(sigs), None)
    if len(sigs) > 1:
        notes.append("sig 波动: %s lat_sig=%s" % (b["cname"], sorted(sigs)))
    if 0 < len([r for r in rows if r["lat_st"] == "OK"]) < len(rows):
        notes.append("%s: 部分 rep CRASH/异常, lat 取 OK rep 中位" % b["cname"])
    sigs = set(r["tput_sig"] for r in rows if r["tput_sig"])
    okv = [r["tput_ops"] for r in rows
           if r["tput_st"] == "OK" and r["tput_ops"]]
    b["tput_st"] = agg_status([r["tput_st"] for r in rows if r["tput_st"]])
    b["tput_ops"] = median(okv)
    mbs = [r["tput_mbs"] for r in rows
           if r["tput_st"] == "OK" and r["tput_mbs"]]
    b["tput_mbs"] = median(mbs)
    b["tput_sig"] = next(iter(sigs), None)
    if len(sigs) > 1:
        notes.append("%s tput_sig 波动" % b["cname"])
    sigs = set(r["sem_sig"] for r in rows if r["sem_sig"])
    b["sem_st"] = agg_status([r["sem_st"] for r in rows if r["sem_st"]])
    b["sem_sig"] = next(iter(sigs), None)
    b["sem_tag"] = next((r["sem_tag"] for r in rows if r["sem_tag"]), None)
    if len(sigs) > 1:
        notes.append("%s sem_sig 波动" % b["cname"])
    b["kat_st"] = agg_status([r["kat_st"] for r in rows if r["kat_st"]])
    b["kat_det"] = next((r["kat_det"] for r in rows if r["kat_det"]), None)
    b["diag_st"] = agg_status([r["diag_st"] for r in rows if r["diag_st"]])
    b["diag_u"] = next((r["diag_u"] for r in rows if r["diag_u"]), None)
    b["diag_det"] = next((r["diag_det"] for r in rows if r["diag_det"]), None)
    dv = [r["diag_v"] for r in rows if r["diag_st"] == "OK" and r["diag_v"]]
    b["diag_v"] = median(dv)
    # 未知新列(探针协议自增): 数值列取中位, 其余取首值; 波动记注记。
    # 结果统一收进 b["extra"] 字典(ingest 按列自增落库)
    keys = set()
    for r in rows:
        keys.update((r.get("extra") or {}).keys())
    if keys:
        b["extra"] = {}
    for kk in sorted(keys):
        vals = [r["extra"][kk] for r in rows
                if (r.get("extra") or {}).get(kk) is not None]
        if not vals:
            continue
        if len(set(vals)) == 1:
            b["extra"][kk] = vals[0]
            continue
        nums = [fnum(v) for v in vals]
        if all(x is not None for x in nums):
            b["extra"][kk] = "%.6g" % median(nums)
            notes.append("%s %s 波动, 取中位 %s" % (b["cname"], kk,
                                                     b["extra"][kk]))
        else:
            b["extra"][kk] = vals[0]
            notes.append("%s %s 波动, 取首值 %s" % (b["cname"], kk, vals[0]))
    return b


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


def execp(cmd, timeout, env=None):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout, env=env)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode("utf-8", "replace") if e.stdout else ""
        return 124, out
    except OSError as e:
        return 126, "exec error: %s\n" % e


def probe_exec(binp, prefix, args, timeout, env=None):
    """执行探针一次。返回 (rc, stdout)。产物缺失 rc=-1。"""
    if not os.path.isfile(binp):
        return -1, ""
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
        args += ["--no-tput", "--time", "0.2"]
    probe_exec(binp, prefix, args, timeout, env=env)
    return 1


def consistency_check(conn, runf, benches):
    """与本机(同 hname+cpu_model)最近一次 run 对拍哨兵指令 lat 列。
    返回 check_note。"""
    prev = conn.execute(
        "SELECT key FROM runs WHERE hname=? AND cpu_model=? AND key<>? "
        "ORDER BY started_at DESC LIMIT 1",
        (runf.get("hname"), runf.get("cpu_model"), runf["key"])).fetchone()
    if not prev:
        return "no-prev"
    pk = prev[0]
    notes = []
    for g, c in CHECK_SENT:
        for abi in ("x86_64", "i386"):
            def lat_of(run_id):
                r = conn.execute(
                    "SELECT lat_ns FROM bench WHERE run_id=? AND abi=? AND "
                    "grp=? AND cname=? AND lat_st='OK' AND lat_ns IS NOT NULL",
                    (run_id, abi, g, c)).fetchone()
                return r[0] if r else None
            a, b = lat_of(runf["key"]), lat_of(pk)
            if a is None or b is None or b == 0:
                continue
            r = a / b
            if r < 1 - CHECK_TOL or r > 1 + CHECK_TOL:
                notes.append("%s_%s %.0f%%" % (abi, c, r * 100))
    if not notes:
        return "consistent"
    return "MISMATCH(%s)" % ";".join(notes)


# ---------------- run ----------------

def do_run(args):
    if sys.platform.startswith("win"):
        eprint("run 需在 Linux 主机执行")
        sys.exit(2)
    mode = args.mode
    groups = args.groups or list(GROUPS)
    abi = args.abi or "all"
    if abi not in ("x86_64", "i386", "all"):
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
    ev["run_tsec"] = "%g" % tsec
    ev["run_only"] = args.only or "-"
    ts = datetime.datetime.now()
    key = build_key(mode, run_m["arch"], run_m["cpu_model"], run_m["ip"], ts)
    print("== run key: %s" % key)

    # native i386 探测(整轮开关)
    i386_ok = True
    if mode == "native" and abi != "x86_64":
        rc, _ = probe_exec(os.path.join(BIN, "timer_i386_linux"), [], [], 15)
        i386_ok = rc == 0

    is_loong = os.uname().machine == "loongarch64"
    wcmd = os.environ.get("WINE") or ""
    if not wcmd:
        wcmd = _sh("command -v kylin-wine 2>/dev/null") or \
               _sh("command -v wine 2>/dev/null")
    env0 = dict(os.environ)
    abi_list = ["x86_64", "i386"] if abi == "all" else [abi]
    agg_rows, notes, dones = [], [], []
    warm_n = 0

    for g in groups:
        for a in abi_list:
            if mode in ("native", "latx"):
                binp = os.path.join(BIN, "%s_%s_linux" % (g, a))
                env = None
            else:
                binp = os.path.join(BIN, "%s_%s_windows.exe" % (g, a))
                env = env0
            prefix = []
            if mode == "wine" and wcmd:
                prefix = [wcmd]
                env = dict(env0)
                env["WINEDEBUG"] = "-all"
            elif mode == "latx" and not is_loong:
                tr = os.environ.get("LATX64" if a == "x86_64" else "LATX32")
                if tr:
                    prefix = [tr] + shlex.split(os.environ.get("LATX_OPTS", ""))
            need_latx_tr = (mode == "latx" and not is_loong
                            and not os.environ.get(
                                "LATX64" if a == "x86_64" else "LATX32"))
            if need_latx_tr:
                notes.append("SKIP: %s_%s 需在 loongarch64 或设 LATX64/LATX32"
                             % (g, a))
                continue
            if mode == "native" and a == "i386" and not i386_ok:
                notes.append("SKIP: %s_%s native i386 不可执行(无 ia32)"
                             % (g, a))
                continue
            if mode == "wine" and not wcmd:
                notes.append("SKIP: %s_%s 无 wine/kylin-wine" % (g, a))
                continue
            if args.warm:
                if mode == "wine":
                    killw()
                run_warm(binp, prefix, g, tsec, timeout, env)
                warm_n += 1
            # 多 rep: 每次 exec 单独解析, 同 cname 归并聚合(入库一行)
            raw = {}
            for r in range(1, reps + 1):
                if mode == "wine":
                    killw()
                rc, out = probe_exec(binp, prefix,
                                     ["--time", str(tsec)] + only_arg,
                                     timeout, env=env)
                if rc == -1:
                    notes.append("SKIP: %s_%s 缺产物" % (g, a))
                    continue
                if rc == 124:
                    notes.append("TIMEOUT(%ds): %s_%s" % (timeout, g, a))
                    continue
                if rc != 0:
                    notes.append("EXIT(%d): %s_%s" % (rc, g, a))
                    continue
                rows, done = parse_seg(out)
                if not rows and done is None:
                    notes.append("输出无 T/D: %s_%s (rc=%d, %d 字节)"
                                 % (g, a, rc, len(out)))
                    continue
                if done:
                    dones.append(done)
                else:
                    notes.append("缺 D 行: %s_%s" % (g, a))
                for row in rows:
                    raw.setdefault((row["abi"], row["cname"]), []).append(row)
            for kk, rrs in raw.items():
                agg_rows.append(agg_bench(rrs, notes))
    if not i386_ok and mode == "native" and abi != "x86_64":
        notes.append("i386 探测不可执行(内核无 IA32_EMULATION), 本场整轮 SKIP")
    done_note = "# DONE 哨兵: 期望[%s] 实得[%s]" % (
        " ".join(sorted(set(groups))), " ".join(sorted(set(dones))))
    ev["probe_notes"] = "\n".join("# %s" % n for n in notes) if notes else "-"

    runf = dict(key=key, mode=mode, arch=run_m["arch"], abi=abi, reps=reps,
                tsec=tsec, started_at=ts.isoformat(timespec="seconds"),
                py_ver=platform.python_version(),
                imported_at=datetime.datetime.now()
                .isoformat(timespec="seconds"),
                warm_discards=warm_n, hname=run_m["hname"],
                cpu_model=run_m["cpu_model"], ip=run_m["ip"],
                done_note=done_note)
    st = ingest(conn, runf, ev, agg_rows)
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


def build_key(mode, arch, cpu_model, ip, ts):
    def slug(s, n=40):
        s = re.sub(r"[^A-Za-z0-9._-]", "_", s or "unknown")
        return s[:n] or "unknowncpu"
    return "%s_%s_%s_%s_%s" % (mode, arch, slug(cpu_model), slug(ip, 24),
                               ts.strftime("%Y%m%d-%H%M%S"))


# ---------------- compare ----------------

def load_run_bench(conn, key):
    out = conn.execute(
        "SELECT abi,grp,cname,lat_st,lat_ns,lat_sig,tput_st,tput_ops,"
        "tput_sig,sem_st,sem_sig,kat_st,diag_st FROM bench WHERE run_id=?",
        (key,)).fetchall()
    return [dict(abi=r[0], grp=r[1], cname=r[2], lat_st=r[3], lat_ns=r[4],
                 lat_sig=r[5], tput_st=r[6], tput_ops=r[7], tput_sig=r[8],
                 sem_st=r[9], sem_sig=r[10], kat_st=r[11], diag_st=r[12])
            for r in out]


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
    ti = {b["cname"]: b for b in load_run_bench(conn, ta)}
    ri = {b["cname"]: b for b in load_run_bench(conn, ra)}
    # 逐方式对拍(lat/tput/sem/kat/diag 各自成一行明细)
    ways = [("lat", "lat_st", "lat_ns", "lat_sig"),
            ("tput", "tput_st", "tput_ops", "tput_sig"),
            ("sem", "sem_st", None, "sem_sig"),
            ("kat", "kat_st", None, None),
            ("diag", "diag_st", None, None)]
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
            for wname, _, _, _ in ways:
                t = ti[k]
                if t[ways_st(wname)]:
                    print("%-6s %-6s %-20s %-5s %-10s %s" % (
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
            print("%-6s %-6s %-20s %-5s %-10s %-9s %8.1f%% %s"
                  % (abi, g, k[1], wname, st, sf, rat, why))
            n += 1
            if st == "DEVIATION":
                dev += 1
    print("== 汇总: 对拍 %d 方式行, DEVIATION %d, run 侧多余 %d, "
          "truth 侧缺失 %d" % (n, dev, miss_r, miss_t))
    sys.exit(1 if (dev > 0 or miss_t > 0) else 0)


def ways_st(wname):
    return {"lat": "lat_st", "tput": "tput_st", "sem": "sem_st",
            "kat": "kat_st", "diag": "diag_st"}[wname]


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
    cur = conn.execute("SELECT * FROM bench WHERE run_id=? ORDER BY grp,cname",
                       (key,))
    bcols = [d[0] for d in cur.description]
    bench = [dict(zip(bcols, r)) for r in cur.fetchall()]
    payload = dict(run=runf, env=evd, bench=bench,
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
        conn.close()
        self._reply(200, dict(status=st, run=runf["key"],
                              rows=len(bench)))

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
    print("%-4s %-58s %-5s %-6s %-4s %-19s %-6s %s"
          % ("id", "key", "mode", "abi", "rep", "started", "rows", "check"))
    for i, r in enumerate(rows, 1):
        note = r[8] or ""
        if note.startswith("MISMATCH"):
            note = "!! " + note
        print("%-4d %-58s %-5s %-6s %-4s %-19s %-6d %s"
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
    print("-- bench 分布 --")
    for r in conn.execute(
            "SELECT abi,count(*),sum(rep_n) FROM bench WHERE run_id=? "
            "GROUP BY abi", (key,)):
        print("  %-6s %d 指令(聚合 rep_n=%d)" % (r[0], r[1], r[2]))


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
    """导出宽表 CSV: 表头 = 26 列协议 + 本 run 的自增列, xlsx 直接导入。"""
    conn = connect(args.db)
    key = resolve_key(conn, args.run)
    if not key:
        sys.exit(2)
    runf = fetch_run(conn, key)
    cur = conn.execute("SELECT * FROM bench WHERE run_id=? "
                       "ORDER BY grp,cname", (key,))
    pcols = [d[0] for d in cur.description]
    rows = cur.fetchall()
    extras = [c for c in pcols if c not in BENCH_FIX_SET]
    hdr = WIDE_HDR + extras
    osn = "windows" if runf.get("mode") == "wine" else "linux"
    bits = "32" if runf.get("abi") == "i386" or \
        runf.get("arch") == "i386" else "64"
    tsec = "%g" % (runf.get("tsec") or 0)
    dash = "-"
    w = csv.writer(sys.stdout)
    w.writerow(hdr)
    for r in rows:
        d = dict(zip(pcols, r))
        base = ["T", d["grp"], d["abi"], osn, bits, tsec, dash, d["cname"]]
        for c in WIDE_HDR[8:24]:          # 16 方式槽
            v = d.get(c)
            base.append(dash if v is None else v)
        base += [dash, dash]              # ok/total
        for c in extras:                  # 自增列(含 NULL -> '-')
            v = d.get(c)
            base.append(dash if v is None else v)
        w.writerow(base)
    eprint("# rows=%d (run %s)" % (len(rows), key))


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
    p.add_argument("--abi", choices=["x86_64", "i386", "all"], default="all")
    p.add_argument("--reps", type=int, default=1,
                   help="每 (组,abi) 执行轮数, 入库聚合一行(中位)")
    p.add_argument("--time", type=float, default=0.5, dest="time")
    p.add_argument("--only", default="")
    p.add_argument("--push", default="", help="完成后推送 URL")
    p.add_argument("--warm", type=int, default=1, help="预热丢弃(默认 1)")
    p.add_argument("--check", type=int, default=1, help="一致性自校验(默认 1)")
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
