#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""isbench.py -- 面向 LAT 翻译器的 x86 指令形态跨环境基准(py3 单入口, sqlite3 宽表入库)

宽表模型: 测试对象是指令(case)。单指令链(lat)/定时长(tput)/语义(sem)/
kat/diag 都是同一指令的测试方式, 在探针输出、库、导出三处都表现为
「一 (架构, 指令) 一行, 方式做列」; reps 多轮聚合为一行(数值取中位)。

子命令: run(native/latx/wine) / compare / ls / show / env-diff / export /
serve / push。探针 stdout 直接解析入库, 不生成 txt; 数据库为唯一产物
(默认 results/isbench.db, 单文件可拷可备份), 支持多台机器数据同库。

依赖: python3 >= 3.6, 仅标准库。数据层(model/db)、环境采集(model/env)与领域常量
(model/__init__)在 app/model/ 包(装配到 dist/app/model/); 本文件保留主逻辑
(CLI/子命令执行/探针输出解析与聚合)。README.md 与 docs/ 见详细说明。
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

# 定位 model 包: dist 布局在 <DIR>/app/model, 源码布局在 <DIR>/model。
for _p in (os.path.join(DIR, "app"), DIR):
    if os.path.isdir(os.path.join(_p, "model")):
        if _p not in sys.path:
            sys.path.insert(0, _p)
        break

from model import GROUPS, grp_ident, ALL_FORMS, form_abi, form_os, fnum, eprint   # noqa: E402
from model.db import (                                                # noqa: E402
    connect, ingest, ingest_openssl_metrics, ingest_func, ingest_debug,
    debug_summary, fetch_run, resolve_key, list_runs, schema_guard,
    load_run_bench, load_tbl_rows, _last_key, existing_tables, table_cols,
    bench_table, verify_table, debug_table, BENCH_TABLES, VERIFY_TABLES,
    DEBUG_TABLES, OPENSSL_FIX)
from model.env import env_collect, _sh                                 # noqa: E402


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

def parse_openssl(out):
    """解析 openssl 探针 stdout(3 行): '# openssl_ver=...' 注释 / 表头(纯度量列名
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


def agg_openssl(rows):
    """多 rep openssl 行(dict 列->值)聚合为一行: 数值列取有效 rep 中位,
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
        # 只查本场**实际入库**的 abi(直接问库, 不再查组级白名单): 拿一个没跑过的
        # abi 去查 lat 会命中下面的 `continue` = 静默落空(就是 mov/alu/logic 踩过的那个坑)。
        for abi in [r[0] for r in conn.execute(
                "SELECT DISTINCT abi FROM %s WHERE run_id=?" % tn,
                (runf["key"],))]:
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
    # 形态 = "<abi>_<os>": mode 定 os 维(只 windows 跑 .exe, 其余跑 _linux ELF),
    # --abi 定 abi 维。遍历 ALL_FORMS 全集, 不在位者由下方产物判据静默跳过。
    want_os = "windows" if mode == "windows" else "linux"
    forms = [f for f in ALL_FORMS if form_os(f) == want_os]
    if abi != "all":
        forms = [f for f in forms if form_abi(f) == abi]
    agg_rows, notes, dones = [], [], []
    v_rows, f_rows = [], []   # 详细明细行(dbg) / 功能结果行(func)
    dbg_arg = ["--debug"] if getattr(args, "debug", False) else []

    for g in groups:
        # 形态 = 路径组合 + 在位判据: 这组不出某个形态就少跑一个, 不需任何组级
        # 白名单(给某组加/减形态只改 build.sh 的 GRP_FORMS_<grp>, py 侧零改动)。
        sfx = ".exe" if want_os == "windows" else ""
        hits = [f for f in forms
                if os.path.isfile(os.path.join(BIN, g + "-" + f + sfx))]
        # 但"整组一个都不在位"必须留痕: 否则 BIN 指错/忘了构建时会静默 0 入库
        # (旧实现靠 probe_exec 的 缺产物 告警暴露, 不能把它一并丢掉)。
        if not hits:
            notes.append("注: %s 无 %s 形态产物(bin=%s), 本场不参与" % (g, want_os, BIN))
            continue
        for frm in hits:
            a = form_abi(frm)
            # 产物名 = <grp>-<form>(windows 形态带 .exe), 与 build.sh 的命名契约同形。
            binp = os.path.join(BIN, g + "-" + frm + sfx)
            # loongarch64 原生二进制只能在 loongarch64 机上跑(非 x86 主机直执
            # 行会 Exec format error); 非本机时静默跳过, 不当缺件告警。
            if a == "loongarch64" and not is_loong:
                continue
            env = env0 if want_os == "windows" else None
            prefix = []
            if mode in ("wine", "windows") and wcmd:
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
            if mode in ("wine", "windows") and not wcmd:
                notes.append("SKIP: %s-%s 无 wine/kylin-wine" % (g, a))
                continue
            # 多 rep: 每次 exec 单独解析, 同身份列归并聚合(入库一行)
            ident = grp_ident(g)
            raw = {}
            for r in range(1, reps + 1):
                if mode in ("wine", "windows"):
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
                warm_discards=0, hname=run_m["hname"],
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


def do_openssl(args):
    """独立 openssl 测速探针(src/openssl/isb_openssl.c, 与指令探针分离编译):
    每 (mode,abi) 一个 run key, reps 聚合为一行入 openssl 表(列 = 算法_尺寸);
    runs/env_wide 复用现有 ingest(空 bench)。不参与哨兵/compare。
    --ver 11 = 测 1.1.1w(openssl11_* 二进制), 与 3.x 同 openssl 表按 openssl_ver 共存。"""
    if sys.platform.startswith("win"):
        eprint("openssl 需在 Linux 主机执行")
        sys.exit(2)
    mode = args.mode
    # --link: static(默认, 原名静态探针) / dynamic(_dy 动态探针, 载 dist/lib 共享 libcrypto)
    lsfx = "_dy" if getattr(args, "link", "static") == "dynamic" else ""
    reps = args.reps or 1
    tsec = args.time
    timeout = int(os.environ.get("TIMEOUT", "900"))
    os.makedirs(RES, exist_ok=True)
    conn = connect(args.db)
    # --ver 11 = openssl 1.1.1w(openssl11_* 二进制), 3 = 3.x(openssl_*): 同 openssl 表
    # openssl_ver 列分版本; 1.1.1 无 sm4-gcm, 探针动态枚举自动少该组列
    lib = "11" if getattr(args, "ver", 3) == 11 else "3"
    mpre = "openssl11-" if lib == "11" else "openssl-"
    bsuf = "build/build-openssl11.sh" if lib == "11" else "build/build-openssl.sh"
    abi_list = ["x64", "i386"] if args.abi == "all" else [args.abi]
    is_loong = os.uname().machine == "loongarch64"
    wcmd = os.environ.get("WINE") or ""
    if not wcmd:
        wcmd = _sh("command -v kylin-wine 2>/dev/null") or \
               _sh("command -v wine 2>/dev/null")
    for a in abi_list:
        # mode 定 os 形态: wine 跑 _windows[_dy].exe, native/latx 跑 _linux[_dy]
        if mode == "wine":
            binp = os.path.join(BIN, "%s%s_windows%s.exe" % (mpre, a, lsfx))
        else:
            binp = os.path.join(BIN, "%s%s_linux%s" % (mpre, a, lsfx))
        if not os.path.isfile(binp):
            eprint("SKIP: %s 缺产物(先跑 %s %s)"
                   % (binp, bsuf, "dynamic" if lsfx else "static"))
            continue
        prefix = []
        env = None
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
            if not wcmd:
                eprint("SKIP: wine %s 无 wine/kylin-wine" % a)
                continue
            prefix = [wcmd]
            env = dict(os.environ)
            env["WINEDEBUG"] = "-all"
        ev, run_m = env_collect(mode)
        ts = datetime.datetime.now()
        # key 不带 abi(openssl 表已有 abi 列); abi 循环内 ts 逐次重取, 天然区分两形态
        key = build_key(mpre + mode, run_m["arch"], run_m["cpu_model"],
                        run_m["ip"], ts)
        print("== openssl run key: %s" % key)
        ev["run_reps"] = str(reps)
        ev["run_tput_ms"] = "%d" % tsec
        ev["run_only"] = "openssl11" if lib == "11" else "openssl"
        notes = []
        raw = []
        for _ in range(reps):
            if mode == "wine":
                killw()
            rc, out, err = probe_exec(binp, prefix, ["--time", str(tsec)],
                                      timeout, env=env)
            if rc != 0:
                notes.append("EXIT(%d): %s%s"
                             % (rc, os.path.basename(binp),
                                " [%s]" % err if err else ""))
                continue
            d, ver = parse_openssl(out)
            if d is None:
                notes.append("输出结构异常: %s" % os.path.basename(binp))
                continue
            raw.append((d, ver))
        if not raw:
            eprint("SKIP: %s 无有效输出" % os.path.basename(binp))
            continue
        agg = agg_openssl([d for d, _ in raw])
        ver = raw[0][1]
        runf = dict(key=key, mode="openssl-" + mode, arch=run_m["arch"], abi=a,
                    reps=reps, tsec=tsec,
                    started_at=ts.isoformat(timespec="seconds"),
                    py_ver=platform.python_version(),
                    imported_at=datetime.datetime.now()
                    .isoformat(timespec="seconds"),
                    warm_discards=0,
                    hname=run_m["hname"], cpu_model=run_m["cpu_model"],
                    ip=run_m["ip"], done_note="")
        st = ingest(conn, runf, ev, [])
        row = dict(run_id=key, abi=a,
                   os="windows" if mode == "wine" else "linux",
                   bits=64 if a == "x64" else 32, tsec=tsec,
                   openssl_ver=ver)
        row.update(agg)
        st2 = ingest_openssl_metrics(conn, row)
        print("== 入库: runs=%s openssl=%s (%d 度量列) db=%s"
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
    # openssl 行(run 可能为 openssl 探针 run; 普通 bench run 无此行 -> payload 里 None)
    orow = conn.execute("SELECT * FROM openssl WHERE run_id=?",
                        (key,)).fetchone()
    ocols = [d[0] for d in conn.execute("SELECT * FROM openssl").description]
    openssl = dict(zip(ocols, orow)) if orow else None
    # 功能表(verify_<grp>)与详细表(debug_<grp>)也一并推送: 只带计时行会让中心库
    # 拿到"跑了 N 个 case"却拿不到"哪个功能判负 / 哪一组输入错在哪个字段"。
    # 空则不带键(两向兼容): 老客户端不送 -> 服务端缺省不写。
    frows = load_tbl_rows(conn, VERIFY_TABLES, key)
    vrows = load_tbl_rows(conn, DEBUG_TABLES, key)
    payload = dict(run=runf, env=evd, bench=bench, openssl=openssl,
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
        # openssl run 载荷: 行 dict 含全部列(固定 + 度量), 幂等 OR REPLACE by run_id
        openssl = payload.get("openssl")
        if isinstance(openssl, dict) and openssl.get("run_id"):
            ingest_openssl_metrics(conn, openssl)
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
    print("-- openssl(openssl 探针, 每 run 一行, 列=算法_尺寸) --")
    row = conn.execute("SELECT * FROM openssl WHERE run_id=?",
                       (key,)).fetchone()
    if row:
        cols = [d[0] for d in conn.execute("SELECT * FROM openssl").description]
        od = dict(zip(cols, row))
        met = [(c, v) for c, v in od.items()
               if c not in OPENSSL_FIX and v not in (None, "")]
        print("  固定: abi=%s os=%s bits=%s tsec=%s openssl_ver=%s"
              % (od.get("abi"), od.get("os"), od.get("bits"),
                 od.get("tsec"), (od.get("openssl_ver") or "")[:40]))
        print("  度量列 %d 非空/%d: %s%s" % (
            len(met), sum(1 for c in cols if c not in OPENSSL_FIX),
            ", ".join("%s=%s" % (c, v) for c, v in met[:6]),
            " ..." if len(met) > 6 else ""))
    else:
        print("  (本 run 非 openssl)")


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
    if (runf.get("mode") or "").startswith(("openssl-", "openssl11-")):
        export_openssl(conn, key)
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


def export_openssl(conn, key):
    """openssl run 导出: 该行宽 CSV(表头 = 库实列序, 去 run_id), 每 run 1 行。"""
    row = conn.execute("SELECT * FROM openssl WHERE run_id=?",
                       (key,)).fetchone()
    if not row:
        eprint("# openssl: run %s 无 openssl 行" % key)
        return
    cols = [d[0] for d in conn.execute("SELECT * FROM openssl").description]
    pcols = [c for c in cols if c != "run_id"]
    w = csv.writer(sys.stdout)
    w.writerow(pcols)
    w.writerow(["-" if row[cols.index(c)] is None else row[cols.index(c)]
                for c in pcols])
    eprint("# rows=1 (openssl run %s)" % key)

# ---------------- CLI ----------------

def build_parser():
    ap = argparse.ArgumentParser(prog="isbench.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")

    def add_db(p, help="库文件(默认 %s)" % DEF_DB):
        p.add_argument("--db", default=DEF_DB, help=help)

    p = sub.add_parser("run", help="执行一轮测试并入库(宽表: 一指令一行)")
    p.add_argument("mode", choices=["native", "latx", "wine", "windows"],
                   help="native=直跑 _linux ELF; latx=套 LATX 翻译器跑 _linux ELF; "
                        "wine=经 wine 加载 _linux ELF; windows=经 wine 跑 mingw 的 "
                        "_windows.exe(Windows 运行时侧对照)")
    p.add_argument("groups", nargs="*",
                   help="组(默认全部: %s)" % " ".join(GROUPS))
    # --abi 只是形态 abi 维的过滤器; "这组有没有这个形态"由产物在位决定, 不在此登记。
    p.add_argument("--abi",
                   choices=["x64", "i386", "loongarch64", "all"], default="all")
    p.add_argument("--reps", type=int, default=1,
                   help="每 (组,abi) 执行轮数, 入库聚合一行(中位)")
    p.add_argument("--time", type=int, default=100, dest="time",
                   help="探针内计时窗口毫秒(默认 100)")
    p.add_argument("--only", default="")
    p.add_argument("--push", default="", help="完成后推送 URL")
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

    p = sub.add_parser("openssl",
                       help="独立 openssl 测速探针(openssl 表, 列=算法_尺寸; 3.x/1.1.1 共存)")
    p.add_argument("mode", choices=["native", "latx", "wine"])
    p.add_argument("--ver", type=int, choices=[3, 11], default=3,
                   help="被测 libcrypto 主版本: 3=3.x(openssl-*), 11=1.1.1w(openssl11-*; "
                        "同表 openssl_ver 列分版本)")
    p.add_argument("--abi", choices=["x64", "i386", "all"], default="all",
                   help="形态(默认 all: x64+i386 各一 run)")
    p.add_argument("--link", choices=["static", "dynamic"], default="static",
                   help="链法: static=原名静态探针, dynamic=_dy 动态探针(载 dist/lib 共享库)")
    p.add_argument("--reps", type=int, default=1,
                   help="每 (mode,abi) 执行轮数, 数值列取中位聚合一行")
    p.add_argument("--time", type=int, default=100, dest="time",
                   help="探针内每(算法,尺寸)计时窗口毫秒(默认 100; 约 20 算法x6 尺寸)")
    p.add_argument("--push", default="", help="完成后推送 URL")
    add_db(p)
    p.set_defaults(fn=do_openssl)
    return ap

def main():
    if len(sys.argv) < 2:
        build_parser().print_help()
        sys.exit(1)
    ap = build_parser()
    args = ap.parse_args()
    if not getattr(args, "fn", None):
        ap.print_help()
        sys.exit(1)
    schema_guard()
    args.fn(args)


if __name__ == "__main__":
    main()
