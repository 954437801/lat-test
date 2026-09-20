"""isbench 环境采集(Linux): /proc 与 /sys 读数、LATX 翻译器指纹、运行机器列。

只读采集、全程容错; 供主入口 do_run/do_openssl 组装 env_wide 行。
运行根 DIR 取自 model 包(定位 SHA256SUMS 等)。
"""
import datetime
import os
import re
import subprocess

from model import DIR


LATX_FIXED = ["LATX64", "LATX32", "LATX_OPTS", "LATX_AOT", "LATX_VPAES",
              "LATX_SOFFPU", "LATX_DEBUG_AOT"]

def _read(path):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return ""

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
