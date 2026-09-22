"""isbench 领域模型: 组清单 / 固定形态全集 / 断言身份 (db、env 与主入口共享)。

包自定位: 本包(<运行根>/app/model)在 src 树与 dist 树均能定位到运行根:
  PKG_DIR = <运行根>/app/model; AUX = dirname(PKG_DIR) = <运行根>/app; DIR = dirname(AUX)。
"""
import os
import sys

PKG_DIR = os.path.dirname(os.path.abspath(__file__))
AUX = os.path.dirname(PKG_DIR)          # <运行根>/app(附属数据: sql/)
DIR = os.path.dirname(AUX)              # 运行根(isbench.py 所在层)


# 组清单 = 产物名 = grp 列值(一可执行恰好一个含 ib.h 的 TU)。拆分维度 = LATX
# 成本结构 + 风险隔离(栈类/串类/原子类各自成组, 一崩不拖全族), 详见 docs/设计/分组与命名.md。
GROUPS = ["scalar", "sse", "avx", "crypto", "cpuid", "timer",
          "mov", "alu", "logic", "flag", "shift", "cc", "ctrl", "bits",
          "special", "vec", "x87", "pmul", "cfloat", "cint", "sfloat"]
# 固定形态全集 = "<abi>_<os>"(与 build.sh 的 ALL_FORMS ∪ 各 GRP_FORMS_<grp> 同集)。
# run 与一致性自校验**不再按组维护 ABI 白名单**: 而是枚举本 mode 对应的全部形态,
# 以"dist/bin 里产物是否在位"为唯一判据 —— 于是给某组加/减形态只需改 build.sh 的
# GRP_FORMS_<grp>(单一来源), py 侧零改动。
# 注: x87 只 i386 的护栏**不在这里** —— 在 isb_x87.c 顶部 #error 与 build.sh 的
# GRP_32ONLY(实测拿 x64 编一份 x87 探针它跑得通还与 i386 逐字一致, 运行期看不出来)。
ALL_FORMS = ("x64_linux", "i386_linux", "loongarch64_linux",
             "x64_windows", "i386_windows")
# 身份列全组统一 cname: pmul 的用例身份 = "<实现>/<档族>"(如 hw/bit), 由探针打成一个
# cname 单元 —— 不再为 pmul 单开 (impl,family) 二维键。三族表主键都是
# (run_id, abi, grp, cname): bench_<grp> 性能 / verify_<grp> 功能 / debug_<grp> 详细。
def grp_ident(grp):
    """用例身份列(决定三族表主键与多 rep 聚合键): 全组统一 cname。"""
    return ("cname",)

def fnum(s):
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


def form_abi(form):
    """form "<abi>_<os>" -> abi(如 i386_windows -> i386)。"""
    return form.rsplit("_", 1)[0]


def form_os(form):
    """form "<abi>_<os>" -> os(如 i386_windows -> windows)。"""
    return form.rsplit("_", 1)[1]


def eprint(*a):
    print(*a, file=sys.stderr)
