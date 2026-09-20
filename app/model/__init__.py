"""isbench 领域模型: 组清单 / ABI 在册范围 / 断言身份 (db、env 与主入口共享)。

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
# 组的 ABI 在册范围(与 build.sh 的 GRP_32ONLY / GRP_FORMS 同集): 缺省两 ABI 都在, 未列就按全集。
# x87 是唯一例外 —— 只有 -m32 的编译器会发射 x87 整型搬运, 给 x64 造 x87
# 探针是测一条不存在的路径; 而实测(见 src/x87/isb_x87.c 取证 6)它编得出、跑得通、还
# 与 i386 逐字一致 => 运行期根本看不出不妥, 只能在登记层就限死。
# cfloat/cint/sfloat 是三形态组: x64/i386 为 x86-under-LATX 对照, loongarch64 为原生基线。
GRP_ABIS = {"x87": ("i386",), "cfloat": ("x64", "i386", "loongarch64"),
            "cint": ("x64", "i386", "loongarch64"),
            "sfloat": ("x64", "i386", "loongarch64")}
ALL_ABIS = ("x64", "i386")
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


def abi_scope(grp):
    """grp 在哪些 ABI 在册(不在册的形态既不构建也不跑也不自校验)。"""
    return GRP_ABIS.get(grp, ALL_ABIS)

def eprint(*a):
    print(*a, file=sys.stderr)
