#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kat_audit.py —— KAT 真值表的语义审计(与采集端 C 代码完全独立的第二实现)

为什么需要: gen_val.sh 只证明「表能回填、本机第二次跑能对上」, 这不等于表是对的
—— 若探针本身写错(例如把 imul 三操作数的 dst 当成输入), 采到的"错真值"照样自洽。
这里用 Python 按 Intel SDM 的算术定义从 {i0,i1,inf} 反算, 与表里的值逐项比,
相当于给真值表做一次独立复核。

只比 expect() 明确给出的字段(返回 dict): 未列出的字段视作"本条不审", 不参与
判定 —— 因为 mul/imul 的 SF/ZF/PF/AF、div/idiv 的全部标志在架构上就是未定义,
拿它们报警反而是假报(探针那边也已经按 IB_FLG_MASK_CFOF / outf=0 上的表)。

分派按**表文件**不按词干: 组名从路径 isb_<grp>_kat.h 里取。同一个词干可以在两张
表里都出现(x87 组收了 special 迁走的 6 条而旧表还残留着它们), 只按词干分派就会
把 special 表里的 stale 行交给 x87 的实现去审(没人报警) —— 看上去仍是 8/8 通过。

用法: python3 kat_audit.py <src/<grp>/isb_<grp>_kat.h>
"""
import os
import re
import struct
import sys
from fractions import Fraction

SUF_W = {"b": 8, "w": 16, "l": 32, "q": 64}


def width_of(stem):
    """形态后缀 _b/_w/_l/_q -> 位宽(与组文件传给探针的 SUF 一致)"""
    m = re.search(r"_(b|w|l|q)(_|$)", stem)
    return SUF_W[m.group(1)] if m else 64


def parity8(x):
    """PF = 结果低 8 位中 1 的个数为偶 -> 1"""
    return 1 if bin(x & 0xFF).count("1") % 2 == 0 else 0


def sgn(x, w):
    """按 w 位当有符号数看 -> 真值。必须先截到 w 位再减 2^w:
    直接 `x - (1 << w)` 是个坑 —— 只对 x 本来就在 w 位内的调用者偶然正确,
    而符号扩展族(cltq/cwtl)拿到的 i0 是全宽的寄存器入值, 高位必须丢。
    (实测: 搬运族首采就是这个形状报出不符, 而表里的值才是架构对的)"""
    v = x & ((1 << w) - 1)
    return v - (1 << w) if v >> (w - 1) else v


def alu(res, w, cf, of, af):
    """按 IB_FLG_MASK(=0x8d5: CF0 PF2 AF4 ZF6 SF7 OF11) 组装标志"""
    res &= (1 << w) - 1
    return {
        "CF": cf & 1, "PF": parity8(res), "AF": af & 1,
        "ZF": 1 if res == 0 else 0, "SF": (res >> (w - 1)) & 1, "OF": of & 1,
    }


def add_sub(a, b, c_in, w, sub):
    """add/adc/inc 与 sub/sbb/dec 的公共算式(直接照 SDM 的定义写)
    AF = 低 4 位之间的半进位/半借位: 只能按定义算 —— 常见的
    ((a^b^res)>>3)&1 是错的(实测位号应为 4, 且立即数形态还会连 c_in 一路算,
    不如老老实实拿低半字节做加减"""
    mask = (1 << w) - 1
    lo_a, lo_b = a & 0xF, b & 0xF
    if sub:
        t = a - b - c_in
        cf = 1 if t < 0 else 0
        af = 1 if (lo_a - lo_b - c_in) < 0 else 0
        res = t & mask
        of = ((a ^ b) & (a ^ res)) >> (w - 1) & 1
    else:
        t = a + b + c_in
        cf = (t >> w) & 1
        af = ((lo_a + lo_b + c_in) >> 4) & 1
        res = t & mask
        of = ((a ^ res) & (b ^ res)) >> (w - 1) & 1
    return res, res, alu(res, w, cf, of, af)


def sides(stem, i0, i1, imm):
    """形态段 -> (dst 侧值, src 侧值)。stem 段序 = Intel 操作数序(dst, src),
    而探针只有两个值载体: 寄存器 %[a] = i0, 内存/栈槽 = 整窗广播的 i1。所以:
      r_*  -> dst = %[a] = i0         m_*  -> dst = 内存 = i1
      dst=r 时 src=r/m -> src = %[b] = i1;  src=i -> imm
      dst=m 时 src=r -> src = %[a] = i0 (只有一个寄存器操作数, 就是 a)
    例外: d1==d2=='m' 的是 IB_KT_SOM(inc/dec 内存自增), 它预置进内存的是 i0。
    div/idiv 不用 lhs(被除数隐式在 rax), 只拿 src 当除数。
    """
    p = stem.split("_")
    d1, d2 = p[1], (p[2] if len(p) > 2 else "")
    if d1 == "m":
        lhs, rhs = i1, (imm if d2 == "i" else i0)
        if d2 == "m":
            lhs = i0                      # IB_KT_SOM
    else:
        lhs, rhs = i0, (imm if d2 == "i" else i1)
    return lhs, rhs


def flags_of_inf(inf):
    """「不影响标志」类形态(not / BMI2 移位)的期望集: 六个位全等于注入值"""
    return {"CF": inf & 1, "PF": (inf >> 2) & 1, "AF": (inf >> 4) & 1,
            "ZF": (inf >> 6) & 1, "SF": (inf >> 7) & 1, "OF": (inf >> 11) & 1}


# 标志位 -> 在 EFLAGS 字里的位移(与 ib.h 的 IB_FLG_MASK=0x8d5 同一张表)
FSHIFT = {"CF": 0, "PF": 2, "AF": 4, "ZF": 6, "SF": 7, "OF": 11}


def pack_flags(f):
    """{CF:0/1,...} -> 一个 EFLAGS 字(用于直接审表里的 inf 整列)"""
    return sum(v << FSHIFT[k] for k, v in f.items())


# 条件码全表(SDM Vol.1 的表): 同一个判断的四个同义词一并列出, 反算端按名取。
# 这里只拿架构定义的六个位做判断 —— 与表里上的位一致, AF 不参与任何 cc。
CC_COND = {
    "e": lambda f: f["ZF"] == 1, "ne": lambda f: f["ZF"] == 0,
    "b": lambda f: f["CF"] == 1, "nae": lambda f: f["CF"] == 1,
    "c": lambda f: f["CF"] == 1,
    "ae": lambda f: f["CF"] == 0, "nb": lambda f: f["CF"] == 0,
    "nc": lambda f: f["CF"] == 0,
    "a": lambda f: f["CF"] == 0 and f["ZF"] == 0,
    "nbe": lambda f: f["CF"] == 0 and f["ZF"] == 0,
    "be": lambda f: f["CF"] == 1 or f["ZF"] == 1,
    "na": lambda f: f["CF"] == 1 or f["ZF"] == 1,
    "s": lambda f: f["SF"] == 1, "ns": lambda f: f["SF"] == 0,
    "p": lambda f: f["PF"] == 1, "pe": lambda f: f["PF"] == 1,
    "np": lambda f: f["PF"] == 0, "po": lambda f: f["PF"] == 0,
    "l": lambda f: f["SF"] != f["OF"], "nge": lambda f: f["SF"] != f["OF"],
    "ge": lambda f: f["SF"] == f["OF"], "nl": lambda f: f["SF"] == f["OF"],
    "le": lambda f: f["ZF"] == 1 or f["SF"] != f["OF"],
    "ng": lambda f: f["ZF"] == 1 or f["SF"] != f["OF"],
    "g": lambda f: f["ZF"] == 0 and f["SF"] == f["OF"],
    "nle": lambda f: f["ZF"] == 0 and f["SF"] == f["OF"],
    "o": lambda f: f["OF"] == 1, "no": lambda f: f["OF"] == 0,
}


def cc_form(stem):
    """词干 -> (家族, cc) 或 (None, None)。三族词干形状不同:
       jcc   je__/jne__      无宽度段(后缀就是两个下划线)
       setcc sete_r_f_b_flags 固定那一段名(r.f.b/flags)
       cmov  cmove_r_rc_q_flags  cc 就在词干头里"""
    m = re.match(r"^j([a-z]*)__$", stem)
    if m:
        return "j", m.group(1)
    m = re.match(r"^set([a-z]+)_r_f_b_flags$", stem)
    if m:
        return "set", m.group(1)
    if stem.startswith("cmov"):
        return "cmov", stem[4:].split("_")[0]
    return None, None


# 搬运族(15Kn)的输入输出规则。源操作数的**访问宽度**与是否符号扩展由助记符给
# (SDM 的 MOVSX/MOVZX 定义); mov/movabs/movbe/bswap 的源宽 = 目的宽(词干里那个
# _l/_q), 所以不需要额外表项。
MOV_SRC_W = {"movzb": 8, "movzw": 16, "movsb": 8, "movsw": 16, "movsl": 32}
MOV_ZEXT = {"movzb": True, "movzw": True, "movsb": False, "movsw": False,
            "movsl": False}
# 隐式累加器三条的审计宽度: 词干里没有宽度段(名字本身带宽度) -> 必须指名
MOV_WIDE_W = {"cwtl": 32, "cltq": 64, "cqto": 64}
# 立即数形态的字面量: 与 isb_mov.c 里写死的同一个数。本文件是「第二实现」,
# 故意各自手写一份 —— 改成从源码里解析就审不出抄错了(与 IB_IMM="$5" 同理)
MOV_IMM = {"mov_r_i_l": 0x12345678, "movabs_r_i_q": 0x123456789ABCDEF}
MOV_OPS = ({"mov", "movabs", "movbe", "bswap"} | set(MOV_SRC_W) |
           set(MOV_WIDE_W))


def bswap(x, w):
    """整字节流反转(BSWAP / MOVBE 的加载侧): 按字节翻、不是按位"""
    return int.from_bytes((x & ((1 << w) - 1)).to_bytes(w // 8, "little"), "big")


def mov_expect(stem, i0, i1, w):
    """搬运族反算 -> {"o0","o1"}。两条通用规则就覆盖 34 个形态的全部形状:
      目的在寄存器 -> o0 = 源侧那个值(源在内存就是窗口广播的 i1, 源在寄存器就
                      是词干里那个操作数, 源是立即数就是 MOV_IMM 那个字面量)
      目的在内存 -> 探针从同一槽回读 -> o0 = 被存进去的寄存器值 = i0
    扩展族再套一层零/符号扩展, movbe/bswap 再套一层字节序反转。"""
    p = stem.split("_")
    op, d1, d2 = p[0], p[1], (p[2] if len(p) > 2 else "")
    mask = (1 << w) - 1
    if op in MOV_WIDE_W:                      # cwtl/cltq/cqto: 状态全在 a/d 里
        if op == "cwtl":
            return {"o0": sgn(i0, 16) & ((1 << 32) - 1), "o1": i1}
        if op == "cltq":
            return {"o0": sgn(i0, 32) & mask, "o1": i1}
        return {"o0": i0, "o1": mask if (i0 >> (w - 1)) & 1 else 0}
    if op == "bswap":
        return {"o0": bswap(i0, w), "o1": i1}
    if op == "movbe":                         # 大端加载形: 内存里那个值 = i1, 反着读
        return {"o0": bswap(i1, w), "o1": i1}
    if op in MOV_SRC_W:                        # 零/符号扩展族
        srcw = MOV_SRC_W[op]
        raw = (i1 if d2 == "m" else i0) & ((1 << srcw) - 1)
        v = raw if MOV_ZEXT[op] else sgn(raw, srcw)
        return {"o0": v & mask, "o1": i1}
    if d1 == "m":                              # store 形态: 回读 = 被存的寄存器
        return {"o0": i0 & mask, "o1": i1}
    if d2 == "i":
        assert stem in MOV_IMM, "立即数形态未登记字面量: " + stem
        return {"o0": MOV_IMM[stem] & mask, "o1": i1}
    return {"o0": i1 & mask, "o1": i1}          # load(r/m) 与 r/r: 源都是 i1


# 栈族(15Ko): push/pop 的「栈」是隐式操作数, 表上能审的就是探针从 (%rsp)
# 回读到那个字(这一次回读连带验了 rsp 位移) + 三条都不改标志:
#   push m.r -> o0 = i0      (压的是寄存器入值)
#   push m.i -> o0 = 5       (压的是写死的立即数)
#   push m.m -> o0 = i1      (压的是内存窗广播值)
#   pop  r.m -> o0 = i1      (造栈帧压的是 %[b]=i1, pop 进寄存器)
#   pop  m.m -> o0 = i0      (写槽本来就被广播成 i1, 所以造栈帧改压 i0 ——
#                             否则「pop 真写了」与「pop 没写」回读同值, 不可证伪)
#   pushf    -> o0 = inf & 0x8d5(压的就是标志本身; 表里只上了架构有定义那 6 位)
STACK_IMM = 5                     # isb_ctrl.c 里 push 立即数形写死的 $5
STACK_OPS = {"push", "pop", "pushf"}


def stack_expect(stem, i0, i1, inf, w):
    """栈族反算 -> {"o0","o1"}。形态段 d1/d2 沿用 xperf 的 form_key 语义:
    首字母是「目的」(m=栈/内存, r=寄存器), 第二个是「源」。"""
    p = stem.split("_")
    op, d1, d2 = p[0], p[1], (p[2] if len(p) > 2 else "")
    mask = (1 << w) - 1
    if op == "pushf":
        assert d2 == "f", "pushf 形态段未预期: " + stem
        return {"o0": (inf & 0x8d5) & mask, "o1": i1}
    if op == "push":
        assert d1 == "m" and d2 in ("r", "i", "m"), "push 形态段未预期: " + stem
        src = {"r": i0, "i": STACK_IMM, "m": i1}[d2]
        return {"o0": src & mask, "o1": i1}
    assert d2 == "m", "pop 形态段未预期: " + stem
    return {"o0": (i0 if d1 == "m" else i1) & mask, "o1": i1}


# special 组(直写风格: 一条指令一个函数, 词干就是助记符)的审计宽度。
# 这一组没有形态段 -> width_of() 那套 `_l_/_q_` 提不到东西(会默认发到64),
# 而上表真值的宽度是探针里钉死的: 原子族 32 位(KAT 表只在 x86_64 采一份,
# 只有两 ABI 同宽才能共表), 串族上的是「缓冲里的 8 字节」这一层 -> 64。
# ★ 原本这里还钉着 6 条 x87(fld_fstp/fadd/fmul/fistp/fcomip/fcw_rt), 已随内核
#   一起迁到 x87 组(X87_W): 词干名没变, 但**归属由表文件决定**、不再由词干决定
#   —— 否则同一词干出现在两张表时, special 的 stale 行会被 x87 的实现接住。
SPECIAL_W = {"xchg_r": 32, "xchg_m": 32, "cmpxchg": 32, "lock_cmpxchg": 32,
             "xadd": 32, "lock_xadd": 32,
             "movsb": 64, "stosb": 64, "cmpsb": 64,
             "rep_movsb": 64, "rep_stosb": 64}

# x87 组: P1 的 12 条 + P2 的 5 条 + P3 的 3 条 + P5 的 6 条 + P6 的 7 条 + 自
# special 迁入的 6 条 = 39 条(与 isb_x87.c 的分节同序; P7 落地后再加 8 条)。上表的
# o0/o1 是 64 位整数、double 位形或 80 位尾数; 短的那些(se 的 16 位、rc_fstcw_rt 的
# 控制字、P3/P6 o1 的高 16 位)都是探针按该宽度回读后零扩展到 64 的 -> 审计宽度仍记
# 64(比较式里不会截掉有效位)。
X87_STEMS = ("fild_fistp_q_rt", "fild_fistp_d_rt", "fild_fistp_w_rt",
             "fild_fistp_q_neg", "fild_q_odd_rt", "fild_fstp_q_dbl",
             "fild_fstp_t_ext", "fistp_q_indef", "fisttp_q_rt",
             "fld_t_fstp_t_rt", "fbld_fistp_q_rt", "fild_fistp_q_x8",
             "rc_fistp_q_rn", "rc_fistp_q_rd", "rc_fistp_q_ru", "rc_fistp_q_rz",
             "rc_fstcw_rt", "pc24_fadd", "pc53_fadd", "pc64_fmul",
             "stack_top_after_fild", "stack_fld8_st8", "fxch_st3",
             "fldst_st1_to_st0", "fincstp_fdecstp_rt", "ffree_tag",
             "fdiv_zero_ze", "fsqrt_neg_ie", "fistp_oe", "stack_underflow_is",
             "denormal_ue", "precision_pe", "fnclex_clears",
             "fld_fstp", "fadd", "fmul", "fistp", "fcomip", "fcw_rt",
             "fcom_cc", "fcompp_cc", "fsubr_pair", "fisubr_m64",
             "fscale_int", "fxam_kinds", "fstsw_allbits", "fninit_defaults")
X87_W = {s: 64 for s in X87_STEMS}


M64 = (1 << 64) - 1
M32 = (1 << 32) - 1

# ---------------- x87 组入值向量(第二实现: 各自手写, 不从 C 里解析) ----------
# 拄的是**口径**不是结论。拿它们复算 i0 的作用是: 入值口径一旦被改坏(例如窄宽度
# 族从"取高 16 位"改成"取低 16 位"), 期望式仍然自洽、只有这一层复核算得出来。
# 逐位的取值理由见 isb_x87.c 的 XVEC/BVEC/IVEC 头注(两处同集, 改一处必改另一处)。
XVEC = (0x0020000000000000, 0x0020000000000001,
        0x37a64339803cdc21, 0x7fffffffffffffff,
        0xcbf29ce484222325, 0xffffffffffffffff,
        0x8000000000000000, 0x123456789abcdef1)
# BVEC: FBLD 的入值(取绝对值用, 符号由 kk&4 定) —— 全部 < 1e18(18 位十进制量程)
BVEC = (0x0020000000000001, 0x0020000000000000,
        0x0de0b6b3a763ffff, 0x0de0b6b3a763fffe,
        0x0003ffffffffffff, 0x0003000000000001,
        0x07a64339803cdc21, 0x00aaaaaaaaaaaaab)
# IVEC: 喂给 FISTP m64int 的 double 位形, 8 个全在 int64 量程**之外**
# (含 2^63 / -(2^63+2) / 2^64 / ±Inf / QNaN / SNaN) -> 期望恒为 integer indefinite
IVEC = (0x43e0000000000000, 0x43e0000000000001,
        0x43f0000000000000, 0xc3e0000000000001,
        0x7ff0000000000000, 0xfff0000000000000,
        0x7ff8000000000000, 0x7ff4000000000001)

INDEF = 0x8000000000000000     # SDM: 目标整数超量程时 FISTP 写的 integer indefinite
SW_IE = 0x0001                 # 状态字只置 IE(取证 c: 越界是 #IA 不是 OE, masked 不置 ES)
SW_PE = 0x020                  # 取证 a: PE=bit5 —— 只要真舍过位就置
SW_C1 = 0x200                  # 取证 a: C1=bit9 —— 实测跟的是"量级变大"(取证 i)


def ext_form(bits):
    """int64 位形 -> 80 位**左规**位形 (mant, se)。与 isb_x87.c 的 ext_form() 各写
    一遍(那里靠无符号回绕取补, 这里是 Python 任意精度整数): 显式整数位恒 1, 所以
    尾数 = |v| 左移到 bit63、指数 = 16383 + 位长 - 1。
    锚点(取证 e, 两台真机): INT64_MAX -> 403d.fffffffffffffffe、-2^63 -> 403e.8000..."""
    sign = 1 if bits >> 63 else 0
    u = (-bits) & M64 if sign else bits
    if u == 0:
        return 0, (0x8000 if sign else 0)
    hi = u.bit_length() - 1
    return (u << (63 - hi)) & M64, (sign << 15) | (hi + 16383)


def p1_dbl_round(bits):
    """int64 位形 -> (double 位形, 状态字), **一次**舍入(RC=RN: 就近取偶、平局取偶)
    —— fild_fstp_q_dbl 那条对照行的 o0 与 o1 全由它推(名字按 isb_x87.c 文件头
    指定的落点算: 两个薄包裹 p1_fild_fstp_q_dbl() / _sw() 才是对外契约)。
    算式全走整数, 不经 Python float: 一旦用 float(i0) 就把"入值必须落在精确区"
    这条前提一并写进期望里(计划要撤的那条 assert 正是这个形状)。
    三个位形锚点(与本机 PE 实测同字, 见 isb_x87.c 文件头):
      2^53+1 -> 0x4340000000000000    INT64_MAX -> 0x43e0000000000000
      -2^63  -> 0xc3e0000000000000
    INT64_MAX 必须舍**上**到 2^63: 它距 2^63 只有 1、距上一档 2^63-1024 有 1023;
    拿"不大于 INT64_MAX 的最大 double"(0x43dfff...) 当期望会把正确实现判成违约。
    状态字一侧(取证 i, 两台真机 144 块 K 行同字): 舍过就置 PE(b5), 量级变大再置
    C1(b9) -> 本向量里实测到三种: 精确 0x000、舍入且量级变小 0x020、舍入且量级
    变大 0x220。而"负数 + 量级变大"这一组合本表拿不到实测(负侧入值只有 -1、
    -2^63 两个精确值与 k=4 那个量级变小的) -> 出现了就点名要新取证, 不拿没验过
    的"数轴方向"读法替硬件说话(那种读法会把 k=4 算成 C1=1, 与两台真机相反)。"""
    sign = 1 if bits >> 63 else 0
    u = (-bits) & M64 if sign else bits
    if u == 0:
        return sign << 63, 0
    hi = u.bit_length() - 1
    if hi <= 52:                                 # 53 位以内 -> double 精确表示
        # 隐含 1 就落在 bit hi: 存进 double 的小数部分是 u 左对齐到 bit52 后的
        # 低 52 位, 不是 "u & (2^52-1)"。本向量里只有 k=5(int64 的 -1) 走这条,
        # 上一版的错对齐正好被 k=1 的先报错挡住(main 只印 bad[0]) -> 单独钉住。
        return ((sign << 63) | ((hi + 1023) << 52)
                | ((u << (52 - hi)) & ((1 << 52) - 1))), 0
    shift = hi - 52
    keep = u >> shift                            # 53 位(含隐含 1)
    rem = u & ((1 << shift) - 1)                 # 被舍掉的低位
    half = 1 << (shift - 1)
    if rem > half or (rem == half and (keep & 1)):
        keep += 1
        if keep >> 53:                           # 进位撑到 54 位 -> 升一档
            keep >>= 1
            hi += 1
            shift = hi - 52                      # 撑一档后位移跟着重算(v 才是真值)
    out = (sign << 63) | ((hi + 1023) << 52) | (keep & ((1 << 52) - 1))
    v = keep << shift                            # 舍后那个 double 的真值(必为整数)
    sw = 0
    if v != u:                                   # 只要舍过位就是"不精确"
        sw |= SW_PE
        if v > u:                                # 实测的 C1 跟的是量级方向
            assert not sign, (
                "fild_fstp_q_dbl 出现双机未取证的方向组合(负侧量级变大): "
                "%x -> %x, 先补取证再定期望" % (bits, out))
            sw |= SW_C1
    return out, sw


def p1_fild_fstp_q_dbl(bits):
    """位形一侧(isb_x87.c 文件头里指定的名字就是本函数)"""
    return p1_dbl_round(bits)[0]


def p1_fild_fstp_q_dbl_sw(bits):
    """状态字一侧: 0x000 精确 / 0x020 舍了但量级变小 / 0x220 舍了且量级变大"""
    return p1_dbl_round(bits)[1]


# P1 的 12 条(全 [解析])按"期望落在哪个字段"分组, 与内核注释逐条对得上
P1_SW0 = ("fild_fistp_q_rt", "fild_fistp_q_neg", "fild_q_odd_rt",
          "fisttp_q_rt", "fbld_fistp_q_rt")      # o0 == i0 且状态字全清
P1_WW = ("fild_fistp_d_rt", "fild_fistp_w_rt")   # o0 == i0 且高位仍留 0xAA 哨兵
P1_STEMS = P1_SW0 + P1_WW + ("fild_fstp_q_dbl", "fild_fstp_t_ext",
                             "fistp_q_indef", "fld_t_fstp_t_rt",
                             "fild_fistp_q_x8")


def p1_in_regime(stem, kk, i0, i1):
    """入值口径复核: 这条 case 喂进去的必须是向量算出来的那个值。
    断言的是"输入还是我以为的输入", 不是"值太小所以真值可比"(后者只对用 float()
    算期望的 fadd/fmul 成立, 见 x87_legacy_expect 里的降级说明)。"""
    if stem in ("fild_fistp_q_rt", "fisttp_q_rt", "fild_fstp_q_dbl",
                "fild_fstp_t_ext"):
        want = XVEC[kk]
    elif stem == "fild_q_odd_rt":
        want = XVEC[kk] | 1
    elif stem == "fild_fistp_q_neg":
        want = (-XVEC[kk]) & M64                 # 无符号回绕取补(-INT64_MIN 不 UB)
    elif stem == "fild_fistp_d_rt":
        want = sgn(XVEC[kk] >> 32, 32) & M64     # 取高 32 位再按 int32 符号扩展
    elif stem == "fild_fistp_w_rt":
        want = sgn(XVEC[kk] >> 48, 16) & M64
    elif stem == "fistp_q_indef":
        want = IVEC[kk]
    elif stem == "fbld_fistp_q_rt":
        assert BVEC[kk] < 10 ** 18, "FBLD 只有 18 位十进制量程, 向量越界: %x" % BVEC[kk]
        neg = 1 if (kk & 4) else 0
        assert i1 == neg, "fbld_fistp_q_rt k=%d 符号位口径变了: %x" % (kk, i1)
        want = (-BVEC[kk]) & M64 if neg else BVEC[kk]
    elif stem == "fld_t_fstp_t_rt":
        m, se = ext_form(XVEC[kk])
        assert (i0, i1) == (m, se), \
            "fld_t_fstp_t_rt k=%d 输入位形不再是 ext_form(XVEC): (%x,%x)" % (kk, i0, i1)
        want = m
    else:                                        # fild_fistp_q_x8: 八组异或
        x = 0
        for v in XVEC:
            x ^= v
        assert (i0, i1) == (x, 0xFF), \
            "fild_fistp_q_x8 入值侧不再是 xor 掩码口径: (%x,%x)" % (i0, i1)
        want = x
    assert i0 == want, "%s k=%d 入值口径变了: 表=%x 应为 %x" % (stem, kk, i0, want)


def p1_expect(stem, i0, i1, inf, kk):
    """P1 的[解析]期望(SDM 文本 + 纯整数算式, 与参考机无关):
      往返族  : FILD m*int "loaded without rounding errors" + FISTP 对量程内整数
                精确存回 -> o0 == i0; 弹栈后 TOP 回 0 且无异常 -> o1 == 0
      写宽族  : 同上, 且目的槽高位必须仍是 0xAA 哨兵 -> o1 == 1(取证 h 的实测写宽)
      dbl 对照: 终点本就是 double, 一次舍与两次舍同值 -> o0 = p1_fild_fstp_q_dbl(i0);
                o1 = 状态字(舍过置 PE、量级变大再置 C1 —— 取证 i)
      ext 定位: 80 位的 64 位尾数容纳任意 int64 -> (o0,o1) = ext_form(i0)
      量程外  : integer indefinite + 只置 IE -> (o0,o1) = (INDEF, SW_IE)
      m80 往返: 10 字节操作数 + 显式整数位原样搬运 -> o0 == i0 且 o1 == i1
      八独立槽: 互不串扰 -> o0 == i0(异或相等) 且 o1 == 0xff(逐组相等掩码全 1)
    全族共用: x87 整型搬运架构上不碰 EFLAGS -> outf == inf & 0x8d5(bit1 是保留位,
    inf 被 IB_FV() 强制置 1 而 outf 过 IB_FLG_MASK 不含它, 故不是字面的 outf==inf)。"""
    p1_in_regime(stem, kk, i0, i1)
    nf = flags_of_inf(inf)
    if stem in P1_SW0:
        return {"o0": i0, "o1": 0, **nf}
    if stem in P1_WW:
        return {"o0": i0, "o1": 1, **nf}
    if stem == "fild_fstp_q_dbl":
        return {"o0": p1_fild_fstp_q_dbl(i0),
                "o1": p1_fild_fstp_q_dbl_sw(i0), **nf}
    if stem == "fild_fstp_t_ext":
        mant, se = ext_form(i0)
        return {"o0": mant, "o1": se, **nf}
    if stem == "fistp_q_indef":
        return {"o0": INDEF, "o1": SW_IE, **nf}
    if stem == "fld_t_fstp_t_rt":
        return {"o0": i0, "o1": i1, **nf}
    return {"o0": i0, "o1": 0xFF, **nf}          # fild_fistp_q_x8


def fbits(num, den):
    """(num/den) 的 IEEE double 位形 —— 与 C 探针那个 qbits() 同口径但完全独立:
    这里让 Python 的 float(就是 double)去算, 探针那侧是 x87 硬件。入值都在精确区
    (分子 <= 48 位、分母是 4/16 这种 2 的幂), 所以两边必须逐位相同。"""
    return struct.unpack("<Q", struct.pack("<d", num / den))[0]


# ====================================================================
# P2 舍入模式(5 条, 全 [解析])
# RC 位段 = 控制字位 10-11(取证 g1 两台真机: 00 就近取偶 / 01 向 -inf / 10 向 +inf
# / 11 向零; 常被拄成的位 2-3 是异常屏蔽位)。入值向量与 isb_x87.c 的 RVQ 同集,
# 位形却各算各的: 那边是"整数转 double 后指数域减 2", 这边是 fbits(q, 4) 的真除法。
# ====================================================================
RVQ = (-15, 10, -10, 14, 2, -2, 12, -16)
RC_RN, RC_RD, RC_RU, RC_RZ = 0, 1, 2, 3
P2_ARMS = {"rc_fistp_q_rn": RC_RN, "rc_fistp_q_rd": RC_RD,
           "rc_fistp_q_ru": RC_RU, "rc_fistp_q_rz": RC_RZ}
P2_STEMS = ("rc_fistp_q_rn", "rc_fistp_q_rd", "rc_fistp_q_ru", "rc_fistp_q_rz",
            "rc_fstcw_rt")
CW_DEFAULT = 0x037F          # finit 后的控制字(屏蔽位全 1、PC=11b、RC=00b)


def rc_cw(enc):
    """RC 编码 -> 期望的控制字读数。先清后置而不是 OR(与 pc_cw 同形): 默认值的位
    10-11 恰好是 0, OR 也能对, 但同一个事实在 PC 位段上却是"默认已是 11b"——
    两处不同形就迟早会把其中一处带错(C 侧本轮真踩过: PC_CW 只 OR 时 24 档设不出来)。"""
    return (CW_DEFAULT & ~0x0C00) | (enc << 10)


def rc_int(qnum, rc):
    """qnum/4 在指定 RC 档下的整数值(纯整数 floor-divmod, 全程不经 float)。
    Python 的 divmod 本就是向负无穷取整 -> 正好就是"下档", 四档都在它之上做纯
    整数判断, 与 SDM 的四种方向语义一一对应, 中间没有第四个近似环节:
      RD = 下档本身; RU = 真舍过位则下档 +1; RZ = 负侧真舍过位才 +1(向零);
      RN = 余数 > 半档进位, = 半档取下档偶数一侧。
    平局(r==2)与负侧是本向量的重点: 0.5/-0.5/2.5/-2.5/3.5 五行把"四档签名两两
    互异"所需的全部形状都走到了(单档不可能同时等于四种签名)。"""
    q, r = divmod(qnum, 4)
    if rc == RC_RD:
        return q
    if rc == RC_RU:
        return q + (1 if r else 0)
    if rc == RC_RZ:
        return q + (1 if (r and q < 0) else 0)
    if r > 2 or (r == 2 and (q & 1)):
        return q + 1
    return q


def p2_expect(stem, i0, i1, inf, kk):
    """P2 的[解析]期望(SDM 文本 + 纯整数算式, 与参考机无关):
      四档存回: o0 = m64int 结果, o1 = m32int 结果 —— 同一次 fldcw 下的两个存回
                宽度, 所以两字段必须是**同一个整数值**的不同宽度表示(本向量都落在
                int32 内, 两字段相等是结果不是前提: 翻译器把 m32 形按 8 字节写就
                会不等 —— 那条断言 P1 的写宽族已钉, 这里顺带再推一次)
      rc_fstcw_rt: o0 = "除 RC 两位之外没动过任一位"(两读数的异或), o1 = 第次读回
                的绝对值(0x037f | enc_t<<10) —— 由 o0^o1 可反推第一次读数,
                所以第一次 fldcw 也没漏检
    标志一侧同 P1: x87 整型搬运架构上不碰 EFLAGS -> outf == inf 的六个位。"""
    nf = flags_of_inf(inf)
    if stem == "rc_fstcw_rt":
        enc_f, enc_t = i0, i1
        assert enc_f == (kk & 3) and enc_t == ((enc_f + 1 + (kk >> 2)) & 3), \
            "rc_fstcw_rt k=%d 两次设的档不再由 kk 推出: (%x,%x)" % (kk, enc_f, enc_t)
        assert enc_f != enc_t, "rc_fstcw_rt k=%d 两次设同一档 -> 往返没有自变量" % kk
        return {"o0": (enc_f ^ enc_t) << 10, "o1": rc_cw(enc_t), **nf}
    rc = P2_ARMS[stem]
    q = RVQ[kk]
    assert i1 == rc, "%s k=%d 表里的 RC 档位与词干名不符: %x" % (stem, kk, i1)
    assert abs(q) < (1 << 24), "RVQ 出 q4bits() 的精确转换区: %d" % q
    assert i0 == fbits(q, 4), \
        "%s k=%d 入值不再是 RVQ/4 的 double 位形: 表=%x 算=%x" % (stem, kk, i0,
                                                            fbits(q, 4))
    v = rc_int(q, rc)
    return {"o0": v & M64, "o1": sgn(v, 32) & M64, **nf}


# ====================================================================
# P3 精度控制(3 条: 每档各自 [解析] + 一道档间关系)
# PC 位段 = 控制字位 8-9(取证 g1/g2 双机实测), **且被硬件 honor** —— 同一算式三档
# 给出三个互异位形, 所以计划原本那句"现代 Intel 忽略 PC、三档应逐位相同"不成立
# (留痕进过程报告, 不改计划文件)。本节的期望全建立在一个模型上: 先把算式按整数
# 算到**精确**, 再舍到本档位宽 —— 两步分开, 才能把"没 honor PC"与"舍错了"分成两种
# 不同的 FAIL(前者只错一列, 后者列列都错)。
# ====================================================================
PC_ARMS = {"pc24_fadd": (0, 24), "pc53_fadd": (2, 53), "pc64_fmul": (3, 64)}
P3_STEMS = ("pc24_fadd", "pc53_fadd", "pc64_fmul")


def pc_cw(enc):
    """PC 编码 -> 期望的控制字读数(fnstcw 原样读回的就是它)。先清后置的理由见
    isb_x87.c 的 PC_CW 与上面的 rc_cw: 默认 0x037f 的位 8-9 已是 11b, 只 OR 设不出
    24 档 —— 审计与探针两边各自写一遗这个式子, 就是为了谁被改坏都能在这里断掉。"""
    return (CW_DEFAULT & ~0x0300) | (enc << 8)


def d_pow2(k):
    """2^k 的 double 位形(与 C 的 D_POW2 同式)。只在本组的量级区取规格化数,
    越界直接报 —— 0、次正规、无穷与 NaN 各有各的位形规则, 套同一个式子就是
    "我以为硬件是这个意思"的又一个形状。"""
    assert 1 <= 1023 + k <= 0x7FE, "d_pow2 只接规格化区: 2^%d" % k
    return (1023 + k) << 52


def d_2pn1(n):
    """2^n + 1 的 double 位形(1 <= n <= 52: 那一位落在小数域内且与隐含 1 不重叠;
    n=0 时这个式子会算成 2^53, 所以下限是 1 而不是 0)"""
    assert 1 <= n <= 52, "2^n+1 要能被 double 精确表示: %d" % n
    return d_pow2(n) | (1 << (52 - n))


FAVEC = (d_pow2(0),) * 7 + (d_pow2(30),)
FBVEC = tuple(d_pow2(k) for k in (-24, -25, -23, -30, -40, -52, -53, 6))
FMVEC = tuple(d_2pn1(n) for n in (12, 20, 24, 26, 27, 30, 40, 52))


def dv(bits):
    """double 位形 -> (符号位, 整数尾数, 位移): 值 = (-1)^sign * num * 2^shift。
    全程整数、不经 Python float —— 一用 float 就把"参考机的 double 舍入"当成了
    事实来源, 而 P3 要的正是"精确值"与"舍到 w 位"两个环节的分离。"""
    sign = 1 if bits >> 63 else 0
    e = (bits >> 52) & 0x7FF
    assert 1 <= e <= 0x7FE, "dv 只接规格化有限 double: %x" % bits
    return sign, (1 << 52) | (bits & ((1 << 52) - 1)), e - 1023 - 52


def dadd(ba, bb):
    """两个规格化 double 的**精确**和 -> (sign, num, shift)。对齐到公共位移后做
    带符号的整数加减: 无溢出、无舍入, 所以这就是 x87 在那个算式上的真值。"""
    sa, na, ha = dv(ba)
    sb, nb, hb = dv(bb)
    h = min(ha, hb)
    x, y = na << (ha - h), nb << (hb - h)
    if sa == sb:
        return sa, x + y, h
    return (sa, x - y, h) if x >= y else (sb, y - x, h)


def dmul(ba, bb):
    """精确积: 尾数相乘、位移相加、符号相异或(整数乘不开玩笑, 永远精确)"""
    sa, na, ha = dv(ba)
    sb, nb, hb = dv(bb)
    return sa ^ sb, na * nb, ha + hb


def m80_sig(sign, num, shift, prec):
    """精确值 (-1)^sign * num * 2^shift 舍到 prec 位有效位(RC=RN 就近取偶)后的
    80 位左规位形 (mant, se)。这就是取证 g2 那六个实测常数的生成式, 反验过才拿它
    当期望(24 档 1+2^-40 -> 0x8000000000000000/0x3fff; 53 档同式 ->
    0x8000000000800000/0x3fff; (2^27+1)^2 三档 -> ...0000 / ...002000000000 /
    ...002000000200 且 se 恒 0x4035)。
    prec 位有效 = 尾数最高位落在 bit(prec-1); 多出来的低位按 RN 舍, 进位撑到
    prec+1 位则右移一位并升一档(m80 的 15 位指数域在本组量程内不会溢出)。"""
    assert num > 0, "P3 的入值不含零、也没有互为相反数的加数: 向量被改坏了"
    q, s = num, shift
    hi = num.bit_length() - 1
    if hi > prec - 1:
        d = hi - (prec - 1)
        q, r = divmod(num, 1 << d)
        half = 1 << (d - 1)
        if r > half or (r == half and (q & 1)):
            q += 1
            if q.bit_length() - 1 > prec - 1:
                q >>= 1
                d += 1
        s += d
    hi_f = q.bit_length() - 1
    return (q << (63 - hi_f)) & M64, (sign << 15) | (hi_f + s + 16383)


def p3_exact(stem, kk):
    """这条用例的入值对与精确结果三元组(每档期望与档间关系共用, 所以只此一份)"""
    enc, prec = PC_ARMS[stem]
    if stem == "pc64_fmul":
        pair = (FMVEC[kk], FMVEC[kk])
        return pair, dmul(*pair), enc, prec
    pair = (FAVEC[kk], FBVEC[kk])
    return pair, dadd(*pair), enc, prec


def p3_expect(stem, i0, i1, inf, kk):
    """P3 每档自己的[解析]期望:
      o0 = 精确结果舍到本档位宽后的 m80 尾数(显式整数位在 bit63)
      o1 = 该 m80 的指数域 | (fnstcw 读回的控制字 << 16) —— 表只有两个输出字段,
           就把"档真设进去且原样读回"与"结果位形"钉进同一个字段
    入值侧先复核向量没被改坏: i0/i1 必须是 FAVEC/FBVEC(乘法那条两侧同值)。"""
    (a, b), (sign, num, shift), enc, prec = p3_exact(stem, kk)
    assert (i0, i1) == (a, b), \
        "%s k=%d 入值不再是本节的向量: 表=(%x,%x) 算=(%x,%x)" % (stem, kk,
                                                            i0, i1, a, b)
    mant, se = m80_sig(sign, num, shift, prec)
    return {"o0": mant, "o1": se | (pc_cw(enc) << 16), **flags_of_inf(inf)}


def pc_arm_relation(stems):
    """档间关系(计划的第二道判据): pc24_fadd 与 pc53_fadd **共用同一对入值向量**,
    所以"两档读数是否不同"必须逐行等于模型预测。为什么每档已有[解析]期望还要它:
    三条的期望共用 m80_sig() 的 prec 参数, 那个参数被写死时三条会同时自洽地全过
    (C 侧本轮就真踩过同形错: PC_CW 原先只 OR, 24 档在硬件上压根没设出来); 而本函数
    只看两个读数之差, 不经过 prec 以外的共因。反向同样有用: 采集机若不 honor PC
    (取证 g0 那句旧结论的字面意思), 八行会全部相同 -> 在这里逐行报出来。
    返回不符描述(空表 = 通过); o1 只比低 16 位(se), 控制字那半边按构造必不同。"""
    a, b = stems.get("pc24_fadd"), stems.get("pc53_fadd")
    if a is None or b is None:
        return ["表里缺 pc24_fadd/pc53_fadd 之一 -> 档间对照无从谈起"]
    msgs, n_pred = [], 0
    for k in range(8):
        _, (sign, num, shift), _, _ = p3_exact("pc24_fadd", k)
        pred = m80_sig(sign, num, shift, 24) != m80_sig(sign, num, shift, 53)
        act = a[k][5] != b[k][5] or (a[k][6] & 0xFFFF) != (b[k][6] & 0xFFFF)
        n_pred += 1 if pred else 0
        if pred != act:
            msgs.append("k=%d 档间实测%s, 模型预测%s(24档 o0=%x 53档 o0=%x)"
                        % (k, "有差别" if act else "相同",
                           "有差别" if pred else "相同", a[k][5], b[k][5]))
    if not msgs and n_pred == 0:
        msgs.append("模型预测两档八行全同 -> 入值向量退化到 PC 不可分辨, 对照失去意义")
    return msgs


# ====================================================================
# P5 栈(6 条, 全 [解析])
# 位段按取证 2/6 的真机读回: **TOP = sw 的 bits 11-13(LSB=bit11)**、IE=bit0、
# SF=bit6、ES=bit7 —— 计划 99 行写的"TOP=bits 8-10、C1=bit11"是错的(订正见
# isb_x87.c 文件头 h) ①)。六条的期望只用到四句话(取证 6 c)/G3): ST(k) = 物理格
# (TOP+k)&7、压栈 TOP-1、弹栈 TOP+1、第 9 次压栈才报 IE|SF —— 所以本节没有一个
# "看死的实测常数", 只有这四句话的组合。
# ====================================================================
SW_DE, SW_ZE, SW_OE, SW_UE = 0x0002, 0x0004, 0x0008, 0x0010
SW_SF = 0x0040
SW_C0, SW_C2, SW_C3 = 0x0100, 0x0400, 0x4000
TOP_SH = 11                                 # TOP 字段在 sw 里的位移(取证 2 真机)

X1_80 = 1 << 63                             # m80 的显式整数位(左规格式恒为 1)
M80_SGN = 1 << 15                           # m80 se 的符号位
M80_EMIN = -16382                           # 最小规格化指数(= 2^-16382)
INDEF80_M = 0xc000000000000000              # -QNaN indefinite 的尾数
INDEF80_S = 0xffff                          # 指数域全 1 + 符号 1


def m80_e(k):
    """真指数 -> m80 指数域(偏置 16383)。非规格化档不走本函数: 它的指数域是 0,
    格距由 m80_dec() 那条 max(ef,1) 的统一式给出。"""
    assert -16383 <= k <= 16383, "m80 规格化档的指数范围外: 2^%d" % k
    return 16383 + k


def top_sw(top, flags=0):
    """TOP -> 状态字读数。全组只经这一个组装式(否则某处写成 <<10 就会静默错一档)"""
    return ((top & 7) << TOP_SH) | flags


P5_STEMS = ("stack_top_after_fild", "stack_fld8_st8", "fxch_st3",
            "fldst_st1_to_st0", "fincstp_fdecstp_rt", "ffree_tag")


def p5_expect(stem, i0, i1, inf, kk):
    """P5 的[解析]期望(逐条与 isb_x87.c 的内核注释同序对得上):
      stack_top_after_fild: 压 n=kk+1 次 -> TOP=(0-n)&7; 弹 n 次 -> TOP 回 0。
        ★ 第 8 次压栈后 TOP 又回到 0(栈满不报), 所以八档的 o0 是 TOP=7..0 的阶梯
      stack_fld8_st8: 第 (7-kk) 次弹出拿回的正是第 kk 个入栈值 -> o0 == i0;
        o1 = 弹完 sw(低 16)| 峰值 sw(高 16) == 0(压满一圈既不溢出也没舍入)
      fxch_st3: 只换 ST0 与 ST(3) -> o0 == i1 且 o1 == i0(纯置换, 无舍入模型)
      fldst_st1_to_st0: 弹回的第一格 = 压栈前的 ST(1) -> (o0, o1 低 16) = ext_form(i0);
        高 16 = 三格弹完的 sw = 0(TOP 回 0、无 IE|SF)
      fincstp_fdecstp_rt: fincstp 是 +1(与压栈反向) -> o0 = (n&7)<<11, o1 = 0
      ffree_tag: tag 每寄存器两位、物理格 p 在 bit 2p -> o0 = 3<<(2*kk);
        o1 = 环境里的 sw = (kk&7)<<11(钉的是"ffree 不动 TOP", 且这一档 TOP 非 0)
    全节共用: 整型往返无损 -> 状态字除 TOP 之外一位不置; EFLAGS 不受影响。"""
    nf = flags_of_inf(inf)
    if stem == "stack_top_after_fild":
        n = kk + 1
        assert (i0, i1) == (XVEC[kk], n), \
            "stack_top_after_fild k=%d 入值/次数口径变了: (%x,%x)" % (kk, i0, i1)
        return {"o0": top_sw((0 - n) & 7), "o1": top_sw((0 - n + n) & 7), **nf}
    if stem == "stack_fld8_st8":
        assert (i0, i1) == (XVEC[kk], 7 - kk), \
            "stack_fld8_st8 k=%d 不再是(第 kk 个入栈值, 第 7-kk 次弹出): (%x,%x)" % (
                kk, i0, i1)
        return {"o0": i0, "o1": 0, **nf}
    if stem == "fxch_st3":
        assert (i0, i1) == (XVEC[kk], XVEC[(kk + 3) & 7]), \
            "fxch_st3 k=%d 换的不是 ST0 与 ST(3): (%x,%x)" % (kk, i0, i1)
        return {"o0": i1, "o1": i0, **nf}
    if stem == "fldst_st1_to_st0":
        assert (i0, i1) == (XVEC[kk], XVEC[(kk + 1) & 7]), \
            "fldst_st1_to_st0 k=%d 的两项入值阶梯变了: (%x,%x)" % (kk, i0, i1)
        mant, se = ext_form(i0)
        return {"o0": mant, "o1": se | (top_sw(0) << 16), **nf}
    if stem == "fincstp_fdecstp_rt":
        n = kk + 1
        assert (i0, i1) == (n, 0), "fincstp_fdecstp_rt k=%d 次数不再由 kk 推出" % kk
        return {"o0": top_sw(n & 7), "o1": top_sw(0), **nf}
    assert stem == "ffree_tag"
    assert (i0, i1) == (kk, 8), "ffree_tag k=%d 不再是(第 kk 格, 栈深 8): (%x,%x)" % (
        kk, i0, i1)
    return {"o0": 3 << (2 * kk), "o1": top_sw(kk & 7), **nf}


# ====================================================================
# P6 异常(7 条, 全 [解析]): masked 路径上每类异常置哪几位 + 同时结果是什么位形
# 位段: IE0 DE1 ZE2 OE3 UE4 PE5 SF6 ES7(取证 2 真机 fnstsw 比对过)。
# 三条全节约束的审计侧读法:
#   - 全程 CW=0x037f(finit 后) -> RC=RN 就近取偶、PC=64 位扩展档、六类异常全屏蔽;
#   - ES 恒 0(取证 7 a): 屏蔽位没放开就不会交付, 所以期望式里不出现 0x0080;
#   - o1 的打包惯例沿用 P3: 结果 se(低 16) | sw(高 16) —— 表只有两个输出字段。
# ====================================================================
P6_STEMS = ("fdiv_zero_ze", "fsqrt_neg_ie", "fistp_oe", "stack_underflow_is",
            "denormal_ue", "precision_pe", "fnclex_clears")


def m80_dec(mant, se, what):
    """m80 位形 -> (符号, 尾数整数, 位移): 值 = (-1)^sign x mant x 2^(max(ef,1)-16446)。
    规格化与非规格化共用同一条式子(ef=0 时给出格距 2^-16445) —— 这就是"最小非规格化
    数与最小规格化数是相邻两格"的算式化, 不需要为 dmin 单开一条分支。"""
    ef = se & 0x7FFF
    assert ef != 0x7FFF, "%s: 本节不喂 Inf/NaN(那是 fdiv_zero_ze/fsqrt 的档): %x" % (
        what, se)
    if ef == 0:
        assert mant < X1_80, "%s: ef=0 却带显式整数位(伪规格化): %x" % (what, mant)
    else:
        assert mant & X1_80, "%s: 规格化档必须左规: %x" % (what, mant)
    return 1 if se >> 15 else 0, mant, max(ef, 1) - 16383 - 63


def ge_pow2(num, den, e):
    """num/den >= 2^e ?(纯整数比较; 负指数走"左移分子", 不会出现分数)"""
    return num >= (den << e) if e >= 0 else (num << -e) >= den


def floor_log2(num, den):
    """正分数 num/den -> floor(log2(.))。先按位长得粗值再各向调整一步(循环至多两圈,
    且比较是精确的) —— 不用 math.log2: 那会把参考机的 double 舍入当事实来源。"""
    e = num.bit_length() - den.bit_length() - 1
    while ge_pow2(num, den, e + 1):
        e += 1
    while not ge_pow2(num, den, e):
        e -= 1
    return e


def rne_grid(num, den, shift, k):
    """精确值 (num/den) x 2^shift 舍到格距 2^k 的整数倍 -> (mant, inexact, up)
    RC=RN(就近取偶): 平局(ties)取偶数一侧。up = 舍后量级**变大**, 也就是实测 C1
    跟的那一位(取证 a/i: 1/3 向上舍 -> C1=1, 1/7 向下舍 -> C1=0)。"""
    d = shift - k
    a, b = (num << d, den) if d >= 0 else (num, den << -d)
    q, r = divmod(a, b)
    if 2 * r > b or (2 * r == b and (q & 1)):
        return q + 1, True, True
    return q, bool(r), False


def m80_rnd(sign, num, den, shift):
    """精确值舍到 80 位扩展精度 -> (mant, se, inexact, up, overflow, tiny)。
    判据分三段写, 才能把"没 honor 精度档"与"舍错了"分成两种不同的 FAIL(与 P3 同):
      tininess 按**舍前**的精确量级判(IEEE 6.3 的可选判据, Intel 实现就是舍前);
      UE 只在 tiny **且** inexact 时置(dmin*2 那行 tiny 而精确 -> 不置);
      OE 只在舍后越出 ef<=0x7ffe 时置, 且按 IEEE 连带置 PE(向上出界 -> C1=1)。
    ef=0x7fff 是 Inf 的位形, 本函数只在 overflow 时返回它。"""
    assert num > 0, "P6 的入值不含零, 也没有互为相反数的加数: 向量被改坏了"
    E = floor_log2(num, den) + shift
    tiny = E < M80_EMIN
    k = max(E, M80_EMIN) - 63
    mant, inexact, up = rne_grid(num, den, shift, k)
    if mant == 0:                          # 舍到 ±0(下溢到零)
        return 0, (M80_SGN if sign else 0), inexact, up, False, tiny
    if mant >> 64:                         # 进位撑到 65 位 -> 升一档(值不变)
        mant >>= 1
        k += 1
    if mant < X1_80:
        assert k == M80_EMIN - 63, "尾数不足 64 位却不在非规格化格距上: k=%d" % k
        ef = 0
    else:
        ef = k + 16383 + 63
        if ef > 0x7FFE:                    # masked 的溢出路径给 ±Inf(取证 6 a6/G7d)
            return X1_80, (M80_SGN if sign else 0) | 0x7FFF, True, True, True, tiny
    return mant, (M80_SGN if sign else 0) | ef, inexact, up, False, tiny


XB_ADD, XB_MUL, XB_DIV = 0, 1, 2

# 与 isb_x87.c 的 XBOP 同集不同写: 那边是 C 常数(M80_E()/M80_1PN() 拼的), 这边是
# 式子。指数字段只在这一侧登记(表上放不下两个 m80 的 160 位) -> 内核侧若抄错指数,
# 结果位形必对不上, 由 o1 兜住; 若抄错尾数, 下面的入值断言当场报。
XBOP = (
    (1, 0),                                        # dmin: 非规格化最小正数 1 x 2^-16445
    (X1_80, m80_e(-16382)),                        # min_norm: 最小正规格化数
    (X1_80, m80_e(-1)),                            # 0.5
    (X1_80, m80_e(0)),                             # 1.0
    (X1_80, m80_e(1)),                             # 2
    (X1_80 | (1 << 62), m80_e(1)),                 # 3
    (X1_80 | (1 << 62) | (1 << 61), m80_e(2)),     # 7
    (X1_80, m80_e(-64)),                           # 2^-64 = 1.0 处 ULP 的一半
    (X1_80, m80_e(-65)),                           # 2^-65 = 不足半个 ULP
    (X1_80 | 1, m80_e(0)),                         # 1+2^-63(80 位可精确表示)
    (X1_80 | (1 << 62), m80_e(0)),                 # 1.5
    (X1_80, m80_e(126)),                           # 2^126
    (X1_80, m80_e(16383)),                         # 2^16383: 最大指数档的 2 的幂
)
BO_DMIN, BO_MINNORM, BO_HALF, BO_ONE, BO_TWO, BO_THREE, BO_SEVEN, \
    BO_2PM64, BO_2PM65, BO_1P2M63, BO_1P5, BO_2P126, BO_2P16383 = range(13)

# (op, li, ri) = "算的是 li op ri", ri 先入栈(在 ST1) —— 方向由两档非对称除法
# (dmin/2 与 1/3)在真机上钉住, 见 isb_x87.c 文件头 g)
XBDEN = ((XB_MUL, BO_DMIN, BO_DMIN), (XB_MUL, BO_DMIN, BO_HALF),
         (XB_DIV, BO_DMIN, BO_TWO), (XB_MUL, BO_DMIN, BO_TWO),
         (XB_ADD, BO_DMIN, BO_DMIN), (XB_MUL, BO_MINNORM, BO_HALF),
         (XB_MUL, BO_MINNORM, BO_DMIN), (XB_ADD, BO_ONE, BO_DMIN))
XBPRC = ((XB_DIV, BO_ONE, BO_THREE), (XB_DIV, BO_ONE, BO_SEVEN),
         (XB_ADD, BO_ONE, BO_2PM64), (XB_ADD, BO_ONE, BO_2PM65),
         (XB_MUL, BO_1P2M63, BO_1P2M63), (XB_MUL, BO_1P5, BO_TWO),
         (XB_MUL, BO_2P126, BO_2P126), (XB_MUL, BO_2P16383, BO_TWO))


def m80_bin(pa, pb, op):
    """两个 m80 的**精确**结果 -> (sign, num, den, shift); 全程整数, 不经 float,
    也不先把 dmin 提升成规格化(那是硬件在扩展精度里做的事, 提升就丢了下溢判据)"""
    sa, na, ha = m80_dec(pa[0], pa[1], "左操作数")
    sb, nb, hb = m80_dec(pb[0], pb[1], "右操作数")
    if op == XB_ADD:
        h = min(ha, hb)
        if sa == sb:
            return sa, (na << (ha - h)) + (nb << (hb - h)), 1, h
        x, y = na << (ha - h), nb << (hb - h)
        return (sa, x - y, 1, h) if x >= y else (sb, y - x, 1, h)
    if op == XB_MUL:
        return sa ^ sb, na * nb, 1, ha + hb
    assert op == XB_DIV
    return sa ^ sb, na, nb, ha - hb            # (na/nb) x 2^(ha-hb), den 不必既约


def x87_bin80_expect(stem, kk, table, i0, i1):
    """denormal_ue / precision_pe 共用(两条量的不是助记符, 而是**标志位的分工**):
      DE 跟入值走(操作数非规格化就置, 与结果无关);
      UE 跟"结果下溢且不精确"走;
      PE 跟精度损失走(舍回原值也算 —— 1.0+2^-64/2^-65 两行就是这么定的);
      OE 只在越上限时置(2^126*2^126 = 2^252 那行证"大指数本身不是 OE")。
    sw 的底是 TOP=7(fldt+fldt 再弹一格) -> 与探针的"运算后"读数同形。"""
    op, li, ri = table[kk]
    assert (i0, i1) == (XBOP[li][0], XBOP[ri][0]), \
        "%s k=%d 尾数入值不再是本节的向量: 表=(%x,%x) 算=(%x,%x)" % (
            stem, kk, i0, i1, XBOP[li][0], XBOP[ri][0])
    sign, num, den, shift = m80_bin(XBOP[li], XBOP[ri], op)
    mant, se, inexact, up, ovf, tiny = m80_rnd(sign, num, den, shift)
    fl = (SW_DE if (XBOP[li][1] & 0x7FFF) == 0 or (XBOP[ri][1] & 0x7FFF) == 0 else 0) \
        | (SW_PE if (inexact or ovf) else 0) | (SW_OE if ovf else 0) \
        | (SW_UE if (tiny and inexact) else 0) | (SW_C1 if up else 0)
    return mant, se, top_sw(7) | fl


# 空栈动作表: (名字, 压栈次数, 弹栈次数, 附带的 CC)。TOP = (0 - 压 + 弹)&7 就是
# 上面那四句话的直接应用, 所以八档的 sw 是推出来的不是抄来的:
#   弹栈双目族一次消耗两格、又把结果压回一格 -> 净 +1(G7e 实测 0x0841)
#   空栈 fld %st(0) 是压栈方向 -> TOP 走到 7(0x3841), 但栈错照报 IE|SF
#   空栈 fxch 不压不弹 -> TOP 不变而**仍报栈错**(0x0041: 按 SDM 推"不报"被实测推翻)
#   fld1;fcompp: 1 压 2 弹 -> 净 +1; 第二格按空栈读 -> 无序 -> C3C2C0=111(G7e/b9)
SU_ACTS = (("faddp", 1, 2, 0), ("fsubp", 1, 2, 0), ("fmulp", 1, 2, 0),
           ("fld_st0", 1, 0, 0), ("fxch_st1", 0, 0, 0), ("fstpt", 0, 1, 0),
           ("fstpt_x3", 0, 3, 0),
           ("fld1_fcompp", 1, 2, SW_C3 | SW_C2 | SW_C0))
SU = {r[0]: r[1:] for r in SU_ACTS}


def su_sw(pushes, pops, cc=0):
    """空栈上的动作 -> 状态字: 栈错恒为 IE|SF(取证 6 c)/G7e 两半互证), TOP 走净位移"""
    return top_sw((0 - pushes + pops) & 7, SW_IE | SW_SF | cc)


# fnclex 的八档"清理前"读数: 每档都从本节其它条的同一模型取(所以两条互为交叉验证,
# 而不是一处写死两处引用), 顺序 = isb_x87.c 的 switch(kk):
#   1/0 -> ZE; sqrt(-1) -> IE; 1+1 -> 无异常对照; 第 9 次 fld1 -> 溢出 IE|SF|C1
#   (压栈方向 TOP-1 -> (0-9)&7 = 7); 后四档 = stack_underflow_is 的 5/3/4/7 档
FC_ROWS = (top_sw(7, SW_ZE), top_sw(7, SW_IE), top_sw(7),
           top_sw((0 - 9) & 7, SW_IE | SW_SF | SW_C1),
           su_sw(*SU["fstpt"]), su_sw(*SU["fld_st0"]), su_sw(*SU["fxch_st1"]),
           su_sw(*SU["fld1_fcompp"]))


# fsqrt_neg_ie 的八档 double 位形(与 isb_x87.c 的 SQRTA 同集): 那边用 D_POW2()/D_NEG
# 拼, 这边用本节的 d_pow2()。★ Inf/NaN 不走 d_pow2(): 它自带"只接规格化区"的护栏
# (那个护栏本身是取证 5 的产物), 而这里的 2^1024 要的恰好是**指数域全 1** 那个不该
# 出现在规格化区的位形 -> 另写一个明面常数, 不拿越护栏的调用当巧合。
D_INF = 0x7FF << 52                           # +Inf 的 double 位形(指数域全 1、尾数 0)
SQRTA = (d_pow2(0), d_pow2(0) | (1 << 63), d_pow2(2) | (1 << 63), 1 << 63,
         (1 << 63) | 1, D_INF | (1 << 63), D_INF | (1 << 63) | (1 << 51),
         d_pow2(2))


def fsqrt_model(bits):
    """FSQRT 负值族(fsqrt_neg_ie 的八档) -> (mant, se, flags)。#IE 的判据按 SDM 是
    **源 < 0**, 于是 -0 与 NaN 都不入判(取证 7 G7a 八档全中这一条):
      NaN(本节只有 -QNaN) -> 比较不成立 -> 原值静默返回(尾数左规、指数域全 1);
      负数(含 -Inf、-dmin) -> IE + integer-indefinite;
      -0 -> -0 精确、无任何异常;
      正的 2 的偶次幂 -> 开方精确(mant=X1、指数减半、不置 PE)。
    ★ 另有一位不在 FSQRT 头上而在**装载**头上: FLDL 一个非规格化 double 就置 DE
      (源要经过格式转换), 而 FLD 一个非规格化 m80 不置(无需转换) —— 探针 G7a 的
      dmin 两档入的是 m80 形, 故它那里读不到这一位; 本条的 -dmin 入的是 double 形
      (SQRTA[4] = 0x...0001)。三个锦点见 _tmp/x87_p6chk.txt 的 A(fldl +dmin -> 3802)/
      C(fldt +dmin -> 3800)/E1(不写 asm、只算 dmin*2 -> sw=0002)。
    +dmin 那一档(真值 2^-8222.5 是无理尾数)按计划不上表, 所以这里遇到就报。"""
    sign = 1 if bits >> 63 else 0
    e = (bits >> 52) & 0x7FF
    frac = bits & ((1 << 52) - 1)
    de = SW_DE if (e == 0 and frac) else 0      # 装载侧的 DE(仅非规格化 double 入值)
    if e == 0x7FF and frac:                        # NaN: 静默返回原值
        assert sign and (frac >> 51), "fsqrt_neg_ie 只取 -QNaN 档: %x" % bits
        return X1_80 | (frac << 11), 0xFFFF, de
    if e == 0 and frac == 0:                       # ±0: 结果同符号零, 无异常
        return 0, (M80_SGN if sign else 0), de
    if sign:                                       # 源 < 0(含 -Inf)-> #IE
        return INDEF80_M, INDEF80_S, SW_IE | de
    assert e != 0x7FF, "sqrt(+Inf) 不在本档(它精确、结果 +Inf): %x" % bits
    assert frac == 0, "sqrt(非 2 的幂的正数)不在本档(尾数推不出来): %x" % bits
    exp2 = e - 1023
    assert exp2 % 2 == 0, "奇数指数的开方落到 2 的半次幂, 本档不含: 2^%d" % exp2
    return X1_80, m80_e(exp2 // 2), de


def fistp_arm(kk):
    """fistp_oe 的第 kk 档 -> (mant, se, 宽度)。八档 = m32/m16 各四:
    2^N / 2^N-0.5 / -2^N(在量程内!) / 远越界。2^N-0.5 写成 (2-2^-N) x 2^(N-1) 的
    尾数 = -2^(63-N)(无符号回绕), 与探针的 E_2P31M 同字(取证 7 G7b 反验过)。"""
    w16 = kk >= 4
    far = kk in (3, 7)
    e = (20 if far else 15) if w16 else (40 if far else 31)
    half = kk in (1, 5)                       # "2^N-0.5" 档(远越界档不取半)
    mant = (-(1 << (63 - e))) & M64 if half else X1_80
    se = (M80_SGN if kk in (2, 6) else 0) | m80_e(e - 1 if half else e)
    return mant, se, 16 if w16 else 32


def p6_expect(stem, i0, i1, inf, kk):
    """P6 的[解析]期望(逐档可追溯到 _tmp/x87_c_pe.txt 的取证 7 实测行):
      fdiv_zero_ze : 非零/±0 -> 只 ZE + 结果 ±Inf(符号 = 两操作数符号亦或);
                     0/0 的四档符号组合**全部**给同一个 -QNaN indefinite 且只置 IE
      fsqrt_neg_ie : 见 fsqrt_model()(#IE 的判据是源<0, 不是"源为负或 NaN")
      fistp_oe     : ★ 词干名里的 oe 是计划写的, **实测是 IE**: 越界写该宽度的整数
                     最小值且只置 IE(连 2^N-0.5 那档先舍后判也不置 PE); -2^N 档在
                     量程内、写回值与越界档**字面相同**, 只靠 sw 分开
      stack_underflow_is : o0 = 推出来的 sw, o1 = INDEF_M —— 八行同值是刻意的:
                     "栈错的代价只在状态字上、内存侧一律同一个填充"这条不变式
      denormal_ue / precision_pe : 见 x87_bin80_expect()(两档共用一个模型)
      fnclex_clears: o0 = 八档清理前读数(全部由本节其它条的模型推), 而
                     **o1 == o0 & ~0xff** 是取证 7 b) 三个实测对钉下的规则:
                     清 IE..PE + SF + ES, 不清 C0/C1/C2/C3/TOP(0x3a41->0x3a00 里
                     留下的就是 C1)。入值 i1 = 本档该在 o0 里看到的异常位 -> 顺带
                     与内核侧的 FC_MASK 对账。
    标志一侧同 P1/P2/P3: x87 不碰 EFLAGS -> outf == inf 的六个位。"""
    nf = flags_of_inf(inf)
    if stem == "fdiv_zero_ze":
        asig, bsig = (kk >> 1) & 1, kk & 1
        a = (d_pow2(0) if kk < 4 else 0) | (asig << 63)
        b = bsig << 63
        assert (i0, i1) == (a, b), "fdiv_zero_ze k=%d 符号组合的入值口径变了: (%x,%x)" \
                                   % (kk, i0, i1)
        if kk < 4:
            se = 0x7FFF | ((M80_SGN if (asig ^ bsig) else 0))
            return {"o0": X1_80, "o1": se | (top_sw(7, SW_ZE) << 16), **nf}
        return {"o0": INDEF80_M,
                "o1": INDEF80_S | (top_sw(7, SW_IE) << 16), **nf}
    if stem == "fsqrt_neg_ie":
        assert i1 == 0, "fsqrt_neg_ie k=%d 的单目口径变了(i1 应为 0): %x" % (kk, i1)
        assert i0 == SQRTA[kk], "fsqrt_neg_ie k=%d 入值不再是本节的八档: 表=%x 算=%x" \
                                % (kk, i0, SQRTA[kk])
        mant, se, fl = fsqrt_model(i0)
        return {"o0": mant, "o1": se | (top_sw(7, fl) << 16), **nf}
    if stem == "fistp_oe":
        mant, se, w = fistp_arm(kk)
        assert (i0, i1) == (mant, se | (w << 16)), \
            "fistp_oe k=%d 入值不再是(尾数, se|宽度<<16): (%x,%x)" % (kk, i0, i1)
        sign, num, shift = m80_dec(mant, se, "fistp_oe 源操作数")
        q, _, _ = rne_grid(num, 1, shift, 0)          # 按当前 RC(RN) 先舍到整数
        v = -q if sign else q
        lo, hi = -(1 << (w - 1)), (1 << (w - 1)) - 1
        sw = SW_IE if (v < lo or v > hi) else 0       # 越界是 #IA, 不是 OE(取证 7 b)
        res = lo if sw else v
        # bit16 = 「只写了 W 字节、高位仍是哨兵」(取证 h 的实测写宽), 期望恒为 1
        return {"o0": res & M64, "o1": sw | (1 << 16), **nf}
    if stem == "stack_underflow_is":
        assert (i0, i1) == (kk, 1 if kk == 7 else 0), \
            "stack_underflow_is k=%d 的(档位, 动作前栈深)口径变了: (%x,%x)" % (
                kk, i0, i1)
        return {"o0": su_sw(*SU_ACTS[kk][1:]), "o1": INDEF80_M, **nf}
    if stem in ("denormal_ue", "precision_pe"):
        mant, se, sw = x87_bin80_expect(stem, kk,
                                        XBDEN if stem == "denormal_ue" else XBPRC,
                                        i0, i1)
        return {"o0": mant, "o1": se | (sw << 16), **nf}
    assert stem == "fnclex_clears"
    before = FC_ROWS[kk]
    assert i0 == kk and i1 == (before & 0xFF), \
        "fnclex_clears k=%d 的异常位掩码与推导出的清理前读数不符: 表 i1=%x 推 o0=%x" % (
            kk, i1, before)
    return {"o0": before, "o1": before & ~0xFF, **nf}


# ====================================================================
# P7 特殊与组合(8 条, 全 [解析]): 比较码 / 方向对 / FSCALE / FXAM / 状态字
# 全位 / fninit。sw 位段同 P5/P6: TOP=bits 11-13、C0/C2/C3=bits 8/10/14。
# ====================================================================
P7_STEMS = ("fcom_cc", "fcompp_cc", "fsubr_pair", "fisubr_m64",
            "fscale_int", "fxam_kinds", "fstsw_allbits", "fninit_defaults")
P7_ZERO, P7_MZERO = 0, 1 << 63
P7_ONE, P7_TWO, P7_FOUR = d_pow2(0), d_pow2(1), d_pow2(2)
P7_2P62, P7_HALF = d_pow2(62), d_pow2(-1)
P7_1P5 = d_pow2(0) | (1 << 51)
P7_2P5 = d_pow2(1) | (1 << 51)
P7_3 = d_pow2(1) | (1 << 51)
P7_100 = d_pow2(6) | (1 << 51) | (1 << 48)
P7_PINF, P7_QNAN, P7_SNAN = 0x7FF0000000000000, 0x7FF8000000000000, 0x7FF4000000000001


def p7_dbl(bits):
    return struct.unpack("<d", struct.pack("<Q", bits & M64))[0]


def i64_to_m80(v):
    """带符号整数(任意量级) -> 左规 m80 (mant, se): 显式整数位恒 1。用 v 本身而非
    位形, 所以能表示超过 int64 量程的正结果(档 6 的 1.5x2^63)。"""
    sign = 1 if v < 0 else 0
    a = -v if v < 0 else v
    if a == 0:
        return 0, (sign << 15)
    hi = a.bit_length() - 1
    return (a << (63 - hi)) & M64, (sign << 15) | (hi + 16383)


def d2m80(bits):
    """double 位形 -> m80 (mant, se): 有限值左规; Inf 指数全 1; NaN 按硬件 quiet
    (置 bit62)并保留载荷(frac<<11)。fxam_kinds 的存回档用它。"""
    sign = 1 if bits >> 63 else 0
    e = (bits >> 52) & 0x7FF
    frac = bits & ((1 << 52) - 1)
    if e == 0x7FF:
        if frac == 0:
            return X1_80, (sign << 15) | 0x7FFF
        return (X1_80 | (1 << 62) | (frac << 11)) & M64, (sign << 15) | 0x7FFF
    assert frac == 0 if e == 0 else True, "d2m80 不含 double 非规格化档: %x" % bits
    if e == 0:
        return 0, (sign << 15)
    return ((1 << 52) | frac) << 11, (sign << 15) | (16383 + (e - 1023))


P7_FCOP = ((P7_TWO, P7_ONE), (P7_ONE, P7_TWO), (P7_FOUR, P7_FOUR), (P7_QNAN, P7_ONE),
           (P7_ONE, P7_MZERO), (P7_MZERO, P7_ZERO), (P7_PINF, P7_PINF),
           (P7_PINF | (1 << 63), P7_PINF))
P7_FSUBAB = ((P7_FOUR, P7_ONE), (P7_TWO, P7_FOUR))
P7_FIA = (P7_FOUR, P7_2P62)
P7_FIC = (3, 3, 0x00020003, 0x7FFFFFFF, 3, 3, 1 << 63, (1 << 62) | 1)
P7_FSA = (P7_ONE, P7_FOUR, P7_FOUR, P7_FOUR, P7_FOUR, P7_3, P7_ONE, P7_FOUR)
P7_FSN = (P7_2P5 | (1 << 63), P7_2P5 | (1 << 63), P7_1P5 | (1 << 63),
          P7_HALF | (1 << 63), P7_1P5, P7_2P5, P7_100 | (1 << 63), P7_MZERO)
P7_FXAV = (P7_ZERO, P7_MZERO, P7_ONE, P7_PINF, P7_QNAN, P7_SNAN, P7_ONE, 0x4000000000000000)
P7_FXA_CC = (0x4000, 0x4000, 0x0400, 0x0500, 0x0100, 0x0100, 0x4100, 0x4400)
P7_FXA_C1 = (0, 0x0200, 0, 0, 0, 0, 0, 0)
P7_DIRTY_SW = (0x3804, 0x3801, 0x3802, 0x3A41, 0x0841, 0x3841, 0x0041, 0x4D41)
P7_CW_BEFORE = (0x037F, 0x037F, 0x037F, 0x007F, 0x037F, 0x037F, 0x037F, 0x037F)
FDIRTY = (0x0004, 0x0001, 0x0002, 0x0041, 0x0041, 0x0041, 0x0041, 0x0041)


def p7_cc(d0, d1):
    """ST0=d0 vs 源=d1 -> sw 低 16 的 CC/IE 部分(SDM 四句话)。"""
    if d0 != d0 or d1 != d1:
        return SW_C3 | SW_C2 | SW_C0 | SW_IE
    if d0 > d1:
        return 0
    if d0 < d1:
        return SW_C0
    return SW_C3


def p7_expect(stem, i0, i1, inf, kk):
    """P7 的 8 条[解析]期望(逐条与 isb_x87.c 第 7 节注同序)。全节共用: x87 不碰
    EFLAGS -> outf == inf 的六个位。"""
    nf = flags_of_inf(inf)
    if stem == "fcom_cc":                      # fldl a; fcoml b — 不弹栈
        assert (i0, i1) == P7_FCOP[kk], "fcom_cc k=%d 入值口径变了" % kk
        cc = p7_cc(p7_dbl(i0), p7_dbl(i1))
        return {"o0": top_sw(7, cc), "o1": top_sw(0, cc), **nf}
    if stem == "fcompp_cc":                    # ST0=i1(后压), ST1=i0(先压)
        assert (i0, i1) == P7_FCOP[kk], "fcompp_cc k=%d 入值口径变了" % kk
        cc = p7_cc(p7_dbl(i1), p7_dbl(i0))
        return {"o0": top_sw(0, cc), "o1": top_sw(7, cc), **nf}
    if stem == "fsubr_pair":
        # 实测方向与 C 注释相反(GAS 的 fsubp %st,%st(1) 算的是 ST(1)=ST(0)-ST(1)):
        # case0/case3 -> b-a, case1/case2 -> a-b。硬件真值逐档见下。
        assert (i0, i1) == P7_FSUBAB[kk & 1], "fsubr_pair k=%d 入值口径变了" % kk
        av, bv = int(p7_dbl(i0)), int(p7_dbl(i1))
        res = (bv - av) if (kk >> 1) in (0, 3) else (av - bv)
        mant, se = i64_to_m80(res)
        return {"o0": mant, "o1": se | (0x3800 << 16), **nf}
    if stem == "fisubr_m64":
        m = kk >> 2
        assert (i0, i1) == (P7_FIA[m], P7_FIC[kk]), "fisubr_m64 k=%d 入值口径变了" % kk
        av = int(p7_dbl(i0))
        cv = sgn(i1 & M32, 32) if m == 0 else sgn(i1, 64)
        res = (av - cv) if (kk & 1) == m else (cv - av)   # m32/m64 的 R 位向反
        mant, se = i64_to_m80(res)
        return {"o0": mant, "o1": se | (0x3800 << 16), **nf}
    if stem == "fscale_int":                   # fldl n; fldl a; fscale — 不弹栈
        # 入值取表里实际位形(不再拄理想向量): isb_x87.c 的 D_2P5/D_THREE 宏是
        # "指数域 OR" 而非构造尾数 -> D_2P5=3.0、D_THREE=+Inf(与注释不符)。
        # 这是探针输入侧的缺陷, 审计按事实复算(待采集侧修宏后重采)。
        mant, a_se = d2m80(i0)                  # a 的 m80(含 Inf)
        res_se = a_se if ((i0 >> 52) & 0x7FF) == 0x7FF else a_se + int(p7_dbl(i1))
        st1_se = d2m80(i1)[1]
        return {"o0": mant, "o1": res_se | (0x3000 << 16) | (st1_se << 32), **nf}
    if stem == "fxam_kinds":
        shape = 0 if kk <= 5 else (1 if kk == 6 else 2)
        assert (i0, i1) == (P7_FXAV[kk], shape), "fxam_kinds k=%d 入值口径变了" % kk
        if shape == 2:
            mant, se = 0x4000000000000000, 0x0000
        elif shape == 1:                        # ffree 后存回的是 indefinite, 非原值
            mant, se = 0xC000000000000000, 0xFFFF
        else:
            mant, se = d2m80(i0)
        sw = top_sw(7, P7_FXA_CC[kk] | P7_FXA_C1[kk] | (SW_IE if kk == 5 else 0))
        return {"o0": mant, "o1": se | (sw << 16), **nf}
    if stem == "fstsw_allbits":
        assert (i0, i1) == (kk, FDIRTY[kk]), "fstsw_allbits k=%d 入值口径变了" % kk
        return {"o0": P7_DIRTY_SW[kk], "o1": 0, **nf}
    assert stem == "fninit_defaults"
    assert (i0, i1) == (kk, FDIRTY[kk]), "fninit_defaults k=%d 入值口径变了" % kk
    return {"o0": P7_DIRTY_SW[kk] | (P7_CW_BEFORE[kk] << 16),
            "o1": 0x0000FFFF0000037F, **nf}


# 在册词干与审计实现的对账(六个分节各自的名字集必须无重叠地铺满 X87_STEMS):
# 只登记不纳审 -> 那一行会被当"未纳审"白过; 只纳审不登记 -> 采不到数也没人响。
X87_LEGACY = ("fld_fstp", "fadd", "fmul", "fistp", "fcomip", "fcw_rt")
X87_COVER = (set(P1_STEMS) | set(P2_STEMS) | set(P3_STEMS) | set(P5_STEMS)
             | set(P6_STEMS) | set(P7_STEMS) | set(X87_LEGACY))
assert len(X87_COVER) == len(P1_STEMS) + len(P2_STEMS) + len(P3_STEMS) \
    + len(P5_STEMS) + len(P6_STEMS) + len(P7_STEMS) + 6, \
    "x87 六个分节的词干集有重叠(同一词干被两处分派 = 其一对它是误解)"
assert X87_COVER == set(X87_STEMS), \
    "x87 在册词干与审计实现不同步: 缺 %s / 多 %s" % (
        sorted(set(X87_STEMS) - X87_COVER), sorted(X87_COVER - set(X87_STEMS)))

# 在册词干与审计实现全覆盖: MAIN 不再有"未纳审"分支(旧 AUDIT_UNCOVERED_GRP /
# X87_P7 两处 SKIP 已随本四组与 x87 P7 的反算落地而删除)。

def x87_n24(stem, *vals):
    """迁入的 n/4 族入值口径(x87n(): 24 位且低位强制为 1)。本函数断的是
    **口径没被改坏**, 不是"值小所以真值可比" —— 后者只对下面 fadd/fmul 那两次
    float() 除法成立, 旧版把同一条 assert 钉在 fistp 上是错的(它是纯整数 divmod,
    对 P1 的整型往返更不成立: SDM 明写 FILD m64int 无舍入装载)。"""
    for v in vals:
        assert v == ((v & 0xFFFFFF) | 1), \
            "%s: 入值不再是 x87n() 的 24 位口径: %x" % (stem, v)


def x87_legacy_expect(stem, i0, i1, inf):
    """自 special 迁入的 6 条的反算(口径逐条照 Intel SDM, 与 C 探针无关):
      fld/fstp : 位形原样搬 -> o0 = double(i0/4); 架构上不碰 EFLAGS
      fadd     : o0 = double((i0+i1)/4)   —— 分子 <= 25 位, 任何精度档都精确
      fmul     : o0 = double((i0*i1)/16)  —— 分子 <= 48 位, 扩展精度与 double 都精确
      fistp    : o0 = 就近取偶(i0/4) 的 64 位整数(finit 后 RC=00b = 最近舍入)
      fcomip   : 只比 CF/ZF/PF 三位(SDM: OF/SF/AF 未定义)。栈序是 fld i0; fld i1
                 -> ST0 是 i1 的值、ST1 是 i0 的值, 所以按 ST0 vs ST1 判大小
      fcw_rt   : fldcw 写进去什么就该 fnstcw 读回什么 -> o0 == i0; 并且入值必须是
                 8 个合法编码之一(RC 四档 x PC 53/64 两档) —— 不合法时不算目标机
                 把指令译错了, 算入值口径被改坏了(被硬件强制的位上「读回==写入」
                 不是可保证的期望: 实测位 6 恒 1、位 7 与 13-15 恒 0, 见组头注 g3)
    除 fcomip 外那五条都断言标志不受影响(outf == inf 的标志位), 抓的是「把 x87
    降级成 SSE 实现时顺手踩了标志」这一类翻译错误。
    ★ 与 P1 的关系: 两套入值口径并存且**不许互相统一** —— 本节是 n/4(<=24 位,
      刻意保证 double 也能精确表示), P1 是高有效位向量(要的正是两者不等)。"""
    if stem in ("fld_fstp", "fadd", "fmul", "fistp", "fcw_rt"):
        flags = flags_of_inf(inf)
    if stem == "fld_fstp":
        x87_n24(stem, i0)
        return {"o0": fbits(i0, 4), "o1": 0, **flags}
    if stem == "fadd":
        x87_n24(stem, i0, i1)
        assert (i0 + i1).bit_length() <= 53, \
            "fadd: 分子出 double 精确区, fbits() 的 float 除法不能再当期望: %x" % (i0 + i1)
        return {"o0": fbits(i0 + i1, 4), "o1": 0, **flags}
    if stem == "fmul":
        x87_n24(stem, i0, i1)
        assert (i0 * i1).bit_length() <= 53, \
            "fmul: 分子出 double 精确区, fbits() 的 float 除法不能再当期望: %x" % (i0 * i1)
        return {"o0": fbits(i0 * i1, 16), "o1": 0, **flags}
    if stem == "fistp":
        # 纯整数算式 -> 不需要量级前提(旧版这里的 assert 已按计划降级到
        # 上面的 fadd/fmul: 那两条才真的靠 float() 算位形)
        x87_n24(stem, i0)
        q, r = divmod(i0, 4)
        if r == 2:                       # 平局 -> 向偶数取(SDM 的 round-to-nearest)
            q += q & 1
        elif r == 3:
            q += 1
        return {"o0": q, "o1": 0, **flags}
    if stem == "fcw_rt":
        # 入值集**按位段构造**, 不抄一张 8 个常数的表 —— 抄表正是旧版出错的地方:
        # 原来那 8 个值(0x0273/0x0277/...) 是按"RC 在位 2-3"算的, 与当时探针一致所以
        # 「过」, 但跟硬件里真正的 RC 无关。现在两边各自按同一个位段定义算(实测
        # RC=位 10-11、PC=位 8-9, 见组头注 g1/g2), 哪一侧被改坏都会在这里断掉。
        legal = {0x0073 | rc << 10 | pc for rc in range(4) for pc in (0x0200, 0x0300)}
        assert i0 in legal, "fcw_rt 入值不是合法控制字编码: %x" % i0
        return {"o0": i0, "o1": 0, **flags}
    assert stem == "fcomip"
    if i1 > i0:
        return {"CF": 0, "ZF": 0, "PF": 0}
    if i1 < i0:
        return {"CF": 1, "ZF": 0, "PF": 0}
    return {"CF": 0, "ZF": 1, "PF": 0}


def x87_expect(stem, i0, i1, inf, kk):
    """x87 组反算入口: P1 的 12 条、P2 的 5 条、P3 的 3 条、P5 的 6 条、P6 的 7 条
    各走自己的[解析]推导, 迁入的 6 条沿旧口径。五支之间靠词干集合分派, 而词干集本身
    由下面的 X87_COVER 断言与 X87_STEMS 对账 —— 在册却不纳审(或反过来)都在 import 就断。
    未登记的词干直接报错而不是返回 None —— 本组的表由本文件全量推导, "未纳审"
    在这里只能意味着两张表的词干集不同步(那是必须当场响的缺陷)。"""
    assert stem in X87_W, "x87 组词干未登记审计实现: " + stem
    if stem in P1_STEMS:
        return p1_expect(stem, i0, i1, inf, kk)
    if stem in P2_STEMS:
        return p2_expect(stem, i0, i1, inf, kk)
    if stem in P3_STEMS:
        return p3_expect(stem, i0, i1, inf, kk)
    if stem in P5_STEMS:
        return p5_expect(stem, i0, i1, inf, kk)
    if stem in P6_STEMS:
        return p6_expect(stem, i0, i1, inf, kk)
    if stem in P7_STEMS:
        return p7_expect(stem, i0, i1, inf, kk)
    return x87_legacy_expect(stem, i0, i1, inf)


def special_expect(stem, i0, i1, inf, w):
    """special 组的反算(口径逐条照 Intel SDM, 与 C 探针无关):
      xchg(r/m) : 两 operand 互换, 六个标志全不受影响(SDM: XCHG 不改标志);
                  内存形的隐式锁也不改架构结果 -> lock_ 前缀共用本规则
      cmpxchg   : acc(i0) 与目的(内存 i1) 比 -> 等: 内存<-src(acc+2, 探针由 i0
                  反算、不占入值槽)、acc 不变; 不等: acc<-内存、内存不变。
                  标志 = SUBTRACT(acc, 内存); lock 形同真值
      xadd      : 目的(内存 i1) <- i0+i1, acc <- 内存入值(AT&T 的源=%eax)
      movsb/stosb: 只动目的低 1 字节, 高 7 字节保持; o1 = 指针推进量(探针写 1)
      cmpsb     : 不写结果, 真值全在标志 = SUBTRACT(两侧低字节, 8 位)
      rep movsb/stosb: 跑完 8 字节 -> 目的 = 全 8 字节源 / v 广播; o1 = 剩余计数 0
    原本里的 x87 六条已连内核一起迁到 x87 组(分派见 expect() 的 grp) —— 本函数
    不再接它们, 否则就是按词干分派的老坑(拿 x87 的实现把 special 的 stale 行审成 8/8)。
    """
    mask = (1 << w) - 1
    if stem in ("xchg_r", "xchg_m", "lock_xchg_r", "lock_xchg_m"):
        return {"o0": i1, "o1": i0, **flags_of_inf(inf)}
    if stem in ("cmpxchg", "lock_cmpxchg"):
        res, _, f = add_sub(i0, i1, 0, w, True)
        # 比较结果的 ZF 就是两值是否相等 —— add_sub 已按 res==0 算过, 不另给
        assert res == 0 or i0 != i1, "%s: 相等/不等两支划分不自洽" % stem
        if i0 == i1:
            return {"o0": i0, "o1": (i0 + 2) & mask, **f}
        return {"o0": i1, "o1": i1, **f}
    if stem in ("xadd", "lock_xadd"):
        res, _, f = add_sub(i1, i0, 0, w, False)   # dst=内存(i1) += acc(i0)
        return {"o0": i1, "o1": res, **f}
    if stem in ("movsb", "stosb"):
        return {"o0": (i1 & ~0xFF) | (i0 & 0xFF), "o1": 1, **flags_of_inf(inf)}
    if stem == "cmpsb":
        _, _, f = add_sub(i0 & 0xFF, i1 & 0xFF, 0, 8, True)
        return {"o0": 0, "o1": 1, **f}
    if stem == "rep_movsb":
        return {"o0": i0, "o1": 0, **flags_of_inf(inf)}
    if stem == "rep_stosb":
        return {"o0": (i0 & 0xFF) * 0x0101010101010101, "o1": 0,
                **flags_of_inf(inf)}
    return None                                    # 本词干未纳审(交给 main 报)


# ==================== vec 组(直写): 128 位 SIMD 反算 ====================
# 输入构造与 isb_vec.c 的 VIN/VIN2/fpd 各写一遍、互不参照(独立复核口径)。
# 结果宽 128 位, 而上表只有 o0/o1 两个 64 位槽 -> 按低/高 qword 拆两个字段审。
# 整数 lane 族架构上不碰 EFLAGS -> inf/outf 记 0 = 不审(与 bits 组同一约定);
# 只上标志的那二族(ptest/comisd)只审 CF/PF/ZF(0x045) —— SF/AF/OF 架构未定义。
VEC_OPS = {"psrlw", "psrld", "psrlq", "psllq", "psraw", "punpcklwd", "punpcklbw",
           "punpcklqdq", "pshuflw", "pshufd", "packuswb", "paddq", "psubd",
           "pand", "por", "pmulhuw", "pmullw", "pmuludq", "pmovmskb",
           "movd_in", "movd_out", "ptest", "comisd", "cvtsi2sd", "cvtdq2pd",
           "roundsd"}
M128 = (1 << 128) - 1        # M64 已在上面的 x87 段定义(同值), 本段只补 128 位


def rb64(x, n):
    """64 位循环右移(= isb_vec.c 的 RB64)"""
    x &= M64
    return ((x >> n) | (x << (64 - n))) & M64


def v_ab(i0, i1):
    """a = (低 qword = i0, 高 qword = i1); b = (低 = i1, 高 = rb64(i0,13))
    —— b 不取 a 的交换形, 否则两 lane 同值、「lane 序译反」检不出来"""
    return (i1 << 64) | i0, (rb64(i0, 13) << 64) | i1


def lanes(x, w):
    """128 位整数 -> 由低到高的 w 位 lane 列表"""
    m = (1 << w) - 1
    return [(x >> (i * w)) & m for i in range(128 // w)]


def unlanes(vals, w):
    """lane 列表 -> 128 位整数(每个值截到 w 位)"""
    m = (1 << w) - 1
    return sum((v & m) << (i * w) for i, v in enumerate(vals)) & M128


def shiftn(x, w, n, arith=False, left=False):
    """逐 lane 移位: 逻辑右移 / 算术右移 / 左移(计数小于 lane 宽 -> 不涉饱和)"""
    m = (1 << w) - 1
    out = []
    for v in lanes(x, w):
        if left:
            out.append((v << n) & m)
        elif arith and (v >> (w - 1)) & 1:
            out.append(((v - (1 << w)) >> n) & m)   # Python 的 >> 对有符号数是算术移
        else:
            out.append(v >> n)
    return unlanes(out, w)


def pair(r):
    """128 位结果 -> {o0, o1}"""
    return {"o0": r & M64, "o1": (r >> 64) & M64}


def dbits(x):
    """64 位整数位形 -> IEEE double"""
    return struct.unpack("<d", struct.pack("<Q", x & M64))[0]


def fbits64(d):
    """double -> 64 位整数位形"""
    return struct.unpack("<Q", struct.pack("<d", d))[0]


def vec_expect(stem, i0, i1, inf, w):
    """vec 组 26 词干的反算。入值语义分两类(与探针一致):
      整数族: i0/i1 就是哈希整数(即 lane 内容)
      浮点族: comisd/roundsd 上表的 i0/i1 已是 double 位形(探针把造好的有限值
              回填进 i 列), 所以这里直接当 double 看; cvtsi2sd/cvtdq2pd 的
              i0 是整数源。"""
    a, b = v_ab(i0, i1)
    if stem == "psrlw":
        return pair(shiftn(a, 16, 3))
    if stem == "psrld":
        return pair(shiftn(a, 32, 5))
    if stem == "psrlq":
        return pair(shiftn(a, 64, 7))
    if stem == "psllq":
        return pair(shiftn(a, 64, 11, left=True))
    if stem == "psraw":
        return pair(shiftn(a, 16, 3, arith=True))
    if stem in ("punpcklwd", "punpcklbw", "punpcklqdq"):
        cw = {"punpcklwd": 16, "punpcklbw": 8, "punpcklqdq": 64}[stem]
        al, bl = lanes(a, cw), lanes(b, cw)
        half = 64 // cw                          # 只取低半(= 每侧 8/cw*4 个)
        return pair(unlanes([v for i in range(half) for v in (al[i], bl[i])], cw))
    if stem in ("pshuflw", "pshufd"):
        cw = 16 if stem == "pshuflw" else 32
        al = lanes(a, cw)
        sel = [(0x4E >> (2 * i)) & 3 for i in range(4)]   # imm8=0x4E -> 2,3,0,1
        lo = [al[i] for i in sel]
        # pshuflw 只动低 4 个 word(高 4 个原样带走), pshufd 四个 dword 全动
        return pair(unlanes(lo + (al[4:] if cw == 16 else []), cw))
    if stem == "packuswb":
        sat = [0 if sgn(v, 16) < 0 else (255 if sgn(v, 16) > 255 else sgn(v, 16))
               for v in lanes(a, 16) + lanes(b, 16)]
        return pair(unlanes(sat, 8))
    if stem == "paddq":
        al, bl = lanes(a, 64), lanes(b, 64)
        return pair(unlanes([(x + y) & M64 for x, y in zip(al, bl)], 64))
    if stem == "psubd":
        al, bl = lanes(a, 32), lanes(b, 32)
        return pair(unlanes([(x - y) & 0xFFFFFFFF for x, y in zip(al, bl)], 32))
    if stem == "pand":
        return pair(a & b)
    if stem == "por":
        return pair(a | b)
    if stem in ("pmulhuw", "pmullw"):
        al, bl = lanes(a, 16), lanes(b, 16)
        p = [(x * y) for x, y in zip(al, bl)]
        return pair(unlanes([(v >> 16) & 0xFFFF for v in p] if stem == "pmulhuw"
                            else [v & 0xFFFF for v in p], 16))
    if stem == "pmuludq":
        al, bl = lanes(a, 32), lanes(b, 32)
        return {"o0": (al[0] * bl[0]) & M64, "o1": (al[2] * bl[2]) & M64}
    if stem == "pmovmskb":
        return {"o0": sum(((a >> (8 * j + 7)) & 1) << j for j in range(16)), "o1": 0}
    if stem == "movd_in":
        return {"o0": i0 & 0xFFFFFFFF, "o1": 0}
    if stem == "movd_out":
        return {"o0": i0 & 0xFFFFFFFF, "o1": 0}
    if stem == "cvtsi2sd":
        return {"o0": fbits64(float(sgn(i0, 32))), "o1": i1}
    if stem == "cvtdq2pd":
        return {"o0": fbits64(float(sgn(i0, 32))),
                "o1": fbits64(float(sgn(i0 >> 32, 32)))}
    if stem == "ptest":
        return {"CF": 1 if ((a & ~b) & M128) == 0 else 0,
                "ZF": 1 if (a & b) == 0 else 0,
                "PF": 1 if ((a | b) & M128) == 0 else 0}
    if stem == "comisd":
        x, y = dbits(i0), dbits(i1)
        return {"CF": 1 if x < y else 0, "ZF": 1 if x == y else 0, "PF": 0}
    if stem == "roundsd":
        return {"o0": fbits64(float(round(dbits(i0)))), "o1": i1}
    return None


def width_of_stem(stem, grp=None):
    """词干 -> 审计宽度。cc 三族要单独定: 探针骨架写死 32 位(见 ib_gen.h 15Km
    的头注 —— 一张表要两 ABI 共用), 而 setcc 词干里的 `_b_` 是目的字节的宽、
    jcc 词干里根本没有宽度段(默认会发到 64) -> 两个都会把那次 cmp 的标志算错。
    cmov 的 `_l_/_q_` 是真操作数宽(只有 x86_64 才采到 .q) -> 按后缀取。
    搬运族的 cwtl/cltq/cqto 同坑: 助记符本身携带宽度、词干里没有宽度段。
    grp=x87 优先级最高: 本组 26 条的宽度全由表钉死, 且词干名与 special 有重叠。"""
    if grp == "scalar":                          # scalar 组: 32 位定宽(KAT 探针)
        return 32
    if grp in ("sse", "crypto"):                 # 两者 KAT 输出都是 128 位
        return 128
    if grp == "avx":                             # 128/256 混编, 取 256 不丢高位
        return 256
    if grp == "x87":                             # x87 组: 26 条全部已登记
        if stem in X87_W:
            return X87_W[stem]
        # 未登记词干在定宽这一步就拦, 且报成点名到词干的 FAIL: 留一个裸 KeyError
        # 出去, "两张表词干集不同步"就退化成整场崩溃(看不出是哪个词干、怎么修)。
        # 消息与 x87_expect 里那条同字 —— 判据只认这一句。
        raise AssertionError("x87 组词干未登记审计实现: " + stem)
    fam, _ = cc_form(stem)
    if stem in SPECIAL_W:                        # special 组: 宽度由族钉死
        return SPECIAL_W[stem]
    if fam in ("j", "set"):
        return 32
    if stem.split("_")[0] in MOV_WIDE_W:
        return MOV_WIDE_W[stem.split("_")[0]]
    return width_of(stem)


def pdep(src, mask, w):
    """PDEP: 把 src 从低到高的各个 1 位依次塞进 mask 里为 1 的位置;
    mask 的 1 不够多时高位直接丢弃(SDM: 超出部分 ignored)"""
    res = k = 0
    for b in range(w):
        if (mask >> b) & 1:
            if (src >> k) & 1:
                res |= 1 << b
            k += 1
    return res


def pext(src, mask, w):
    """PEXT: 把 src 中被 mask 选中的位压缩到低位"""
    res = k = 0
    for b in range(w):
        if (mask >> b) & 1:
            if (src >> b) & 1:
                res |= 1 << k
            k += 1
    return res


def rb64(x, n):
    """64 位循环左移(探针 SRB/ARB 同式)"""
    x &= M64
    return ((x >> n) | (x << (64 - n))) & M64


def _sgn32(u, part):
    """取 u 的高/低 32 位当有符号整数(探针 s_fpd/af_f 的取半口径)"""
    v = ((u >> 32) & M32) if part else (u & M32)
    return v - (1 << 32) if v >> 31 else v


def _round_bin(fr, p, emin, emax):
    """Fraction(>=0) -> 最近的二进制浮点(round-half-even): p 位有效位(含隐含位),
    指数范围 [emin, emax]。返回 Python float(= 该浮点值; f32 可被 double 精确承载)。"""
    if fr == 0:
        return 0.0
    e = fr.numerator.bit_length() - fr.denominator.bit_length()
    while Fraction(2) ** e > fr:
        e -= 1
    while Fraction(2) ** (e + 1) <= fr:
        e += 1
    if e < emin:                                  # 次正规: 有效位从 2^(emin-p+1) 数起
        e = emin
    scaled = fr / Fraction(2) ** (e - (p - 1))
    m = int(scaled)
    rem = scaled - m
    if rem > Fraction(1, 2) or (rem == Fraction(1, 2) and (m & 1)):
        m += 1
    if m >= (1 << p):
        m >>= 1
        e += 1
    if e > emax:
        return float("inf")
    return float(m) * (2.0 ** (e - (p - 1)))


def to_f32(fr):
    """精确值(Fraction/int/float) -> 最近 f32(以 double 精确承载)。
    为什么不用 struct('<f', float(fr)): 那是「先 double 再 float」的二次舍入,
    对加减/除法会偶发与单精度一次舍入不同。"""
    fr = Fraction(fr)
    return -_round_bin(-fr, 24, -126, 127) if fr < 0 else _round_bin(fr, 24, -126, 127)


def f32_in(u, part, div):
    """s_fpd/af_f 的 float 侧: (float)(有符号 int32 / div)"""
    return to_f32(Fraction(_sgn32(u, part), div))


def f64_in(u, part, div):
    """s_fpd 的 double 侧: 有符号 int32 / div(精确, 无舍入)"""
    return _sgn32(u, part) / div


def f32_add(a, b):
    return to_f32(Fraction(a) + Fraction(b))


def f32_sub(a, b):
    return to_f32(Fraction(a) - Fraction(b))


def f32_mul(a, b):
    return to_f32(Fraction(a) * Fraction(b))


def f32_div(a, b):
    return to_f32(Fraction(a) / Fraction(b))


def f32_fma(a, b, c):
    """FMA: a*b+c 只舍入一次"""
    return to_f32(Fraction(a) * Fraction(b) + Fraction(c))


def _pg(vals, w):
    """lane 列表(低位在前) -> 一个整数(低位在前)"""
    r = 0
    for i, v in enumerate(vals):
        r |= (v & ((1 << w) - 1)) << (i * w)
    return r


def _ug(x, n, w):
    """整数 -> n 个 w 位 lane(低位在前)"""
    return [(x >> (i * w)) & ((1 << w) - 1) for i in range(n)]


def _s16(v):
    return v - 0x10000 if v & 0x8000 else v


def _sat16(v):
    return -32768 if v < -32768 else (32767 if v > 32767 else v)


def bits128_to_bytes(x):
    """128 位整数 -> AES-NI 的字节序(byte i = 第 i 个字节, 低位在前 = MOVDQU 装载序)"""
    return (x & ((1 << 128) - 1)).to_bytes(16, "little")


def bytes_to_bits128(b):
    return int.from_bytes(b, "little")


# ---- CRC32C(SSE4.2 crc32l): 反射多项式 0x82F63B78, 无最终异或 ----
CRC32C_TAB = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (_c >> 1) ^ (0x82F63B78 if _c & 1 else 0)
    CRC32C_TAB.append(_c)


def crc32c(crc, data):
    c = crc & M32
    for i in range(4):
        c = (c >> 8) ^ CRC32C_TAB[(c ^ ((data >> (8 * i)) & 0xFF)) & 0xFF]
    return c & M32


def scalar_expect(stem, i0, i1):
    """scalar 组(isb_scalar.c): 32 位定宽, 两 ABI 共用一张表; 只比 o0/o1/outf。"""
    a, b = i0 & M32, i1 & M32
    if stem == "add_r64":
        res, _, f = add_sub(a, b, 0, 32, False)
        return {"o0": res, "o1": 0, **f}
    if stem == "mul_r64":                          # imull: 低 32 位积 + CF/OF
        ps = sgn(a, 32) * sgn(b, 32)
        res = ps & M32
        of = 1 if sgn(res, 32) != ps else 0
        return {"o0": res, "o1": 0, "CF": of, "OF": of}
    if stem == "crc32":
        return {"o0": crc32c(a, b), "o1": 0}
    return None


# ---- AES(FIPS-197): AESENC/AESDEC 单轮 ----
AES_SBOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
)
AES_ISBOX = (
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
)


def _aes_shift_rows(s):
    """state byte 序 = AES-NI(byte0 最高位, 列主序 s[4c+r]); 第 r 行左移 r"""
    return [s[4 * ((c + r) % 4) + r] for c in range(4) for r in range(4)]


def _aes_inv_shift_rows(s):
    return [s[4 * ((c - r) % 4) + r] for c in range(4) for r in range(4)]


def _xtime(x):
    return ((x << 1) ^ (0x11B if x & 0x80 else 0)) & 0xFF


def _gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        b >>= 1
        a = _xtime(a)
    return r & 0xFF


def _aes_mix_columns(s):
    o = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]
        o[4 * c + 0] = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
        o[4 * c + 1] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
        o[4 * c + 2] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
        o[4 * c + 3] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)
    return o


def _aes_inv_mix_columns(s):
    o = [0] * 16
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        o[4 * c + 0] = _gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9)
        o[4 * c + 1] = _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13)
        o[4 * c + 2] = _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11)
        o[4 * c + 3] = _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)
    return o


def aesenc(a, b):
    """AESENC(a, b) = AddRoundKey(MixColumns(SubBytes(ShiftRows(a))), b)"""
    s = [AES_SBOX[x] for x in _aes_shift_rows(bits128_to_bytes(a))]
    s = _aes_mix_columns(s)
    bb = bits128_to_bytes(b)
    return bytes_to_bits128(bytes(s[i] ^ bb[i] for i in range(16)))


def aesdec(a, b):
    """AESDEC(a, b) = AddRoundKey(InvMixColumns(InvSubBytes(InvShiftRows(a))), b)"""
    s = [AES_ISBOX[x] for x in _aes_inv_shift_rows(bits128_to_bytes(a))]
    s = _aes_inv_mix_columns(s)
    bb = bits128_to_bytes(b)
    return bytes_to_bits128(bytes(s[i] ^ bb[i] for i in range(16)))


def clmul64(a, b):
    """64x64 -> 128 无进位乘(PCLMULQDQ)"""
    r = 0
    for i in range(64):
        if (b >> i) & 1:
            r ^= a << i
    return r & ((1 << 128) - 1)


def _ror32(x, n):
    x &= M32
    return ((x >> n) | (x << (32 - n))) & M32


def sha256_rnds2(abcd, efgh, msg):
    """SHA256RNDS2(Intel SDM): SRC1(abcd, 即内在的 a)= {C,D,G,H},
    SRC2(efgh, 即内在的 b)= {A,B,E,F}, XMM0(msg)= {WK1,WK0}(已含 W+K);
    出 {A2,B2,E2,F2}。两轮。"""
    C, D = (abcd >> 96) & M32, (abcd >> 64) & M32
    G, H = (abcd >> 32) & M32, abcd & M32
    A, B = (efgh >> 96) & M32, (efgh >> 64) & M32
    E, F = (efgh >> 32) & M32, efgh & M32
    wk = [msg & M32, (msg >> 32) & M32]
    for i in range(2):
        s1 = _ror32(E, 6) ^ _ror32(E, 11) ^ _ror32(E, 25)
        ch = (E & F) ^ ((~E & M32) & G)
        t1 = (H + s1 + ch + wk[i]) & M32
        s0 = _ror32(A, 2) ^ _ror32(A, 13) ^ _ror32(A, 22)
        maj = (A & B) ^ (A & C) ^ (B & C)
        t2 = (s0 + maj) & M32
        H, G, F = G, F, E
        E = (D + t1) & M32
        D, C, B = C, B, A
        A = (t1 + t2) & M32
    return (A << 96) | (B << 64) | (E << 32) | F


def crypto_expect(stem, i0, i1, i2, i3):
    """crypto 组(isb_crypto.c): a=(i0,i1), b=(i1, rotl64(i0,13)); 结果低/高 64 ->
    o0/o1; 整数/SIMD 族不碰 EFLAGS -> outf=0。"""
    a = ((i1 & M64) << 64) | (i0 & M64)
    b = (rb64(i0, 13) << 64) | (i1 & M64)
    if stem == "aesenc":
        return pair(aesenc(a, b))
    if stem == "aesdec":
        return pair(aesdec(a, b))
    if stem == "pclmulqdq":
        return pair(clmul64(i0 & M64, i1 & M64))
    if stem == "sha256rnds2":
        # 专条: abcd=(i0,i1), efgh=(i2,i3) 直构(不走 CR_B), msg=abcd^efgh
        e = ((i3 & M64) << 64) | (i2 & M64)
        return pair(sha256_rnds2(a, e, a ^ e))
    return None


def _s8(v):
    return v - 0x100 if v & 0x80 else v


def _pf4(vals):
    """4 个 f32(低位在前) -> 128 位整数"""
    return int.from_bytes(struct.pack("<4f", *[float(v) for v in vals]), "little")


def _pd2(vals):
    """2 个 f64(低位在前) -> 128 位整数"""
    return int.from_bytes(struct.pack("<2d", *[float(v) for v in vals]), "little")


def _i32(v):
    """double -> int32(截断); 越界/NaN/Inf -> 0x80000000(CVTTPD2DQ 的 indefinite)"""
    if v != v or v in (float("inf"), float("-inf")) or v < -2147483648.0 or v > 2147483647.0:
        return 0x80000000
    return int(v) & M32


SSE_MOV_FULL = {"movups_ld", "movaps_ld", "movdqa", "movdqu", "lddqu", "movaps_st"}
SSE_PS4 = {"mulss": f32_mul, "addss": f32_add, "subss": f32_sub}
SSE_PD_BIN = {"addpd": lambda x, y: x + y, "mulpd": lambda x, y: x * y}
SSE_SD_BIN = {"addsd": lambda x, y: x + y, "divsd": lambda x, y: x / y}


def sse_expect(stem, i0, i1):
    """sse 组(isb_sse.c 439-550): 输入都是哈希重导的有限值/位形, 输出 128 位 ->
    o0(低64)/o1(高64), 整数/SIMD 族 outf=0。"""
    win = ((i1 & M64) << 64) | (i0 & M64)
    a, b = win, (rb64(i0, 13) << 64) | (i1 & M64)
    if stem in SSE_MOV_FULL:                 # 全 128 位窗口回读
        return pair(win)
    if stem == "movq":
        return pair(i0 & M64)
    if stem == "movss":                      # load_ss: 低 32 位, 高位置 0
        return pair(i0 & M32)
    if stem == "movsd":                      # load_sd: 低 64 位, 高位置 0
        return pair(i0 & M64)
    # ---- 位/整数 lane ----
    if stem == "xorps":
        return pair(a ^ b)
    if stem == "shufps":                      # imm 0x4e -> [a2,a3,b0,b1]
        ad, bd = _ug(a, 4, 32), _ug(b, 4, 32)
        return pair(_pg([ad[2], ad[3], bd[0], bd[1]], 32))
    if stem == "pcmpeqd":
        ad, bd = _ug(a, 4, 32), _ug(b, 4, 32)
        return pair(_pg([M32 if ad[i] == bd[i] else 0 for i in range(4)], 32))
    if stem == "pcmpeqq":
        aq, bq = _ug(a, 2, 64), _ug(b, 2, 64)
        return pair(_pg([M64 if aq[i] == bq[i] else 0 for i in range(2)], 64))
    if stem == "paddd":
        ad, bd = _ug(a, 4, 32), _ug(b, 4, 32)
        return pair(_pg([(ad[i] + bd[i]) & M32 for i in range(4)], 32))
    if stem == "paddw":
        aw, bw = _ug(a, 8, 16), _ug(b, 8, 16)
        return pair(_pg([(aw[i] + bw[i]) & 0xFFFF for i in range(8)], 16))
    if stem == "pmaddwd":
        aw, bw = _ug(a, 8, 16), _ug(b, 8, 16)
        return pair(_pg([(_s16(aw[2*i]) * _s16(bw[2*i]) + _s16(aw[2*i+1]) * _s16(bw[2*i+1])) & M32
                         for i in range(4)], 32))
    if stem == "pmulld":
        ad, bd = _ug(a, 4, 32), _ug(b, 4, 32)
        return pair(_pg([(ad[i] * bd[i]) & M32 for i in range(4)], 32))
    if stem in ("pshufb", "pshufb_sem"):
        ab, bb = _ug(a, 16, 8), _ug(b, 16, 8)
        return pair(_pg([0 if bb[i] & 0x80 else ab[bb[i] & 0x0F] for i in range(16)], 8))
    if stem in ("pmaddubsw", "pmaddubsw_sem"):    # a 无符号字节 * b 有符号字节
        ab, bb = _ug(a, 16, 8), _ug(b, 16, 8)
        out = [_sat16(ab[2*i] * _s8(bb[2*i]) + ab[2*i+1] * _s8(bb[2*i+1])) & 0xFFFF for i in range(8)]
        return pair(_pg(out, 16))
    if stem in ("pmulhrsw", "pmulhrsw_sem"):
        aw, bw = _ug(a, 8, 16), _ug(b, 8, 16)
        out = [(((_s16(aw[i]) * _s16(bw[i])) >> 14) + 1) >> 1 & 0xFFFF for i in range(8)]
        return pair(_pg(out, 16))
    if stem == "palignr":                      # (a:b) 拼接(a 高) 右移 5 字节
        return pair(((a << 128) | b) >> 40 & ((1 << 128) - 1))
    if stem == "pblendw":                      # imm 0x3c: word 2..5 取 b
        aw, bw = _ug(a, 8, 16), _ug(b, 8, 16)
        return pair(_pg([bw[i] if (0x3C >> i) & 1 else aw[i] for i in range(8)], 16))
    if stem in ("pabsw",):
        aw = _ug(a, 8, 16)
        return pair(_pg([abs(_s16(v)) & 0xFFFF for v in aw], 16))
    if stem in ("pabsb_sem",):
        ab = _ug(a, 16, 8)
        return pair(_pg([abs(_s8(v)) & 0xFF for v in ab], 8))
    if stem == "pmovsxwd":                     # 低 4 个 word 符号扩展成 dword
        aw = _ug(a, 8, 16)
        return pair(_pg([_s16(aw[i]) & M32 for i in range(4)], 32))
    if stem == "phaddsw_sem":                  # hadds_epi16(a,b)
        aw, bw = [_s16(v) for v in _ug(a, 8, 16)], [_s16(v) for v in _ug(b, 8, 16)]
        oa = [_sat16(aw[2*i] + aw[2*i+1]) & 0xFFFF for i in range(4)]
        ob = [_sat16(bw[2*i] + bw[2*i+1]) & 0xFFFF for i in range(4)]
        return pair(_pg(oa + ob, 16))
    if stem == "phminposuw":
        w = _ug(a, 8, 16)
        mv = min(w)
        return pair(mv | (w.index(mv) << 16))
    if stem == "mpsadbw":                      # imm 3: 4 字节窗 b[12:16] vs a 的 8 个滑动窗(步 1)
        ab, bb = _ug(a, 16, 8), _ug(b, 16, 8)
        out = [sum(abs(ab[i + j] - bb[12 + j]) for j in range(4)) for i in range(8)]
        return pair(_pg(out, 16))
    # ---- 浮点族 ----
    aa = [f32_in(i0, 0, 4), f32_in(i0, 1, 8), f32_in(i1, 0, 4), f32_in(i1, 1, 8)]
    rb = rb64(i0, 13)
    bb4 = [f32_in(i1, 0, 4), f32_in(i1, 1, 8), f32_in(rb, 0, 4), f32_in(rb, 1, 8)]
    if stem in SSE_PS4:                        # 只改低 lane, 高 3 lane 取自 a
        return pair(_pf4([SSE_PS4[stem](aa[0], bb4[0]), aa[1], aa[2], aa[3]]))
    if stem == "roundps":                      # imm 0x00 -> 就近取偶
        return pair(_pf4([float(round(v)) for v in aa]))
    da = [f64_in(i0, 0, 4), f64_in(i1, 1, 8)]
    db = [f64_in(i1, 0, 4), f64_in(rb, 1, 8)]
    if stem in SSE_PD_BIN:
        return pair(_pd2([SSE_PD_BIN[stem](da[0], db[0]), SSE_PD_BIN[stem](da[1], db[1])]))
    if stem in SSE_SD_BIN:                     # 只改低 lane
        return pair(_pd2([SSE_SD_BIN[stem](da[0], db[0]), da[1]]))
    if stem == "cvttpd2dq":
        return pair(_i32(da[0]) | (_i32(da[1]) << 32))
    if stem == "haddpd":
        return pair(_pd2([da[0] + da[1], db[0] + db[1]]))
    if stem == "addsubpd":
        return pair(_pd2([da[0] - db[0], da[1] + db[1]]))
    return None


def _pf8(vals):
    """8 个 f32(低位在前) -> 256 位整数"""
    return int.from_bytes(struct.pack("<8f", *[float(v) for v in vals]), "little")


def _q4(r):
    """256 位结果 -> {o0..o3}(低位在前)"""
    return {"o0": r & M64, "o1": (r >> 64) & M64, "o2": (r >> 128) & M64, "o3": (r >> 192) & M64}


def _q2_low(r):
    """128 位结果 -> {o0,o1,o2=0,o3=0}(AOUT128)"""
    return {"o0": r & M64, "o1": (r >> 64) & M64, "o2": 0, "o3": 0}


def _shufb_lane(x128, ctrl128):
    ab, cb = _ug(x128, 16, 8), _ug(ctrl128, 16, 8)
    return _pg([0 if cb[i] & 0x80 else ab[cb[i] & 0x0F] for i in range(16)], 8)


def avx_expect(stem, i0, i1, i2, i3):
    """avx 组(isb_avx.c 308-424): A0..A3=i0..i3; 128 位形态只用 i0,i1(o2/o3=0),
    256 位用 o0..o3。b=AVINB 的高低位组合与探针宏一致(低位在前)。"""
    A = [i0 & M64, i1 & M64, i2 & M64, i3 & M64]
    a = (A[3] << 192) | (A[2] << 128) | (A[1] << 64) | A[0]
    b = (rb64(A[0], 13) << 192) | (rb64(A[3], 7) << 128) | (rb64(A[2], 29) << 64) | rb64(A[1], 11)
    if stem in ("vmovaps_ymm", "vmovdqa_ymm", "vmovdqu"):   # 窗口回读 = A0..A3
        return _q4((A[3] << 192) | (A[2] << 128) | (A[1] << 64) | A[0])
    if stem == "vpxor_ymm":
        return _q4(a ^ b)
    if stem in ("vpaddd_ymm", "vpaddd256_sem"):
        ad, bd = _ug(a, 8, 32), _ug(b, 8, 32)
        return _q4(_pg([(ad[i] + bd[i]) & M32 for i in range(8)], 32))
    if stem == "vpmulld_ymm":
        ad, bd = _ug(a, 8, 32), _ug(b, 8, 32)
        return _q4(_pg([(ad[i] * bd[i]) & M32 for i in range(8)], 32))
    if stem == "vpmaddwd_ymm":
        aw, bw = _ug(a, 16, 16), _ug(b, 16, 16)
        return _q4(_pg([(_s16(aw[2*i]) * _s16(bw[2*i]) + _s16(aw[2*i+1]) * _s16(bw[2*i+1])) & M32
                        for i in range(8)], 32))
    if stem == "vpaddq":
        aq, bq = _ug(a, 4, 64), _ug(b, 4, 64)
        return _q4(_pg([(aq[i] + bq[i]) & M64 for i in range(4)], 64))
    if stem == "vpshufb256_sem":               # 每 128 位 lane 内字节重排
        lo = _shufb_lane(a & ((1 << 128) - 1), b & ((1 << 128) - 1))
        hi = _shufb_lane(a >> 128, b >> 128)
        return _q4(lo | (hi << 128))
    if stem == "vpsrad_ymm":
        return _q4(_pg([(sgn(v, 32) >> 1) & M32 for v in _ug(a, 8, 32)], 32))
    if stem == "vpsllq":
        return _q4(_pg([(v << 11) & M64 for v in _ug(a, 4, 64)], 64))
    if stem == "vpsrlq":
        return _q4(_pg([v >> 7 for v in _ug(a, 4, 64)], 64))
    if stem == "vpsrlw":
        return _q4(_pg([v >> 3 for v in _ug(a, 16, 16)], 16))
    if stem == "vpbroadcastd":
        d = A[0] & M32
        return _q4(_pg([d] * 8, 32))
    if stem == "vinsertf128":                  # 把 b 的低 128 插入 a 的高 128
        return _q4((((rb64(A[2], 29) << 64) | rb64(A[1], 11)) << 128) | (A[1] << 64) | A[0])
    if stem == "vptest":
        return {"o0": 0, "o1": 0, "o2": 0, "o3": 0,
                "CF": 1 if (a & (~b & ((1 << 256) - 1))) == 0 else 0,
                "ZF": 1 if (a & b) == 0 else 0}
    # ---- 浮点族 ----
    rb0 = rb64(A[0], 13)
    if stem == "vaddps_xmm":
        aa = [f32_in(A[0], 0, 4), f32_in(A[0], 1, 8), f32_in(A[1], 0, 4), f32_in(A[1], 1, 8)]
        bb = [f32_in(A[1], 0, 4), f32_in(A[1], 1, 8), f32_in(rb0, 0, 4), f32_in(rb0, 1, 8)]
        return _q2_low(_pf4([f32_add(aa[i], bb[i]) for i in range(4)]))
    aa8 = [f32_in(A[0], 0, 4), f32_in(A[0], 1, 8), f32_in(A[1], 0, 4), f32_in(A[1], 1, 8),
           f32_in(A[2], 0, 4), f32_in(A[2], 1, 8), f32_in(A[3], 0, 4), f32_in(A[3], 1, 8)]
    bb8 = [f32_in(A[1], 0, 4), f32_in(A[1], 1, 8), f32_in(A[2], 0, 4), f32_in(A[2], 1, 8),
           f32_in(A[3], 0, 4), f32_in(A[3], 1, 8), f32_in(rb0, 0, 4), f32_in(rb0, 1, 8)]
    if stem == "vaddps_ymm":
        return _q4(_pf8([f32_add(aa8[i], bb8[i]) for i in range(8)]))
    if stem == "vmulps_ymm":
        return _q4(_pf8([f32_mul(aa8[i], bb8[i]) for i in range(8)]))
    if stem in ("vfmadd213ps", "vfmadd213ps_sem"):
        return _q4(_pf8([f32_fma(aa8[i], bb8[i], 0.125) for i in range(8)]))
    return None


def expect(stem, i0, i1, inf, w, grp=None, kk=0, i2=0, i3=0):
    """按助记符 + 形态段反算 -> {"o0","o1","CF"...} 或 None(本条不审)
    grp 取自表文件名(见 main): 分派按组不按词干 —— 同一词干可以在两张表里都
    出现(x87 收了 special 迁走的 6 条), 按词干分派会把 stale 行交给错的一侧。"""
    if grp == "x87":
        return x87_expect(stem, i0, i1, inf, kk)
    if grp == "scalar":
        return scalar_expect(stem, i0, i1)
    if grp == "crypto":
        return crypto_expect(stem, i0, i1, i2, i3)
    if grp == "sse":
        return sse_expect(stem, i0, i1)
    if grp == "avx":
        return avx_expect(stem, i0, i1, i2, i3)
    if stem in X87_W:
        # 别的组表里出现 x87 词干 = 内核已迁走而表没重采。报成"未纳审"就白了一半
        # (看不出该怎么修), 所以这里直接点名处置方式。
        raise AssertionError("%s 已连内核迁到 x87 组, 本表里是 stale 行 -> "
                             "重采: gen_val.sh special" % stem)
    if stem in SPECIAL_W:
        # special 组(直写)的词干里没有形态段, 后面的 sides() 拆分会直接 IndexError
        # (如 "cmpxchg" 只有一段) -> 在拆分之前就分到各自的反算里
        return special_expect(stem, i0, i1, inf, w)
    if stem in VEC_OPS:
        # vec 组(直写)同坑: 词干里没有宽度段也没有形态段, 而且操作数是 128 位
        # lane 向量 —— sides()/width_of() 那套逐段拆分在这里没有任何可拆的东西
        return vec_expect(stem, i0, i1, inf, w)
    op = stem.split("_")[0]
    mask = (1 << w) - 1
    c_in = inf & 1                          # CF: 探针 IB_SETF 注入的输入标志
    imm = 5 if "_i_" in stem else None      # 立即数形态在组文件里写死 IB_IMM="$5"
    lhs, src = sides(stem, i0, i1, imm)
    fam, cc = cc_form(stem)
    if fam is not None:
        # 标志消费三族(15Km): 条件不注入, 而是探针里一次真 cmp 现生成 -> 入值侧要
        # 审两层: inf == 该次比较的架构定义(采到的标志本身也被复算) + outf == inf
        # (三条指令都不得改标志); 判断侧 o0 按家族各自反算。
        if cc not in CC_COND:
            return None
        _, _, f = add_sub(i0, i1, 0, w, True)     # cmp = SUBTRACT, 不写回
        holds = CC_COND[cc](f)
        res = {"set": 1 if holds else 0,          # 目的字节(setcc 不碰内存/寄存器)
               "j": 0 if holds else 1,            # 取路径=0, 不取路径=1
               "cmov": i1 if holds else i0}[fam]  # dest=%[a]=i0, src=%[b]=i1
        return {"o0": res, "o1": i1, "inf": pack_flags(f), **flags_of_inf(inf)}
    if op in MOV_OPS:
        # 搬运族(15Kn): 架构上六个标志全不受影响 -> 期望集就是注入值本身。
        # outf == inf 这一条就是本组除结果之外的全部断言(翻译器把 mov 译成会
        # 踩 EFLAGS 的实现, 在这里直接现形)。
        return {**mov_expect(stem, i0, i1, w), **flags_of_inf(inf)}
    if op in STACK_OPS:
        # 栈族(15Ko): 同上, push/pop/pushf 全不改标志 -> outf == inf 也是断言。
        return {**stack_expect(stem, i0, i1, inf, w), **flags_of_inf(inf)}
    if op in ("cmp",):
        res, _, f = add_sub(lhs, src, 0, w, True)
        return {"o0": i0, "o1": i1, **f}
    if op in ("test",):
        res = lhs & src
        # AF 在 test 后未定义(SDM) -> 不进审计集; CF/OF 清 0
        return {"o0": i0, "o1": i1, "CF": 0, "OF": 0,
                "PF": parity8(res), "ZF": 1 if res == 0 else 0,
                "SF": (res >> (w - 1)) & 1}
    if op in ("add", "sub", "adc", "sbb", "inc", "dec"):
        sub = op in ("sub", "sbb", "dec")
        cin = c_in if op in ("adc", "sbb") else 0
        if op in ("inc", "dec"):
            b, cin = 1, 0                   # inc/dec 不影响 CF -> 下面单独沿用注入值
        else:
            b = src
        res, _, f = add_sub(lhs, b, cin, w, sub)
        if op in ("inc", "dec"):
            f["CF"] = c_in                  # 唯一「读标志当输入」但不是 adc/sbb 的情形
        # o1 取决于探针模板: IB_KT_SOM(m.m 形态)回读内存 -> o1=o0; 其它探针 o1=b 不变
        return {"o0": res, "o1": res if "_m_m_" in stem else i1, **f}
    if op in ("and", "or", "xor"):
        # 逻辑运算: CF/OF 恒清 0(这两位本身就是断言), AF 未定义 -> 不进审计集
        # (探针那边用 IB_FLG_MASK_LOGIC 上的表, 已经把 AF 剔掉)
        res = {"and": lhs & src, "or": lhs | src, "xor": lhs ^ src}[op] & mask
        return {"o0": res, "o1": i1, "CF": 0, "OF": 0,
                "PF": parity8(res), "ZF": 1 if res == 0 else 0,
                "SF": (res >> (w - 1)) & 1}
    if op == "not":
        # not 不改标志(SDM 明确承诺) -> 六个标志应恒等于注入值 inf;
        # 这比「算对结果」更严: 翻译器若把 not 译成会踩标志的实现就报警
        res = (~lhs) & mask
        return {"o0": res, "o1": i1, **flags_of_inf(inf)}
    if op in ("shl", "shr", "sar", "rol", "ror", "shld", "shrd",
              "shlx", "sarx", "shrx", "rorx"):
        # 移位族不用 sides(): 表里的 i1 含义由探针模板定
        #   IB_KT_SHA  -> i1 = 真实计数(立即数形态是常量 3/1, BMI2 是动态值)
        #   IB_KT_SHD  -> i1 = 第二个数据源(寄存器), 计数就恒为 $3
        if op in ("shld", "shrd"):
            dst, src, n = i0, i1, 3
        else:
            dst, src, n = i0, None, i1
        assert 1 <= n < w, "%s: 计数 %d 不在 [1,%d) —— 探针钳区间失效" % (stem, n, w)
        if op in ("shlx", "sarx", "shrx", "rorx"):        # BMI2: 不写标志
            res = {"shlx": (dst << n) & mask,
                   "shrx": dst >> n,
                   "sarx": (sgn(dst, w) >> n) & mask,
                   "rorx": ((dst >> n) | (dst << (w - n))) & mask}[op]
            return {"o0": res, "o1": i1, **flags_of_inf(inf)}
        if op == "shl":
            res, cf = (dst << n) & mask, (dst >> (w - n)) & 1
        elif op == "shr":
            res, cf = dst >> n, (dst >> (n - 1)) & 1
        elif op == "sar":
            s = sgn(dst, w)
            res, cf = (s >> n) & mask, (s >> (n - 1)) & 1
        elif op == "rol":
            res = ((dst << n) | (dst >> (w - n))) & mask
            cf = res & 1                                  # CF = 移入低位的那一位
        elif op == "ror":
            res = ((dst >> n) | (dst << (w - n))) & mask
            cf = (res >> (w - 1)) & 1
        elif op == "shld":
            res = ((dst << n) | (src >> (w - n))) & mask
            cf = (dst >> (w - n)) & 1
        else:                                             # shrd
            res = ((dst >> n) | (src << (w - n))) & mask
            cf = (dst >> (n - 1)) & 1                     # 最后移出的是 dst 的位
        if op in ("rol", "ror"):
            # 循环移只写 CF(OF 仅计数=1 时), 而 SF/ZF/AF/PF 是「不受影响」
            # (实测逐位等于注入值, 并不按结果重算 PF/ZF/SF) -> 与 IB_FLG_MASK_ROT 同口径
            out = {"o0": res, "o1": i1, "CF": cf}
            out.update({k: v for k, v in flags_of_inf(inf).items()
                        if k in ("PF", "AF", "ZF", "SF")})
            return out
        out = {"o0": res, "o1": i1, "CF": cf, "PF": parity8(res),
               "ZF": 1 if res == 0 else 0, "SF": (res >> (w - 1)) & 1}
        # AF 永未定义; OF 只在计数=1 时有定义(sar 恒清 0) -> 与探针掩码同口径
        if n == 1:
            out["OF"] = 0 if op == "sar" else (
                cf ^ ((res >> (w - 1)) & 1) if op == "shl" else
                ((dst >> (w - 1)) & 1) ^ ((res >> (w - 1)) & 1))
        return out
    if op in ("bt", "bts", "btc", "btq"):
        # 位数组侧: 寄存器形态 = %[a] = i0; btq 那条是内存位数组(栈槽预置值 = i1),
        # 而 %[a] 只是形式上的旁路寄存器。bts/btc 写回位数组, bt/btq 不写。
        arr = i1 if op == "btq" else i0
        idx = imm if imm is not None else (i1 & (w - 1))   # 寄存器位号按宽度取模
        old = (arr >> idx) & 1                             # CF = 被指定的那一位
        res = {"bt": i0, "btq": i0, "bts": arr | (1 << idx), "btc": arr ^ (1 << idx)}[op]
        f = flags_of_inf(inf)
        f["CF"] = old                                       # 只 CF 被写, 其余不受影响
        return {"o0": res, "o1": i1, **f}
    if op in ("bsr", "bsf"):
        # 探针已把源 |1 -> dest 有定义; 非 0 源下 CF/ZF 均清 0, SF/OF/AF/PF 未定义。
        # 本族探针契约(KAT v2, IB_KT_BITA): o0 = 源原值(未改动), o1 = 结果。
        idx = (i0.bit_length() - 1) if op == "bsr" else ((i0 & -i0).bit_length() - 1)
        return {"o0": i0, "o1": idx, "CF": 0, "ZF": 0}
    if op in ("popcnt", "lzcnt", "tzcnt", "andn", "bzhi", "blsr", "bextr",
              "pdep", "pext"):
        # 这一族只审结果, 不审标志: 探针那边用的是 IB_KT_BITF(MASK=0), outf 恒上
        # 成 0。理由见 ib_gen.h 15Kk 末尾 —— 这几条的 EFLAGS 在 SDM 里是按指令
        # 各自描述的(popcnt/lzcnt/tzcnt 只说 CF 清 0、余全未定义; BMI 走 SUBTRACT
        # 语义), 参考机实测采到的 outf 与「不受影响」「按结果算」两种统一规则都对
        # 不上(bzhi 的 PF 跟结果、andn 的不跟) -> 上表等于要求翻译器复现未承诺的东西
        if op == "popcnt":
            res = bin(i0).count("1")
        elif op == "lzcnt":
            res = w - i0.bit_length()
        elif op == "tzcnt":
            res = w if i0 == 0 else (i0 & -i0).bit_length() - 1
        elif op == "andn":                                  # AT&T: andn src2, src1, dst
            res = (~i0 & i1) & mask
        elif op == "bzhi":                                  # i1 = index(探针已落在 [0,宽度))
            res = i0 & ((1 << i1) - 1)
        elif op == "blsr":
            res = i0 & (i0 - 1) & mask
        elif op == "bextr":                                 # i1 = 控制字 start[7:0]|len[15:8]
            res = (i0 >> (i1 & 0xFF)) & ((1 << ((i1 >> 8) & 0xFF)) - 1)
        elif op == "pdep":
            # AT&T `pdepl %b,%a,%s` = Intel PDEP dst, src1=a, src2=b:
            # 数据在 src1(%[a]=i0), 掩码在 src2(%[b]=i1) —— 两条指令同一口径,
            # 反直觉的地方是 AT&T 把掩码写在数据前面, 手工核对 k=0 才定下来
            res = pdep(i0, i1, w)
        else:                                               # pext: 数据=%[a], 掩码=%[b]
            res = pext(i0, i1, w)
        # 本族探针契约(KAT v2, IB_KT_BITA): o0 = 源原值(未改动), o1 = 结果。
        # andn/bzhi/bextr/pdep/pext 的第二操作数(掩码/控制字)存在 i1(=0 仅当 blsr 单目)。
        return {"o0": i0, "o1": res}
    if op == "neg":
        res = (0 - i0) & mask
        f = alu(res, w, 1 if i0 else 0, 1 if i0 == (1 << (w - 1)) else 0,
                1 if (i0 & 0xF) else 0)
        return {"o0": res, "o1": i1, **f}
    if op == "imul":
        # 二/三操作数 imul: 只定义 CF/OF; OF = 符号扩展的高半与低半不等价
        if imm is not None:                 # 三操作数: dst = src * imm, %[a] 的入值不参与
            ps = sgn(i1, w) * imm
        else:
            ps = sgn(i0, w) * sgn(src, w)
        res = ps & mask
        of = 1 if sgn(res, w) != ps else 0
        return {"o0": res, "o1": i1, "CF": of, "OF": of}
    if op == "mul":
        p = i0 * src
        hi = (p >> w) & mask
        return {"o0": p & mask, "o1": hi, "CF": 1 if hi else 0, "OF": 1 if hi else 0}
    if op in ("div", "idiv"):
        # div/idiv 的唯一显式操作数就是除数(寄存器 %[b] 或内存都是 i1 载体),
        # 被除数隐式在 rdx:rax = i0 -> 不能用 sides() 的 lhs/src 约定
        d = i1 if i1 else 1                 # 探针把除数 |3 -> 恒非 0
        if op == "div":
            return {"o0": i0 // d, "o1": i0 % d}
        a, b = sgn(i0, w), sgn(d, w)        # idiv: 商向零截断, 余数跟随被除数符号
        q = abs(a) // abs(b) * (1 if (a < 0) == (b < 0) else -1)
        r = a - q * b
        return {"o0": q & mask, "o1": r & mask}
    return None


BIT = {"CF": 0x001, "PF": 0x004, "AF": 0x010, "ZF": 0x040, "SF": 0x080, "OF": 0x800}


def parse(path):
    """#define IB_KAT_<sn> { {...}, ... } -> {stem: [(i0,i1,i2,i3,inf,o0,o1,o2,o3,outf) x8]}"""
    txt = open(path, encoding="utf-8").read().replace("\r\n", "\n")
    out = {}
    for m in re.finditer(r"#define\s+IB_KAT_(\w+)\s*\{(.*?)\n\}", txt, re.S):
        rows = []
        for r in re.finditer(r"\{\s*" + r"0x([0-9a-fA-F]+)ULL,\s*" * 9 +
                             r"0x([0-9a-fA-F]+)ULL\s*\}", m.group(2)):
            rows.append(tuple(int(x, 16) for x in r.groups()))
        out[m.group(1)] = rows
    return out


def main():
    path = sys.argv[1]
    # 组名从文件名取(src/<grp>/isb_<grp>_kat.h): 这就是上面说的"分派按表不按词干"的
    # 唯一依据。提不到组名就直接失败 —— 拿默认值跑下去等于把一张表交给猜的分派。
    m = re.search(r"isb_(\w+)_kat\.h$", os.path.basename(path))
    if not m:
        print("!! 文件名不是 isb_<grp>_kat.h, 定不出组名: %s" % path)
        return 1
    grp = m.group(1)
    stems = parse(path)
    n_ok = n_bad = n_skip = 0
    for stem, rows in sorted(stems.items()):
        try:                                   # 词干未登记 = 表与实现不同步, 点名
            w = width_of_stem(stem, grp)
        except AssertionError as ex:
            n_bad += 1
            print("FAIL %-22s %s" % (stem, ex))
            continue
        if len(rows) != 8:
            print("SKIP %-22s 行数=%d(非 8)" % (stem, len(rows)))
            n_skip += 1
            continue
        bad = []
        for k, (i0, i1, i2, i3, inf, o0, o1, o2, o3, outf) in enumerate(rows):
            try:
                e = expect(stem, i0, i1, inf, w, grp, k, i2, i3)
            except AssertionError as ex:      # 探针自己的口径挂了(如计数越区间)
                bad.append("k=%d 探针异常: %s" % (k, ex))
                continue
            if e is None:
                bad.append("k=%d 该助记符未纳审" % k)
                continue
            for f, v in sorted(e.items()):
                if f == "inf":
                    # inf 整列比对: 只有标志消费三族会提交这一项(它们的输入条件
                    # 不是注入的, 而是探针里那次 cmp 的产物 -> 连输入侧也要复算)
                    if inf != v:
                        bad.append("k=%d inf 表=%x 算=%x (i0=%x i1=%x outf=%x)"
                                   % (k, inf, v, i0, i1, outf))
                    continue
                got = {"o0": o0, "o1": o1, "o2": o2, "o3": o3}.get(f)
                if got is None:
                    got = 1 if (outf & BIT[f]) else 0
                if got != (v & ((1 << w) - 1 if f.startswith("o") else 1)):
                    bad.append("k=%d %s 表=%x 算=%x (i0=%x i1=%x inf=%x outf=%x)"
                               % (k, f, got, v, i0, i1, inf, outf))
        if bad:
            n_bad += 1
            print("FAIL %-22s %s" % (stem, bad[0]))
            for extra in bad[1:]:
                # 只增行、不改原 FAIL 行的形状: 同一词干的其余不符也列出来。只印 bad[0] 会
                # 让一个错挡住下一个(x87 本轮就是 k=1 的 o1 挡住了 k=5 的 o0,
                # 修一个才看见下一个) —— 行首是空格, 不影响按 ^FAIL 统计的脚本
                print("     %-22s %s" % (stem, extra))
        else:
            n_ok += 1
            print("ok   %-22s 8/8 与独立复算一致(%d 位)" % (stem, w))
    # 档间关系是**跨词干**的判据, 不进 审/通过 的计数(那两个数由表里的词干数钉,
    # 加进来就会与采集端的 EXPECT_STEM 对不上) -> 单独一行结论 + 单独影响退出码。
    # 结论行格式不动: 它是多处脚本按子串认的契约。
    n_arm = 0
    if grp == "x87":
        arm = pc_arm_relation(stems)
        n_arm = len(arm)
        for m in arm:
            print("FAIL %-22s %s" % ("pc_arm_relation", m))
        print("-- 档间关系(pc24_fadd vs pc53_fadd, 不占词干审计数): %s --"
              % ("8 行差别逐行合于模型预测" if not arm else "%d 行不符" % n_arm))
    print("== 审=%d 通过=%d 不符=%d 跳过=%d ==" % (n_ok + n_bad, n_ok, n_bad, n_skip))
    return 1 if (n_bad or n_arm) else 0


if __name__ == "__main__":
    sys.exit(main())
