/* ib_gen.h —— 统一输入生成器(KAT v2 唯一口径)
 *
 * 一个功能测试点的输入必须满足两条:
 *   1) 确定性: 同 (片段名, 槽号 k, 字槽 slot) 在任何机器、任何语言重写都得同一个值
 *      —— 编译期可重算、不依赖任何数据文件、不依赖浮点/随机源;
 *   2) 可复现: 采集机与被测机各自现场重算, 不靠"把输入也存进表"来对齐 —— 真值表里
 *      那份输入只作错档核(表内输入 vs 现场生成输入), 不参与判定(见 ib_core.h ib_kv)。
 *
 * 两类来源:
 *   IB_G(sn,k,slot)   哈希派生: 通用 GPR/SIMD/内存地址, 由 ib_strhash(片段名)+k+slot 混合;
 *   IB_GB(sn,k,idx)   边界向量: 需要精确边界值(2^53 / INT64_MIN / 全 1 / 0xaa 填充)的族,
 *                     哈希推不出这些"恰好在缺陷分界线上"的值, 故用固定向量表按 idx 选。
 *
 * 必须在 #include "ib_core.h" 之后引用(用到 IB_FV/IB_FLG_MASK)。
 * 与 pmul_gold 的关系: pmul 的输入由 pmul_bits(L,k) 公式生成(全宽 64x64 的领域规则),
 * 判定是"实测 == 采集值"; 本生成器是通用组的输入侧口径, 判定是"输出 5 字全等"。
 */
#ifndef ISB_IB_GEN_H
#define ISB_IB_GEN_H

/* 自带 stdint: 本文件要能被单独编译做形状自检, 不依赖包含者已先带进 uint64_t。 */
#include <stdint.h>

/* FNV-1a: 片段名 -> 64 位散列(与输出协议里的内存摘要同族, 但不是同一处实现) */
__attribute__((unused)) static uint64_t ib_strhash(const char *s)
{
    uint64_t h = 1469598103934665603ULL;
    while (*s) {
        h ^= (uint64_t)(unsigned char)*s++;
        h *= 1099511628211ULL;
    }
    return h;
}

/* 雪崩混合(murmur3 finalizer): 让相邻 (k,slot) 派生出的输入互不相关 */
__attribute__((unused)) static uint64_t ib_mix(uint64_t z)
{
    z += 0x9e3779b97f4a7c15ULL;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

__attribute__((unused)) static uint64_t ib_kin(uint64_t h, int k, int slot)
{
    return ib_mix(h + (uint64_t)k * 0xff51afd7ed558ccdULL + slot * 0x100000001b3ULL);
}

/* 统一生成器: 第 k 个测试点的第 slot 个字(0..3) */
#define IB_G(sn, k, slot)    ib_kin(ib_strhash(sn), (k), (slot))

/* 兼容别名: 已有 kat 函数全用这两个, 语义与 IB_G 完全等同(不是第二套实现) */
#define IB_KIN(sn, k, slot)  IB_G(sn, k, slot)
#define IB_KIN8(sn, k, slot, TY) ((TY)(IB_G(sn, k, slot) & \
                                     (0xffffffffffffffffULL >> \
                                      (64 - 8 * (int)sizeof(TY)))))
/* 入标志: 恒置 bit1(RES 位)并按族套掩码 -> 只比可比对的状态位 */
#define IB_KFL(sn, k)        IB_FV(IB_G(sn, k, 2))

/* 边界向量: "恰好在缺陷分界线上"的值(需要精确边界的族按 idx 选)。
 * 与 x87 各 case 自带的 XVEC/BVEC/IVEC 同一思路, 这里给通用族一份公共表。 */
#define IB_GB_N 12
__attribute__((unused)) static const uint64_t ib_gb_vec[IB_GB_N] = {
    0x0000000000000000ULL,  /* 0 */
    0x0000000000000001ULL,  /* 1 */
    0xffffffffffffffffULL,  /* -1 / 全 1 */
    0x7fffffffffffffffULL,  /* INT64_MAX */
    0x8000000000000000ULL,  /* INT64_MIN */
    0x0020000000000000ULL,  /* 2^53: double 精确表示的最大连续整数下界 */
    0x0020000000000001ULL,  /* 2^53+1: 走 double 必丢(缺陷分界线右端点) */
    0xaaaaaaaaaaaaaaaaULL,  /* 0xaa 填充 */
    0x5555555555555555ULL,  /* 0x55 填充 */
    0x00000000ffffffffULL,  /* 低 32 位全 1 */
    0x000000000000ffffULL,  /* 低 16 位全 1 */
    0xdeadbeefcafebabeULL   /* 高位稠密(有效位宽拉满) */
};
#define IB_GB(sn, k, idx)    ib_gb_vec[(((k) * 7) + (idx)) % IB_GB_N]

#endif /* ISB_IB_GEN_H */
