/* isb_sfloat_slots.h —— isbench sfloat 组 8 槽固定输入(探针与真值生成器共用)
 *
 * 唯一来源: 探针 src/sfloat/isb_sfloat.c 与真值生成器 src/sfloat/gen_gold_sfloat.c 都 include 本头,
 * 保证"现场重算输入的数值"与"采集真值时的输入"逐位一致 —— 这正是错档核(kat 真值表
 * 与现场输入对齐)的意义所在。
 *
 * 取值纪律(与 cfloat 的"1.0 播种"同族, 但这里要覆盖更多位形):
 *   - 一律用 double 字面量, 且在 f64/f80/f128 三宽度上均可精确表示(短二进制小数或
 *     2 的幂/整数), 这样三宽度拿到的是同一个实数值, 不是三个各自凑的数;
 *   - 全为正 -> sqrt 定义域内; 量级从 1e-5 到 1e10 -> 加/减/乘/除结果全程规格化,
 *     除一处 1e-5-1e-5=0(零不是次正规, 不触发慢路径)外不落 0/denormal;
 *   - 二进制可见: 真值表由真 x86 现场采集后逐位固定, 换机只重算 got 再 memcmp。
 */
#ifndef ISB_SFLOAT_SLOTS_H
#define ISB_SFLOAT_SLOTS_H

#define SF_KAT_N 8

/* 第一操作数(一元运算与二元运算的左操作数) */
static const double sf_slot_a[SF_KAT_N] = {
    1.0, 3.0, 2.0, 0.5, 6.25, 1.0e10, 1.0e-5, 9.0
};
/* 第二操作数(二元运算的右操作数; 一元运算不用) */
static const double sf_slot_b[SF_KAT_N] = {
    1.0, 2.0, 0.5, 0.25, 1.5, 3.0, 1.0e-5, 4.0
};

#endif /* ISB_SFLOAT_SLOTS_H */
