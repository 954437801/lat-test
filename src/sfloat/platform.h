/* isbench sfloat 组使用的可移植 platform.h(统一三形态 x64/i386/loongarch64)。
 *
 * 与 SoftFloat 官方 build 目录下的 platform.h 等价, 唯一改动: SOFTFLOAT_INTRINSIC_INT128
 * 按 __SIZEOF_INT128__ 门控 —— i386(-m32) 没有 __int128, 必须关掉否则编不过;
 * x86_64/loongarch64 有该类型则打开(走 64x64->128 内建快路径)。
 */
#define LITTLEENDIAN 1

#ifdef __GNUC_STDC_INLINE__
#define INLINE inline
#else
#define INLINE extern inline
#endif

#define SOFTFLOAT_BUILTIN_CLZ 1
#if defined(__SIZEOF_INT128__)
#define SOFTFLOAT_INTRINSIC_INT128 1
#endif
#include "opts-GCC.h"
