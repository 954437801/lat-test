/* isb_x87.c —— x87 组编译单元入口(统一构建)
 *
 * x87 组源码已拆成 4 个实现文件(便于组织与逐个实现专用延迟函数):
 *   isb_x87_main.c : 头注释 + 全局缓冲/入值向量定义 + helper + 用例表 + main
 *   isb_x87_ops.c  : 40 个 KAT 回调(_kat)
 *   isb_x87_tp.c   : 40 个定时长吞吐量测试(_tp)
 *   isb_x87_lat.c  : 延迟测试(逐个实现专用函数)
 *
 * 为什么用统一构建而不是把每个 .c 单独编译再链接:
 *   检测框架的头 ib_core.h 内含函数与全局变量**定义**(g_os/g_lat_iters/ib_* 一族),
 *   这是为"单源文件组"设计的形态。若把 4 个 .c 各自 -c 再链接, 每个 .o 都带一份
 *   ib_core.h 的定义, 链接期会报 multiple definition。改 ib_core.h 为声明/定义分离
 *   会波及全部 ISA 组。因此 x87 组按统一构建合成单一编译单元, 既保持代码分文件,
 *   又不改动公共头与其它组的构建契约。
 */
#include "isb_x87_main.c"
#include "isb_x87_ops.c"
#include "isb_x87_tp.c"
#include "isb_x87_lat.c"
