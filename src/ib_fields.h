/* ib_fields.h —— 全仓输出数据的字段名与结构定义(只有宏, 不生成任何对象)
 *
 * 一、这个头存在的唯一理由
 *   各组测的东西本来就不一样, 用例表、内核、常量表强行统一最耗资源也不合理 ——
 *   所以每组自己的 .h/.c、自己的真值表, 不混合。需要统一的只有**输出数据长什么样**:
 *   列叫什么、中文叫什么、状态有哪些取值、明细串怎么写。这些一处定死, 各组跑出来的
 *   数据才同形可比, 解析侧与数据字典才可能只有一套口径。
 *
 * 二、三条纪律(新增字段照此办, 不照办就是本头作废)
 *   1) 名字只有这一份。任何 .c/.h/.py 要输出或解析这些名字, 一律引用本头的宏; 一旦
 *      出现第二处字面量, 早晚漂移, 而漂移是静默的(列还在, 意思变了)。
 *   2) 读名字不必查文档。概念用全词(status/detail/iters/signature), 单位用单位
 *      (ns / ops_s / mb_s), 行业缩写只保留人人都认的(kat/abi/os/bits/pclmul)。
 *      宁可长, 不要猜。
 *   3) 中文名单元自解释。一字段一个中文名, 且不含逗号(要与列名逐列对齐)。
 *
 * 三、只放宏
 *   本头被 18 个 TU 各含一次(每颗可执行恰好一个含 ib.h 的 TU)。头里写一个没被用到
 *   的 static 对象, 在 strict 口径(-Wall -Wextra -Werror)下就是所有组一起编译失败。
 *
 * 四、Python 侧怎么用
 *   isbench.py **不** include 本头、也**不**复制字段名: 探针把列名与中文名作为数据
 *   自己打出来(rec=field / rec=label 两行), 解析侧现读现建。isbench.py 唯一允许
 *   "规划"的是主键/引用键/测试标识 —— 见第 2 节。
 */
#ifndef IB_FIELDS_H
#define IB_FIELDS_H

/* ==================== 1. 记录类型: 每行第一列 = 这一行是什么 ====================
 * 一个文件可以有多段, 每段以 field 行起头(field/label/data 三件套), 解析按 field 行
 * 分段: 换一组列就换一段, 不必回头改解析器。
 * 列名对齐约定: 第 0 列装的是标签本身, field 行**不重复声明**它的列名 —— 声明从第 1
 * 列起, 与 data 行天然同位对齐。解析侧给第 0 列沿用 IB_COL_REC 这个惯例名。 */
#define IB_COL_REC        "rec"       /* 第 0 列的惯例名(field 行里不出现它) */
#define IB_L_COL_REC      "记录类型"   /* 同上, 给数据字典用 */
#define IB_L_REC_FUNC     "功能结果"   /* func 段的记录类型中文 */
#define IB_L_REC_DBG      "详细明细"   /* dbg 段的记录类型中文 */
#define IB_REC_META       "meta"      /* 本场运行标识与环境(k=v); 只有需要"换机回捞"的组才打 */
#define IB_REC_FIELD      "field"     /* 英文列名行 = 数据库列名, 段的起点 */
#define IB_REC_LABEL      "label"     /* 中文列名行 = 数据字典原料, 与 field 严格同列序 */
#define IB_REC_DATA       "data"      /* 实测数据行 */
#define IB_REC_GROUP      "group"     /* 组尾汇总行(ok/total 计数对账) */
#define IB_REC_FUNC       "func"      /* 功能结果行(段): 一行, 列 = 该组每个功能, 值 true/false */
#define IB_REC_DBG        "dbg"       /* 详细明细行(段, 仅 --debug): 逐条 in/gold/got 明细 */

/* ==================== 2. 身份字段: isbench.py 允许规划的那几个 ====================
 * 除本节之外的所有列, 解析侧一律现读现建, 不得在 Python 里存名。
 * ⚠ 保留字说明(CSV 与库内不同名不是随意, 别"顺手统一"):
 *   CSV 列 group/case 在 SQL 里是保留字(GROUP BY / CASE WHEN), 所以库内列名固定为
 *   grp/cname。两边的对应关系写死在这里, 谁改谁负责全仓重采。
 * pmul 表的键归属:
 *   主键   = (run_id, abi, grp, impl, family)
 *   引用键 = run_id -> runs.key; grp -> 产物名(= 可执行文件名)
 *   测试标识 = pmul_ver(按哪一版真值判的) + cpu/host/window_sec(哪台机、多长窗口) */
#define IB_F_RUN_ID       "run_id"
#define IB_L_RUN_ID       "本场运行标识"
#define IB_F_ABI          "abi"
#define IB_L_ABI          "指令集架构"
#define IB_F_OS           "os"
#define IB_L_OS           "操作系统"
#define IB_F_BITS         "bits"
#define IB_L_BITS         "指针位宽"
#define IB_F_GROUP        "group"         /* CSV 列; 库内列名 = grp(见上方保留字说明) */
#define IB_L_GROUP        "测试组名"
#define IB_F_GRP          "grp"           /* 库内列; 与 IB_F_GROUP 同义, 只出现在库里 */
#define IB_L_GRP          "测试组名(库内列)"
#define IB_F_CASE         "case"          /* CSV 列; 库内列名 = cname */
#define IB_L_CASE         "用例名"
#define IB_F_CNAME        "cname"         /* 库内列 */
#define IB_L_CNAME        "用例名(库内列)"
#define IB_F_WINDOW_SEC   "window_sec"    /* 定时长吞吐的时间窗口(秒): 由整数毫秒参数
                                           * --time MS 除以 1000 换算(只做整数->浮点) */
#define IB_L_WINDOW_SEC   "计时窗口(秒)"
#define IB_F_PROBE_VER    "probe_ver"     /* 探针/真值表版本: 任何一条度量都能反查按哪版判的 */
#define IB_L_PROBE_VER    "真值表版本"
#define IB_F_PMUL_VER     "pmul_ver"      /* pmul 组专用版本列(名字带组名, 不与通用列混) */
#define IB_L_PMUL_VER     "真值表版本(pmul)"
#define IB_F_CPU          "cpu"
#define IB_L_CPU          "CPU 型号"
#define IB_F_HOST         "host"
#define IB_L_HOST         "主机名"
#define IB_F_IMPLS        "impls"         /* 本场选了哪些实现(k=v 串内用逗号, 整元加引号) */
#define IB_L_IMPLS        "实现选择"
#define IB_F_FAMILIES     "families"
#define IB_L_FAMILIES     "档族选择"
#define IB_F_IMPL         "impl"
#define IB_L_IMPL         "实现"
#define IB_F_FAMILY       "family"
#define IB_L_FAMILY       "档族"
#define IB_F_OK           "ok"
#define IB_L_OK           "通过数"
#define IB_F_TOTAL        "total"
#define IB_L_TOTAL        "总数"
#define IB_F_STEM         "stem"          /* x87 真值表词干(一组 k 槽共用一个词干) */
#define IB_L_STEM         "词干"
#define IB_F_KK           "kk"            /* 真值槽序号(0..IB_KAT_N-1) */
#define IB_L_KK           "真值槽"
#define IB_F_STATUS       "status"
#define IB_L_STATUS       "状态"
#define IB_F_TIER         "tier"            /* pmul 档名(如 p00) */
#define IB_L_TIER         "档名"

/* ==================== 3. 度量列的词根与后缀 ====================
 * 列名 = <词根>_<后缀>, 中文名 = <词根中文> + <后缀中文>。
 * 单指令(一次一条)与 8 指令块(一次八条)这类结果, 只有词根+后缀都成体系, 跨组对列
 * 比才是"同一件事的两列", 而不是两个各自编的名字。 */
#define IB_W_LATENCY      "latency"       /* 单依赖链延迟 */
#define IB_LW_LATENCY     "单依赖链"
#define IB_W_THROUGHPUT   "throughput"    /* 定时长吞吐 */
#define IB_LW_THROUGHPUT  "定时长吞吐"
#define IB_W_BLOCK8       "block8"        /* 连续 8 指令块(本仓既有语义词, 不展开) */
#define IB_LW_BLOCK8      "8指令块"
#define IB_W_SEMANTIC     "semantic"      /* 语义对拍 */
#define IB_LW_SEMANTIC    "语义对拍"
#define IB_W_KAT          "kat"           /* known-answer test: 行业缩写, 展开反而没人认 */
#define IB_LW_KAT         "真值比对"
#define IB_W_DIAG         "diag"          /* 环境/能力自描述 */
#define IB_LW_DIAG        "环境自描述"

#define IB_SUF_STATUS     "_status"
#define IB_LS_STATUS      "状态"
#define IB_SUF_NS         "_ns"           /* 单位: 纳秒 */
#define IB_LS_NS          "纳秒"
#define IB_SUF_ITERS      "_iters"
#define IB_LS_ITERS       "迭代次数"
#define IB_SUF_OPS_S      "_ops_s"        /* 单位: 每秒操作数 */
#define IB_LS_OPS_S       "每秒操作数"
#define IB_SUF_MB_S       "_mb_s"         /* 单位: 每秒兆字节(内存型用例才有值) */
#define IB_LS_MB_S        "每秒兆字节"
#define IB_SUF_SIG        "_sig"          /* 结果签名: 16 位十六进制 */
#define IB_LS_SIG         "结果签名"
#define IB_SUF_TAG        "_tag"          /* 数据集标识: 签名是在哪套输入上算的 */
#define IB_LS_TAG         "数据集标识"
#define IB_SUF_DETAIL     "_detail"
#define IB_LS_DETAIL      "明细"
#define IB_SUF_KAT        "_kat"          /* pmul 用: 一档一个全宽校验串 */
#define IB_LS_KAT         "校验串"
#define IB_SUF_VALUE      "_value"
#define IB_LS_VALUE       "数值"
#define IB_SUF_UNIT       "_unit"
#define IB_LS_UNIT        "单位"
/* ⚠ 中文拼接规则: 词根只说"测的是什么", 后缀只说"量的是哪个量" —— 两边都不带单位
 * 括号也不带对象名, 拼起来才不会像"定时长吞吐吞吐(ops/s)"这种叠字(叠字就是设计
 * 缺陷的信号, 不要靠往中间塞空格来遮)。 */

/* ==================== 4. 性能表 16 列: 表序的唯一出处 ====================
 * 输出分三段, 段的 frame 宏都收在这里(表序一旦只能从这一处长出来, "改了表头忘了
 * 改解析侧"这类漂移在结构上就不可能发生):
 *   性能段 data 行 = IB_WIDE_FIELD;  功能段 func 行 = IB_FUNC_FIELD + 各组功能名;
 *   详细段 dbg 行 = IB_DBG_FIELD(仅 --debug 时才吐)。
 * 性能段只留"具体指标 + 状态": 结果签名(sig)/语义对拍(semantic)/迭代数(iters)/
 * kat 明细/diag 明细 全部拿掉 —— "对不对"由功能段(verify_<grp>)与详细段(debug_<grp>)
 * 单独承担, 不再混进性能表。
 * 注: 第 0 列(rec)由打印方用 IB_REC_FIELD/IB_REC_LABEL 占位, 不在本表序里重复声明。 */
/* 分段 token: 供 ib_hdr()/ib_flush() 按 --no-lat/--no-tput/--no-b8 动态拼接列集
 * (关掉的指标整列不输出); IB_WIDE_FIELD/LABEL 由它们拼成, 仍是单一来源不漂移。 */
#define IB_FLD_ID   IB_F_GROUP "," IB_F_ABI "," IB_F_OS "," IB_F_BITS
#define IB_LBL_ID   IB_L_GROUP "," IB_L_ABI "," IB_L_OS "," IB_L_BITS
#define IB_FLD_LAT  IB_W_LATENCY IB_SUF_STATUS "," IB_W_LATENCY IB_SUF_NS
#define IB_LBL_LAT  IB_LW_LATENCY IB_LS_STATUS "," IB_LW_LATENCY IB_LS_NS
#define IB_FLD_TPUT IB_W_THROUGHPUT IB_SUF_STATUS "," IB_W_THROUGHPUT IB_SUF_OPS_S "," IB_W_THROUGHPUT IB_SUF_MB_S
#define IB_LBL_TPUT IB_LW_THROUGHPUT IB_LS_STATUS "," IB_LW_THROUGHPUT IB_LS_OPS_S "," IB_LW_THROUGHPUT IB_LS_MB_S
#define IB_FLD_B8   IB_W_BLOCK8 IB_SUF_STATUS "," IB_W_BLOCK8 IB_SUF_NS
#define IB_LBL_B8   IB_LW_BLOCK8 IB_LS_STATUS "," IB_LW_BLOCK8 IB_LS_NS
#define IB_FLD_DIAG IB_W_DIAG IB_SUF_STATUS "," IB_W_DIAG IB_SUF_VALUE "," IB_W_DIAG IB_SUF_UNIT
#define IB_LBL_DIAG IB_LW_DIAG IB_LS_STATUS "," IB_LW_DIAG IB_LS_VALUE "," IB_LW_DIAG IB_LS_UNIT

#define IB_WIDE_FIELD \
    IB_FLD_ID "," IB_F_WINDOW_SEC "," IB_F_CASE "," IB_FLD_LAT "," IB_FLD_TPUT "," IB_FLD_B8 "," IB_FLD_DIAG

#define IB_WIDE_LABEL \
    IB_LBL_ID "," IB_L_WINDOW_SEC "," IB_L_CASE "," IB_LBL_LAT "," IB_LBL_TPUT "," IB_LBL_B8 "," IB_LBL_DIAG

/* 功能段: 固定前缀(group/abi) + 各组功能名(探针按序自己打); 值 = true/false/- */
#define IB_FUNC_FIELD     IB_F_GROUP "," IB_F_ABI
#define IB_FUNC_LABEL     IB_L_GROUP "," IB_L_ABI
/* 详细段(标准组): 逐 (用例, 真值槽 kk) 一条, 与旧 K 行同位(仅去掉 kind 标签)。
 * 10 字真值单元 = 输入 i0..i3 + inf + 输出 o0..o3 + outf(见 ib_core.h ib_kv)。 */
#define IB_DBG_FIELD \
    IB_F_GROUP "," IB_F_ABI "," IB_F_CASE "," IB_F_STEM "," IB_F_KK "," \
    "i0,i1,i2,i3,inf,o0,o1,o2,o3,outf,src"
#define IB_DBG_LABEL \
    IB_L_GROUP "," IB_L_ABI "," IB_L_CASE "," IB_L_STEM "," IB_L_KK "," \
    "输入0,输入1,输入2,输入3,输入标志,输出0,输出1,输出2,输出3,输出标志,来源"
/* 详细段(pmul): 逐 (实现,档族,档) 一条; 列名复用明细串的键名(§6) */
#define IB_PMUL_DBG_FIELD \
    IB_F_GROUP "," IB_F_ABI "," IB_F_CASE "," IB_F_TIER "," \
    IB_K_IN "," IB_K_GOLD "," IB_K_GOT "," IB_K_STATUS "," \
    IB_K_INBITS "," IB_K_MINPOP
#define IB_PMUL_DBG_LABEL \
    IB_L_GROUP "," IB_L_ABI "," IB_L_CASE "," IB_L_TIER "," \
    IB_LK_IN "," IB_LK_GOLD "," IB_LK_GOT "," IB_LK_STATUS "," \
    IB_LK_INBITS "," IB_LK_MINPOP

/* ==================== 5. 状态串取值: 全仓一套, 新组不得自造同义词 ====================
 * 占位符 IB_V_NONE 在库里存 NULL("没测"与"测了且值为 0"必须是两件事)。 */
#define IB_ST_OK          "OK"
#define IB_ST_FAIL        "FAIL"
#define IB_ST_CRASH       "CRASH"              /* 抓到信号: Linux 侧可跳回, Windows 侧进程终止 */
#define IB_ST_PASS        "PASS"
#define IB_ST_UNSUPPORTED "HOSTUNSUPPORTED"    /* 本机不具备该能力(CPUID/OS 层) */
#define IB_ST_NOGOLD      "NOGOLD"             /* 真值表未回填: 此刻"正确"尚未定义 */
#define IB_ST_KATFAIL     "KATFAIL"
#define IB_ST_INMISMATCH  "INMISMATCH"         /* 错档核: 表内输入 != 现场生成输入 */
#define IB_ST_COLLECT     "COLLECT"            /* 本次目的就是采集 got */
#define IB_ST_TIERMIS     "TIERMISMATCH"       /* 档位被增删过而真值未重采 */
#define IB_V_NONE         "-"                  /* 未测/不适用的占位: 全仓唯一记号 */
#define IB_V_TRUE         "true"               /* 功能判定: 正常 */
#define IB_LV_TRUE        "正常"
#define IB_V_FALSE        "false"              /* 功能判定: 异常 */
#define IB_LV_FALSE       "异常"

/* ==================== 6. 明细串文法与串内键名 ====================
 * 一列装不下全宽输入输出时(kat/diag/detail), 用串内键; 串内一律用 ';' 分段, 段内
 * 'k=v', **绝不允许出现逗号**(逗号是列分隔符, 一个逗号就把一列撑成两列 —— 实测撞过
 * meta 的 impls 值, 所以 meta 里带逗号的单元必须整元加双引号)。 */
#define IB_K_IN           "in"
#define IB_LK_IN          "输入"
#define IB_K_GOLD         "gold"
#define IB_LK_GOLD        "真值"
#define IB_K_GOT          "got"
#define IB_LK_GOT         "实测"
#define IB_K_STATUS       "status"
#define IB_LK_STATUS      "状态"
#define IB_K_INBITS       "inbits"            /* 两侧输入有效位宽之和 */
#define IB_LK_INBITS      "两侧输入位数之和"
#define IB_K_MINPOP       "minpop"            /* 较少置位一侧的位数(成本归属分析用) */
#define IB_LK_MINPOP      "较少置位侧的位数"

#endif /* IB_FIELDS_H */
