/* isb_pmul.c —— isbench 组 pmul: 同一条 64x64->128 无进位乘的「多实现同 run 对照」
 *
 * 为什么要有这个组(现有 crypto/pclmulqdq 测不出来):
 *   crypto 组只回答「硬件 pclmulqdq 在 LATX 下多快」, 答不出「同样这一次乘法用纯
 *   查表软模拟要多久」。设计文档《LATX-PCLMULQDQ翻译优化-遍历稀疏侧》第 7 节把
 *   查表法定为 Tier-2 却没有任何实测数据, 决策留档里那条「纯查表被否 —— 两侧均为
 *   运行期值、无静态表形态」更是直接关于本指令的判断。本组的存在就是用实测去
 *   检验这条命题, 而不是继续引用它。
 *
 * 五种内核(同骨架, 所以共模可减):
 *   base  无乘法的空骨架        —— 量化骨架本身(循环 + volatile 载入 + call)的成本
 *   ref   64 圈逐位 shift/xor    —— 任何机器上都成立的独立判据, 也是两张表的建表器
 *   hw    pclmulqdq              —— 与 crypto/pclmulqdq 同一编码纪律(target 属性放行)
 *   t4    uint8_t  T4[16][16]    =   256 B, 16x16 = 256 次查表(表极小、次数多)
 *   t8    uint16_t T8[256][256]  = 128 KB,  8x8  =  64 次查表(表大、次数少)
 *
 * 二维表不可退化(判定基准, 也是本组成立的前提):
 *   真实 GHASH 负载里 a 与 b 都是运行期值, 谁都不是常数 —— 所以表形态固定为
 *   T[索引(a)][索引(b)], 两侧索引都在运行期从变量算出, 建表与取表路径两侧对称。
 *   一维退化表(把某一侧当常数预乘)在这里不成立, 拿它测出来的成本也是假的。
 *   两侧操作数一律经 volatile 载入, 保证「两侧都是变量」这件事在机器码层面成立。
 *
 * 明确禁止跳零优化: 查表次数恒为 256/64 是所有档位之间可比的前提(整条成本曲线
 *   的解释力全在这个恒定次数上)。若为提速而跳过零段, 曲线立刻失去意义。
 *
 * 度量单位 = 单次 64x64 -> 128 乘。GHASH 的 128x128(4 次单乘 + 折半合并)不在本组。
 *
 * 输出契约(不套 IB_ROW_* 模板、不注册 ib_case; 名字全取自
 * ib_fields.h, 本文件不自造同义词): 每行第一列 = 记录类型, 解析按 field 行分段 ——
 * 一个文件里换一组列就换一段, 所以 isbench.py 不需要保存本组的字段名。
 *   meta ,pmul_ver=..,abi=..,os=..,bits=..,window_sec=..,"cpu=..","host=..","impls=..","families=.."
 *   field,abi,os,bits,window_sec,pmul_ver,impl,family,<档>_ns,<档>_it,<档>_ops,<档>_kat, ...
 *   label,<中文名行>: 与 field 严格同列序, 逐列一个中文名(数据字典的原料)
 *   data ,<值行>: 行 = (实现, 档族) 二维, 非本族档一律打 IB_V_NONE("-") -> 解析成 NULL
 *   列名对齐约定: 第 0 列装的是"这一行是什么"的标签本身, field 行**不重复声明**
 *   它的列名 —— 声明从第 1 列起, 与 data 行天然同位对齐。解析侧给第 0 列沿用
 *   IB_COL_REC("rec") 这个惯例名即可, 不必猜。值里带逗号的单元整元加双引号。
 *   <档>_kat 文法: in=<a>:<b>;gold=<lo>:<hi>;got=<lo>:<hi>;status=<..>;inbits=<n>;minpop=<n>
 *   单列承载全宽输入输出(384 个度量列再各配 4 列会撑不住), 串内不含逗号。
 *   isbench.py 只规划主键/引用键/测试标识(run_id,abi,grp,impl,family 与 pmul_ver),
 *   其余列现读现建 —— 字段名与中文名的唯一出处是 ib_fields.h, 本组与宽表组共用。
 *
 * 崩溃兜底的不对称(必须知道): Linux 侧信号可 siglongjmp 回来 -> 该档 st=CRASH;
 * Windows 侧 VEH 只认 ib.h 的宽表用例上下文, 本探针不设那个上下文, 真崩就是进程
 * 终止、CSV 残缺 -> 解析侧按"值行数不足"报错重采。这不是漏改, 而是不肯让崩溃
 * 顺便往我的 CSV 里插一行 29 列宽表数据(那才是真正会静默污染入库的形态)。
 */
#include "ib_fields.h"        /* 字段名/中英文名/状态串/记录类型的唯一出处 */
#include "ib_core.h"
#include "isb_pmul_gold.h"
#ifndef _WIN32
#include <sys/utsname.h>      /* 仅真机守卫用: 见 pmul_gold_host_ok() */
#endif

/* ==================== 1. 档位表(96 档, 全部由规则生成) ====================
 * 采集模式: **不特意固定任何操作数** —— 按规则生成指定位长
 * 的 bit, 填进指令的寄存器, 执行, 读回输出寄存器, 再把这一对"输入/输出"存成
 * 常量表。所以本文件里没有任何手挑的"有意义的数"(原先的稠密魔数
 * 0xdeadbeefcafe1235 与一对 GCM 规范向量已全部删除): 每个操作数都是 (位长 L,
 * 序号 k) 的纯函数, 任何人照 pmul_bits() 那几行重算一遍就能逐位复核整张表
 * (Python 侧那份第三方核就是这么做的)。
 *
 * 档位仍是公式推导、不手写常数, 并与编译期真值表逐档核对: 手写 96 行 (a,b) 与
 * 真值表两份并存的后果是"增删一档后真值错档", 而错档是静默的(A 档的真值判 B 档
 * 的结果, 照样能绿)。核对逻辑见 pmul_check_gold()。
 */
enum { FAM_BIT, FAM_WONE, FAM_WHI, FAM_DUAL, FAM_RND, FAM_N };
static const char *g_fam[FAM_N] = { "bit", "wone", "whi", "dual", "rnd" };

#define PT_MAX 96
static const int g_wl[6] = { 2, 4, 8, 16, 32, 64 };   /* wone/whi 档的有效位宽 */
static const int g_dl[4] = { 2, 8, 32, 64 };          /* dual 档两侧位宽(报告阈值 6~8) */

struct pmul_tier {
    char name[8];
    uint64_t a, b;
    int fam;
};
static struct pmul_tier g_pt[PT_MAX];
static int g_pt_n;

/* 有效位宽(不是 popcount): 0 -> 0, 否则最高置位位的位置 + 1 */
static int pmul_width(uint64_t x)
{
    return x ? 64 - __builtin_clzll(x) : 0;
}

/* (1<<L)-1, L=64 时不能左移 64(未定义), 单独给全掩码 */
static uint64_t pmul_mask(int L)
{
    return L >= 64 ? ~(uint64_t)0 : (((uint64_t)1 << L) - 1);
}

/* 规则位模式: 生成一个"有效位宽恰为 L"的操作数, 值只由 (L, k) 决定 ——
 *   x = 1; 迭代 (L + k) 次 { x = x*3 + 1; x ^= x >> 13; x ^= x << 7; }
 *   取低 L 位, 再强制最高位置 1。
 * 为什么是这个形状: 乘 3 与那两个位移量都是**结构参数**(与"1<<p"同级别的中性
 * 规则), 不是被挑出来代表某种真实数据或某个规范向量的值 —— 这就是"不特意固定
 * 某些东西"。把高位搅回低位是必要的: 纯 x*3+1 的低位周期太短, 在小 L 上会退化
 * 成几个雷同的数。强制最高位是"指定长度"四个字的兑现: 不强制的话生成值的实际
 * 位宽常常小于 L。可复现性: 每步都是 mod 2^64 的整数运算, 换语言重写逐位相同。 */
static uint64_t pmul_bits(int L, unsigned k)
{
    uint64_t x = 1;
    unsigned i;

    if (L <= 0)
        return 0;
    for (i = 0; i < (unsigned) L + k; i++) {
        x = x * 3u + 1u;
        x ^= x >> 13;
        x ^= x << 7;
    }
    return (x & pmul_mask(L)) | ((uint64_t)1 << (L - 1));
}

static void pmul_tier_add(int fam, const char *name, uint64_t a, uint64_t b)
{
    struct pmul_tier *t;
    if (g_pt_n >= PT_MAX) {
        fprintf(stderr, "pmul: 档位超过 %d, 档位表被静默截断 -> 立即终止\n", PT_MAX);
        exit(2);
    }
    t = &g_pt[g_pt_n++];
    snprintf(t->name, sizeof t->name, "%s", name);
    t->a = a;
    t->b = b;
    t->fam = fam;
}

static void pmul_build_tiers(void)
{
    char nm[8];
    int i, p, j;

    /* family bit: a = 1<<p 逐位扫过 p=0..63; b = 规则位模式(k=p 就换一个值, 于是
     * 64 档的稠密侧各不相同、且没有一个是手挑的)。p=64 在 64 位操作数上无定义,
     * 所以"最长位数"由 wone/whi 的 L=64 档收尾, 不在此族硬凑。 */
    for (p = 0; p < 64; p++) {
        snprintf(nm, sizeof nm, "p%02d", p);
        pmul_tier_add(FAM_BIT, nm, (uint64_t)1 << p, pmul_bits(64, (unsigned) p));
    }
    /* family wone: a=b=(1<<L)-1, 逼出表索引全 0xF / 0xFF */
    for (i = 0; i < 6; i++) {
        snprintf(nm, sizeof nm, "d%02d", g_wl[i]);
        pmul_tier_add(FAM_WONE, nm, pmul_mask(g_wl[i]), pmul_mask(g_wl[i]));
    }
    /* family whi: a=b=1<<(L-1), 逼出索引 0x1 配一整个 0x0 侧 */
    for (i = 0; i < 6; i++) {
        snprintf(nm, sizeof nm, "h%02d", g_wl[i]);
        pmul_tier_add(FAM_WHI, nm, (uint64_t)1 << (g_wl[i] - 1),
                      (uint64_t)1 << (g_wl[i] - 1));
    }
    /* family dual: 两侧独立变元 16 档矩阵, La 主序。
     * 这是"两个变量都没有一个是常数"的代表族 —— 二维表双侧索引就是为它存在的。
     * 非对称档 m03=(2,64) 与 m12=(64,2): 若 LATX 真按稀疏侧遍历, 两档在同 minpop
     *   下应当等价(坐实成本归属); t4/t8 在两档的差值则是双侧索引对表的缓存压力。
     * m15=(64,64) 就是 GHASH 的稠密x稠密形态(Tier-2 是否重启的直接判据)。 */
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++) {
            snprintf(nm, sizeof nm, "m%02d", i * 4 + j);
            pmul_tier_add(FAM_DUAL, nm, pmul_mask(g_dl[i]), pmul_mask(g_dl[j]));
        }
    /* family rnd: 四档全部由 pmul_bits() 现算 —— 含一对交换序(积必须相同)与两个
     * 自乘档(积必须等于上面的位扩散恒等式), 两条判据都不需要任何固定常数。 */
    pmul_tier_add(FAM_RND, "r01", pmul_bits(64, 1), pmul_bits(64, 2));
    pmul_tier_add(FAM_RND, "r02", pmul_bits(64, 2), pmul_bits(64, 1));
    pmul_tier_add(FAM_RND, "r03", pmul_bits(64, 1), pmul_bits(64, 1));
    pmul_tier_add(FAM_RND, "r04", pmul_bits(64, 2), pmul_bits(64, 2));
}

/* ==================== 2. 五种内核 ====================
 * 统一签名: 结果写进 out[3]。第三个 limb 是**溢出检查位** —— 数学上恒应为 0
 * (t4 最高到 bit 126、t8 到 125、ref/hw 天然 128 位内), 所以一旦非 0 就说明
 * 索引或位偏算错了; 与其按"两个 limb 足够"静默截断, 不如留着它当场暴露。
 */
static volatile uint64_t g_a, g_b;      /* 两侧操作数都必须是运行期 volatile 载入 */
static volatile uint64_t g_sink;        /* 计时结果的去向, 防整个循环被 DCE */

typedef void (*pmul_mul_fn)(uint64_t a, uint64_t b, uint64_t *out);

static inline void pmul_acc_xor(uint64_t *acc, uint64_t v, int sh)
{
    int lw = sh >> 6, s = sh & 63;
    acc[lw] ^= v << s;
    if (s)
        acc[lw + 1] ^= v >> (64 - s);   /* sh<128 => lw<=1 => 下标<=2, 不越界 */
}

/* base: 不乘, 只走同一套载入/累加/返回。它是其余四条的共模。 */
static void mul_base(uint64_t a, uint64_t b, uint64_t *out)
{
    out[0] = a ^ b;
    out[1] = 0;
    out[2] = 0;
}

/* ref: 固定 64 圈、**不跳零** —— 每圈都算掩码并累加, 圈数与输入密度无关。
 * 它是"等价于 LATX 旧循环形态"的**成本参考实现**(与 t4/t8 同为被测对象)。
 * 注意它不参与裁决对错: 判定标准只有真机采集进来的那张常量表(见第 8b 节)。 */
static void mul_ref(uint64_t a, uint64_t b, uint64_t *out)
{
    int i;
    out[0] = out[1] = out[2] = 0;
    for (i = 0; i < 64; i++) {
        /* 无分支掩码: 该位 1 -> 全 1, 0 -> 全 0。写成 `~0 + bit` 是错的
         * (bit=1 时 +1 正好回绕成 0, 掩码反了), 必须用 0 - bit。 */
        uint64_t m = 0 - (uint64_t)((b >> i) & 1u);
        pmul_acc_xor(out, a & m, i);
    }
}

/* hw: ctrl 是编译期立即数(0x00 = 两个低 64 位相乘); x/y 的高 64 位留 0。
 * 禁自反馈链(x=clmul(x,k) 那种) —— 它会改变操作数密度, 档位语义就没了。 */
__attribute__((target("pclmul"))) static void mul_hw(uint64_t a, uint64_t b,
                                                     uint64_t *out)
{
    __m128i x = _mm_set_epi64x(0, (long long)a);
    __m128i y = _mm_set_epi64x(0, (long long)b);
    uint64_t h[2];
    _mm_storeu_si128((__m128i *)h, _mm_clmulepi64_si128(x, y, 0x00));
    out[0] = h[0];
    out[1] = h[1];
    out[2] = 0;
}

/* 两张真二维交叉乘积表。尺寸钉在编译期: 判定基准就是 256 B / 128 KB 这两档,
 * 任何一侧被改窄(例如把 t8 退化成 [256])都会在这里编译不过, 而不是悄悄变快。 */
static uint8_t  g_t4[16][16];
static uint16_t g_t8[256][256];
_Static_assert(sizeof g_t4 == 256, "t4 表必须是 16x16 uint8_t = 256 B");
_Static_assert(sizeof g_t8 == 131072, "t8 表必须是 256x256 uint16_t = 128 KB");

/* t4: a、b 各拆 16 个半字节, 每对段查 T4[段(a)][段(b)] 再左移 4*(x+y)。
 * 查表次数恒 16x16 = 256, 不跳零。两侧路径完全对称(没有"一侧是常数"的分支)。 */
static void mul_t4(uint64_t a, uint64_t b, uint64_t *out)
{
    int x, y;
    out[0] = out[1] = out[2] = 0;
    for (x = 0; x < 16; x++) {
        unsigned ia = (unsigned)((a >> (4 * x)) & 0xFu);
        for (y = 0; y < 16; y++) {
            unsigned ib = (unsigned)((b >> (4 * y)) & 0xFu);
            pmul_acc_xor(out, (uint64_t)g_t4[ia][ib], 4 * (x + y));
        }
    }
}

/* t8: 同上, 8 个字节段, 查表次数恒 8x8 = 64。 */
static void mul_t8(uint64_t a, uint64_t b, uint64_t *out)
{
    int x, y;
    out[0] = out[1] = out[2] = 0;
    for (x = 0; x < 8; x++) {
        unsigned ia = (unsigned)((a >> (8 * x)) & 0xFFu);
        for (y = 0; y < 8; y++) {
            unsigned ib = (unsigned)((b >> (8 * y)) & 0xFFu);
            pmul_acc_xor(out, (uint64_t)g_t8[ia][ib], 8 * (x + y));
        }
    }
}

#define IMPL_N 5
static const char *g_impl[IMPL_N] = { "base", "ref", "hw", "t4", "t8" };
static pmul_mul_fn g_fn[IMPL_N] = { mul_base, mul_ref, mul_hw, mul_t4, mul_t8 };
/* 该内核是否为纯软件实现: hw 需要 CPUID 门控, 其余四条任何机器都能跑 */
static const int g_impl_needs_pclmul[IMPL_N] = { 0, 0, 1, 0, 0 };

/* 建表: 由 ref 逐格填(不计入任何计时)。填完必须确认高位段真的是 0 —— 表宽
 * (8 位 / 16 位)是按"4x4 积不超 8 位、8x8 积不超 15 位"这个事实定的, 事实若
 * 不成立, 表本身就已经把结果截断了, 后面怎么测都是错的。 */
static int g_tbl_bad;
static void pmul_build_tables(void)
{
    int i, j;
    uint64_t o[3];
    for (i = 0; i < 16; i++)
        for (j = 0; j < 16; j++) {
            mul_ref((uint64_t)i, (uint64_t)j, o);
            if (o[1] || o[2])
                g_tbl_bad = 1;
            g_t4[i][j] = (uint8_t)o[0];
        }
    for (i = 0; i < 256; i++)
        for (j = 0; j < 256; j++) {
            mul_ref((uint64_t)i, (uint64_t)j, o);
            if (o[1] || o[2])
                g_tbl_bad = 1;
            g_t8[i][j] = (uint16_t)o[0];
        }
    if (g_tbl_bad) {
        fprintf(stderr, "pmul: 建表发现段积超出表宽(表形态与数学不自洽) -> 立即终止\n");
        exit(2);
    }
}

/* ==================== 3. 运行选项与状态 ====================
 * 窗口默认 50 ms 而不是 ib.h 的 100 ms: 本组一个形态有 5 实现 x 96 档 x 2 方式
 * = 960 个计时点, 按 100 ms 算单形态也要 ~96s。自适应定时保证「不管机器差多少
 * 倍, 总耗时都近似」, 这正是 LATX(native 的 5~30 倍慢)与本组天然适配的地方。 */
#define PMUL_TMS_DEF    50
#define PMUL_LAT_WARM   1000ULL     /* 第一轮只预热, 不出数 */
#define PMUL_LAT_ROUNDS 6           /* 预热 + 最多 5 轮放大 */
/* 迭代上限: 自适应放大最多到此。再受本机字长约束 —— 计时内核形参已是 ib_uw(i386=32 位),
 * 若 it 超过 2^32-1 会被静默截断, 故在 i386 上把上限压回 IB_UW_MAX(x64 仍为 2^34)。 */
#define PMUL_IT_CAP     ((1ULL << 34) < IB_UW_MAX ? (1ULL << 34) : IB_UW_MAX)
#define PMUL_NCHAIN     8           /* tput 独立累加链数 */
#define PMUL_TPUT_BLK   1024        /* tput 每查一次钟的每链操作数 */
#define PMUL_KAT_N      320         /* kat 串上限: 6 段 16 位定宽 16 进制串 + 标签, 实测 ~160 */

enum { IMPL_BASE, IMPL_REF, IMPL_HW, IMPL_T4, IMPL_T8 };

static int g_sel_i[IMPL_N];
static int g_sel_f[FAM_N];
static int g_collect;               /* --collect: 无真值采集模式 */
static int g_list;
/* --gen-gold: 本组自己出真值表(硬件直算 + 逐位模型复算, 见第 8b 节) */
static int g_gen_gold, g_gen_gold_fail;
static const char *g_gold_ver;      /* --gold-ver; 未给则按 abi 生成 */
static char g_gold_ver_buf[64];
/* 用户到底给没给这个选择器 —— "没给"与"给了但一个都没命中"是两件事:
 * 前者该全选, 后者必须拒跑。混为一谈会让 --impl 拼错变成一次静默的全量测量。 */
static int g_i_given, g_f_given;
static int g_hw_ok;                 /* CPUID pclmul */
static int g_tier_mismatch;         /* 真值表与公式档位不一致(致命) */

struct pmul_meas {
    double ns;                    /* lat: 单次 64x64->128 乘的稳态 ns */
    double ops;                   /* tput: ops/s(浮点速率, 不是圈数 —— 圈数在 it 里) */
    unsigned long long it;         /* lat 实际迭代数(自适应的产物, 必须报出来) */
    uint64_t got[3];               /* 单发结果(kat 判定的依据, 与计时链无关) */
    int has;                       /* 本档本次是否真测过 */
    int bad;                       /* 保护区抓到信号 -> st=CRASH */
    char kat[PMUL_KAT_N];
};
static struct pmul_meas g_m[PT_MAX];

/* ==================== 4. 真值核对(防静默假绿) ====================
 * 档位由公式生成、真值由表提供, 两份并存的风险是"加了/删了一档之后, A 档的
 * 真值去判 B 档的结果" —— 这种错档往往照样全绿。所以启动即逐档核对 (a,b)。
 * 不一致时不计时: 一份解释不了的 200 s 计时表没有价值(行照出, 全档标 TIERMISMATCH)。 */
static void pmul_check_gold(void)
{
    int i;

    if (IB_PMUL_GOLD_N == 0)
        return;                     /* 未回填: 走 NOGOLD, 不算不一致 */
    if (IB_PMUL_GOLD_N != PT_MAX || IB_PMUL_GOLD_N != g_pt_n) {
        g_tier_mismatch = 1;
        fprintf(stderr, "pmul: 真值表 %d 行 / 探针档位 %d 档 / 表上限 %d 不一致\n"
                        "      -> 全部判 TIERMISMATCH; 请用 pack/gen_gold_pmul.sh 重新回填真值表\n",
                IB_PMUL_GOLD_N, g_pt_n, PT_MAX);
        return;
    }
    for (i = 0; i < g_pt_n; i++) {
        if (g_pmul_gold[i][0] != g_pt[i].a || g_pmul_gold[i][1] != g_pt[i].b) {
            g_tier_mismatch = 1;
            fprintf(stderr, "pmul: 第 %d 档(%s) 输入与真值表错位\n"
                            "      表=%016llx:%016llx 探针=%016llx:%016llx\n"
                            "      -> 档位被增删过而真值未重采; 全部判 TIERMISMATCH\n",
                    i, g_pt[i].name,
                    (unsigned long long)g_pmul_gold[i][0],
                    (unsigned long long)g_pmul_gold[i][1],
                    (unsigned long long)g_pt[i].a,
                    (unsigned long long)g_pt[i].b);
            return;
        }
    }
}

/* ==================== 5. kat 串与状态判定 ====================
 * 单列承载全宽输入输出: in=<a>:<b>;gold=<lo>:<hi>;got=<lo>:<hi>;status=<..>;inbits=<..>;minpop=<..>
 * gold=-:- 的两个场合(真值未回填 / 档位错档)都是"参考系不可信"的意思 —— 不打
 * 一串全零假装有真值, 那会被当成合法的零结果。 */
static void pmul_kat_str(char *dst, size_t n, const struct pmul_tier *t,
                         const uint64_t *got, const uint64_t *gold,
                         const char *st)
{
    int wa = pmul_width(t->a), wb = pmul_width(t->b);
    char gsf[40], gotf[40];

    if (gold)
        snprintf(gsf, sizeof gsf, "%016llx:%016llx",
                 (unsigned long long)gold[0], (unsigned long long)gold[1]);
    else
        snprintf(gsf, sizeof gsf, IB_V_NONE ":" IB_V_NONE);
    if (got)
        snprintf(gotf, sizeof gotf, "%016llx:%016llx",
                 (unsigned long long)got[0], (unsigned long long)got[1]);
    else
        snprintf(gotf, sizeof gotf, IB_V_NONE ":" IB_V_NONE);
    snprintf(dst, n, IB_K_IN "=%016llx:%016llx;" IB_K_GOLD "=%s;" IB_K_GOT "=%s;"
             IB_K_STATUS "=%s;" IB_K_INBITS "=%d;" IB_K_MINPOP "=%d",
             (unsigned long long)t->a, (unsigned long long)t->b, gsf, gotf, st,
             wa + wb, wa < wb ? wa : wb);
}

/* 自己的保护区: 只借 ib.h 的 setjmp/信号钩子, **绝不设 ib_cur_grp/ib_cur_name**。
 * 一设那三个, Windows VEH 就会往 stdout 打一行 29 列宽表数据(ib.h 的格式),
 * 那才是真正会静默污染本组 CSV 的形态 —— 比"崩了没留痕"严重得多。 */
#define PMUL_TRY(bad, BODY) do {                                              \
        ib_sig_nr = 0;                                                        \
        ib_intest = 1;                                                        \
        if (IB_SIGSETJMP(ib_jb) == 0) {                                       \
            BODY                                                              \
        } else {                                                              \
            ib_intest = 0;                                                    \
            (bad) = 1;                                                        \
        }                                                                     \
        ib_intest = 0;                                                        \
    } while (0)

/* ==================== 6. 计时内核 ==================== */

/* lat: 单依赖累加链, 返回**总耗时 ns**。每圈都重新从 volatile 载入两侧操作数:
 * 把载入提到循环外, 编译器就有了把整个乘法常数折叠掉的空间, 测出来的就不再是
 * "两侧都是变量"的成本(那是本组成立的前提)。 */
static uint64_t pmul_lat(pmul_mul_fn fn, uint64_t a, uint64_t b,
                         ib_uw iters)
{
    uint64_t acc[3] = { 0, 0, 0 };
    ib_uw i;
    uint64_t t0, t1;        /* 整数纳秒: 不用 double 往返 */

    g_a = a;
    g_b = b;
    IB_BARRIER();
    t0 = ib_now();
    for (i = 0; i < iters; i++) {
        uint64_t o[3];
        fn(g_a, g_b, o);
        acc[0] ^= o[0];
        acc[1] ^= o[1];
        acc[2] ^= o[2];
    }
    t1 = ib_now();
    IB_BARRIER();
    g_sink ^= acc[0] ^ acc[1] ^ acc[2];   /* 结果有去向, 整个循环不可 DCE */
    return t1 - t0;
}

/* 定时自适应: 先 1000 圈预热, 再按实测速率补齐到窗口。慢机器(LATX)自动少跑,
 * 快机器自动多跑, 于是每个度量点花的 wall time 近似相等。 */
static uint64_t pmul_lat_fit(pmul_mul_fn fn, uint64_t a, uint64_t b,
                             unsigned long long *it_out, int *bad)
{
    const uint64_t target = (uint64_t)g_tput_ms * 1000000ULL;  /* 窗口: 毫秒 -> 纳秒 */
    /* volatile 不是防优化而是保正确: 这三个量在 setjmp 与 longjmp 之间被改,
     * 不钉在内存里则崩溃回来后的值是未定义的(C99 7.13.2.1)。 */
    volatile unsigned long long it = PMUL_LAT_WARM;
    volatile uint64_t el = 0;
    volatile int round;

    for (round = 0; round < PMUL_LAT_ROUNDS; round++) {
        unsigned long long per, want;
        int b2 = 0;

        PMUL_TRY(b2, { el = pmul_lat(fn, a, b, it); });
        if (b2) {
            *bad = 1;
            *it_out = 0;
            return 0;
        }
        if (round == 0)                 /* 预热轮不出数, 只给速率定标 */
            continue;
        /* 整数比例换算下一轮圈数: 目标总耗时 target / 每圈耗时(el/it)。
         * per 取整到下界会把 want 略高估, 但这里只是"估到量级", 下一轮实测会修正。 */
        per = el / it;
        if (per == 0)
            per = 1;
        if (el >= target)
            break;
        want = target / per;
        it = want >= PMUL_IT_CAP ? PMUL_IT_CAP : want;
        if (it < PMUL_LAT_WARM)
            it = PMUL_LAT_WARM;
        if (it >= PMUL_IT_CAP)
            break;                      /* 已顶到上限, 再放大无意义 */
    }
    *it_out = it;
    return el;
}

/* tput: PMUL_NCHAIN 条互不依赖的累加链跑满窗口, 回报 ops/s。
 * 与 lat 分开是必要的: 单依赖链量的是"一次乘多久", 多链量的才是"流水线能吃多满",
 * 查表实现(t4/t8)这两件事差得最远 —— 只报一个数就会把曲线讲成另一个故事。 */
static double pmul_tput_run(pmul_mul_fn fn, uint64_t a, uint64_t b, int *bad)
{
    const uint64_t target = (uint64_t)g_tput_ms * 1000000ULL;  /* 窗口: 毫秒 -> 纳秒 */
    uint64_t acc[PMUL_NCHAIN][3];
    volatile unsigned long long ops = 0;   /* 同上: 在保护区里累加, 必须留在内存 */
    volatile uint64_t t0, el;
    int k, i, b2 = 0;

    for (i = 0; i < PMUL_NCHAIN; i++) {
        acc[i][0] = (uint64_t)i + 1;    /* 非零起点, 免得 0^x 退化看不出链在动 */
        acc[i][1] = acc[i][2] = 0;
    }
    g_a = a;
    g_b = b;
    PMUL_TRY(b2, {
        IB_BARRIER();
        t0 = ib_now();
        for (;;) {
            for (i = 0; i < PMUL_TPUT_BLK; i++)
                for (k = 0; k < PMUL_NCHAIN; k++) {
                    uint64_t o[3];
                    fn(g_a, g_b, o);
                    acc[k][0] ^= o[0];
                    acc[k][1] ^= o[1];
                    acc[k][2] ^= o[2];
                }
            ops += (unsigned long long)PMUL_TPUT_BLK * PMUL_NCHAIN;
            if (ib_now() - t0 >= target)
                break;
        }
        el = ib_now() - t0;
    });
    if (b2) {
        *bad = 1;
        return 0;
    }
    for (k = 0; k < PMUL_NCHAIN; k++)
        g_sink ^= acc[k][0] ^ acc[k][1] ^ acc[k][2];
    return el > 0 ? (double)ops * 1e9 / (double)el : 0;
}

/* ==================== 7. 一个 (实现, 档族) = 一行 ====================
 * 先单发取语义、再计时、最后拼 kat。单发必须存在: 计时链的 acc 是 xor 自消的
 * (偶数次迭代就归零), 拿它当正确性判据是个悖论 —— 正确性与计时分开, 与 ib.h
 * 里"lat/tput 只管计时、对错由 KAT 判"的分工同一个道理。 */
static int g_ovf;                   /* got[2] 非 0 = 积超出 128 位, 数学上不可能 */

/* 单档测量。拆成一个不含循环的函数不是美观问题: setjmp/longjmp 不能横跨循环
 * 计数器 —— 计数器若是寄存器量而保护区覆盖了整圈, 崩回来的 ti 就是未定义值
 * (gcc -Wclobbered 报的正是这件事), 后患是把别的档误测成这一档。 */
static void pmul_measure_one(int impl, int ti)
{
    const struct pmul_tier *t = &g_pt[ti];
    struct pmul_meas *m = &g_m[ti];
    pmul_mul_fn fn = g_fn[impl];
    /* volatile 不是多余的修饰而是上面那段纪律的本体: 这两个量在 PMUL_TRY 保护区
     * **之后**才被赋值/读用, 跨 setjmp 存活的就是 -Wclobbered 点名的那一类。 */
    const uint64_t * volatile gold = NULL;
    const char * volatile st = NULL;
    unsigned long long it = 0;
    /* volatile 不是装饰: 这两个量现在只在 g_do_lat/g_do_tput 成立时才赋值(条件赋值),
     * 而赋值点跨在 PMUL_TRY 的 setjmp 保护区之后 —— gcc -Wclobbered 点名的正是这一类
     * (与上面 gold/st 同一条纪律: 跨 setjmp 存活的局部量必须 volatile)。 */
    volatile uint64_t ns = 0;   /* 总耗时 ns(整数; 每圈值 m->ns 才是小数) */
    volatile double ops = 0;

    memset(m, 0, sizeof *m);
    m->has = 1;
    if (g_tier_mismatch) {
        pmul_kat_str(m->kat, sizeof m->kat, t, NULL, NULL, IB_ST_TIERMIS);
        return;
    }
    if (g_impl_needs_pclmul[impl] && !g_hw_ok) {
        pmul_kat_str(m->kat, sizeof m->kat, t, NULL, NULL, IB_ST_UNSUPPORTED);
        return;
    }
    PMUL_TRY(m->bad, { fn(t->a, t->b, m->got); });
    if (m->bad) {
        pmul_kat_str(m->kat, sizeof m->kat, t, NULL, NULL, IB_ST_CRASH);
        return;
    }
    if (m->got[2])
        g_ovf++;
    /* --no-lat / --no-tput 真的跳过计时(而不是跑了再丢): help 里写了参数而代码不读
     * = 用户以为少跑了东西、实际全都跑了还全绿, 过滤静默失效比报错更坏。 */
    if (g_do_lat)
        ns = pmul_lat_fit(fn, t->a, t->b, &it, &m->bad);
    if (!m->bad && g_do_tput)
        ops = pmul_tput_run(fn, t->a, t->b, &m->bad);
    if (m->bad) {                 /* 单发对了但计时环崩了: 也是崩, 不掩盖 */
        pmul_kat_str(m->kat, sizeof m->kat, t, m->got, NULL, IB_ST_CRASH);
        return;
    }
    m->ns = it ? (double)ns / (double)it : 0;
    m->it = it;
    m->ops = ops;
    if (IB_PMUL_GOLD_N == g_pt_n && ti < IB_PMUL_GOLD_N)
        gold = g_pmul_gold[ti] + 2;   /* 表行 = {a, b, lo, hi} 四列: 前两列是输入,
                                       * 已由 pmul_check_gold() 逐档核过; 本指针的
                                       * 语义是"{lo,hi} 两 limb", 所以必须跳过前两列。
                                       * 指到行首 = 拿 a,b 当 lo,hi 判, 后果是全档
                                       * 齐刷刷 FAIL(本次就是这么撞出来的)。 */
    if (m->got[2])
        st = IB_ST_FAIL;          /* 积溢出: 不管真值表说什么都是错 */
    else if (!gold)
        st = IB_ST_NOGOLD;
    else
        st = (m->got[0] == gold[0] && m->got[1] == gold[1]) ? IB_ST_OK : IB_ST_FAIL;
    if (impl == IMPL_BASE) {
        /* base 算的不是乘积, 给它任何 st 取值都是说谎 —— 用本仓已有的
         * "不适用"记号 '-', 跟非本族档的占位同一个语义。 */
        m->kat[0] = 0;
    } else {
        pmul_kat_str(m->kat, sizeof m->kat, t, m->got, gold, st);
    }
    /* 详细明细(仅 --debug): 与 perf/func 分开发, 落 debug_pmul 表 */
    if (impl != IMPL_BASE && g_debug) {
        char gsf[40], gotf[40], line[256];
        int wa = pmul_width(t->a), wb = pmul_width(t->b);

        if (gold)
            snprintf(gsf, sizeof gsf, "%016llx:%016llx",
                     (unsigned long long)gold[0], (unsigned long long)gold[1]);
        else
            snprintf(gsf, sizeof gsf, "%s:%s", IB_V_NONE, IB_V_NONE);
        snprintf(gotf, sizeof gotf, "%016llx:%016llx",
                 (unsigned long long)m->got[0], (unsigned long long)m->got[1]);
        snprintf(line, sizeof line,
                 IB_REC_DBG ",pmul,%s,%s/%s,%s,%016llx:%016llx,%s,%s,%s,%d,%d\n",
                 g_abi, g_impl[impl], g_fam[t->fam], t->name,
                 (unsigned long long)t->a, (unsigned long long)t->b,
                 gsf, gotf, st, wa + wb, wa < wb ? wa : wb);
        ib_dbg_put(line);
    }
}

static void pmul_measure_block(int impl, int fam)
{
    int ti;

    /* 档位过滤 = ib.h 的 ib_name_ok(前缀匹配、逗号分隔多前缀): 与其余各组同一套
     * 语义, 不在本组另造一个只认单前缀的版本。档名不在表里的前缀会在 main 里
     * 按"一个都没命中"拒跑, 不会退化成"过滤没生效但输出了全量"。 */
    for (ti = 0; ti < g_pt_n; ti++)
        if (g_pt[ti].fam == fam && ib_name_ok(g_pt[ti].name))
            pmul_measure_one(impl, ti);
}

/* ==================== 6b. 输出三段: 性能 / 功能 / 详细 ====================
 * 本组一次 exec 出三段(与标准组同语义, 只是多一层"实现/档族"维度):
 *   性能段 data 行: 每 (实现,档族) 一行, 列 = 各档的 ns / ops_s(只要指标);
 *   功能段 func 行: 每 (实现,档族) 一行, 列 = 各档 true/false, 非本族/不适用 = '-';
 *   详细段 dbg 行 : 逐 (实现,档族,档) 的 in/gold/got/status/inbits/minpop, 仅 --debug。
 * 功能段与详细段都在组尾整块吐出(段的 field 行必须连续, 不能插在 data 行中间)。 */
#define PMUL_FUNC_MAX (IMPL_N * FAM_N)
#define PMUL_FUNC_ROW 1600
static char g_func_rows[PMUL_FUNC_MAX][PMUL_FUNC_ROW];
static int g_func_n;
static int g_ok_n, g_tot_n;

/* kat 串里的 status= 段 -> 功能判定(true/false/-): pmul 里只有 OK/FAIL/CRASH 是
 * 判定, NOGOLD/TIERMISMATCH/HOSTUNSUPPORTED 是"参考系不可信/不适用", 一律 '-'。 */
static const char *pmul_verdict(const char *kat)
{
    const char *p = strstr(kat, IB_K_STATUS "=");

    if (!p)
        return IB_V_NONE;
    p += strlen(IB_K_STATUS "=");
    if (!strncmp(p, IB_ST_OK, strlen(IB_ST_OK)))
        return IB_V_TRUE;
    if (!strncmp(p, IB_ST_FAIL, strlen(IB_ST_FAIL)) ||
        !strncmp(p, IB_ST_CRASH, strlen(IB_ST_CRASH)))
        return IB_V_FALSE;
    return IB_V_NONE;
}

static void pmul_print_header(void)
{
    int ti;

    /* field 行 = 数据库列名(解析侧按它建列, 不在 Python 里存名); label 行 = 中文名。
     * 两行的列序由**同一段循环**生成: 一旦中文名与字段名各写一遍, 错位比不提供更坏。
     * case 列 = 本组的用例身份 = "<实现>/<档族>"(全组统一身份列)。 */
    printf(IB_REC_FIELD ",%s,%s,%s,%s,%s,%s,%s",
           IB_F_GROUP, IB_F_ABI, IB_F_OS, IB_F_BITS, IB_F_WINDOW_SEC,
           IB_F_PMUL_VER, IB_F_CASE);
    for (ti = 0; ti < g_pt_n; ti++)
        printf(",%s%s,%s%s", g_pt[ti].name, IB_SUF_NS,
               g_pt[ti].name, IB_SUF_OPS_S);
    printf("\n");
    /* 中文名这里用"<档名> <后缀中文>"中间加一个空格: 档名是 ASCII、中文后缀不带空格
     * 时两者会粘连成 p00纳秒 这种难读形(列名行则相反 —— 列名不能带空格)。 */
    printf(IB_REC_LABEL ",%s,%s,%s,%s,%s,%s,%s",
           IB_L_GROUP, IB_L_ABI, IB_L_OS, IB_L_BITS, IB_L_WINDOW_SEC,
           IB_L_PMUL_VER, IB_L_CASE);
    for (ti = 0; ti < g_pt_n; ti++)
        printf(",%s %s,%s %s", g_pt[ti].name, IB_LS_NS,
               g_pt[ti].name, IB_LS_OPS_S);
    printf("\n");
}

static void pmul_emit_func(void)
{
    int i;

    if (!g_func_n)
        return;
    printf(IB_REC_FIELD ",%s,%s,%s", IB_F_GROUP, IB_F_ABI, IB_F_CASE);
    for (i = 0; i < g_pt_n; i++)
        printf(",%s", g_pt[i].name);
    printf("\n");
    printf(IB_REC_LABEL ",%s,%s,%s", IB_L_GROUP, IB_L_ABI, IB_L_CASE);
    for (i = 0; i < g_pt_n; i++)
        printf(",%s", g_pt[i].name);
    printf("\n");
    for (i = 0; i < g_func_n; i++)
        printf("%s\n", g_func_rows[i]);
    fflush(stdout);
}

static void pmul_print_row(int impl, int fam)
{
    int ti, used;
    char cn[64];
    char *fr;

    snprintf(cn, sizeof cn, "%s/%s", g_impl[impl], g_fam[fam]);
    printf(IB_REC_DATA ",pmul,%s,%s,%d,%.3f,%s,%s", g_abi, g_os,
           (int)(sizeof(void *) * 8), (double)g_tput_ms / 1000.0,
           IB_PMUL_GOLD_V, cn);
    for (ti = 0; ti < g_pt_n; ti++) {
        const struct pmul_meas *m = &g_m[ti];

        if (g_pt[ti].fam != fam || !m->has || m->bad) {
            /* 非本族档 / 本族档没测 / 崩了: 计时列全 IB_V_NONE。未跑的计时列打
             * IB_V_NONE 而不是 0: "没测"与"测了且为 0" 是两件事。 */
            printf(",%s,%s", IB_V_NONE, IB_V_NONE);
            continue;
        }
        {
            char nsb[32], opb[32];

            if (g_do_lat)
                snprintf(nsb, sizeof nsb, "%.3f", m->ns);
            else
                snprintf(nsb, sizeof nsb, "%s", IB_V_NONE);
            if (g_do_tput)
                snprintf(opb, sizeof opb, "%.6g", m->ops);
            else
                snprintf(opb, sizeof opb, "%s", IB_V_NONE);
            printf(",%s,%s", nsb, opb);
        }
    }
    printf("\n");
    fflush(stdout);            /* PE 崩溃时尽可能多留几行已算完的 */

    /* 功能行: 本 (实现,档族) 一行, 列 = 全部档; 非本族/不适用 = '-' */
    if (g_func_n >= PMUL_FUNC_MAX)
        return;
    fr = g_func_rows[g_func_n];
    used = snprintf(fr, PMUL_FUNC_ROW, IB_REC_FUNC ",pmul,%s,%s", g_abi, cn);
    for (ti = 0; ti < g_pt_n; ti++) {
        const struct pmul_meas *m = &g_m[ti];
        const char *v = IB_V_NONE;

        if (g_pt[ti].fam == fam && m->has && !m->bad)
            v = pmul_verdict(m->kat);
        if (strcmp(v, IB_V_NONE)) {
            g_tot_n++;
            if (!strcmp(v, IB_V_TRUE))
                g_ok_n++;
        }
        if (used < PMUL_FUNC_ROW)
            used += snprintf(fr + used, (size_t)(PMUL_FUNC_ROW - used), ",%s", v);
    }
    g_func_n++;
}

/* ==================== 8. meta 行与运行环境 ==================== */

/* meta 按空格切、CSV 按逗号切 —— 两个字符都不能出现在值里; 不可打印字符直接丢 */
static void pmul_san(char *s)
{
    char *o = s;

    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == ' ')
            c = '_';
        else if (c == ',')
            c = '.';
        else if (c < 0x21 || c > 0x7e)
            continue;
        *o++ = (char)c;
    }
    *o = 0;
}

static void pmul_cpu_brand(char *dst, size_t n)
{
    unsigned maxl, b, c, d;
    unsigned v[4];
    char raw[52];
    size_t k = 0, e;
    unsigned leaf;

    snprintf(dst, n, "unknown");
    ib_cpuid(0x80000000u, 0, &maxl, &b, &c, &d);
    if (maxl < 0x80000004u)
        return;
    raw[0] = 0;
    for (leaf = 0x80000002u; leaf <= 0x80000004u; leaf++) {
        ib_cpuid(leaf, 0, &v[0], &v[1], &v[2], &v[3]);
        memcpy(raw + k, v, 16);
        k += 16;
    }
    raw[k] = 0;
    e = k;
    while (e && (raw[e - 1] == ' ' || raw[e - 1] == 0))   /* 尾部定宽补的空 */
        e--;
    raw[e] = 0;
    snprintf(dst, n, "%s", raw);
    pmul_san(dst);
    if (!dst[0])
        snprintf(dst, n, "unknown");     /* 翻译器下拿不到品牌串也得有个值 */
}

static void pmul_host_name(char *dst, size_t n)
{
    char nb[256];

    nb[0] = 0;
#ifdef _WIN32
    {
        DWORD nn = (DWORD)sizeof nb;
        if (GetComputerNameA(nb, &nn) && nn < sizeof nb)
            nb[nn] = 0;
    }
#else
    if (gethostname(nb, sizeof nb - 1) == 0)
        nb[sizeof nb - 1] = 0;
#endif
    snprintf(dst, n, "%s", nb[0] ? nb : "unknown");
    pmul_san(dst);
    if (!dst[0])
        snprintf(dst, n, "unknown");
}

static void pmul_join_sel(const int *sel, const char **names, int n,
                          char *dst, size_t dn)
{
    int i;
    size_t used = 0;

    dst[0] = 0;
    for (i = 0; i < n; i++)
        if (sel[i]) {
            int w = snprintf(dst + used, dn - used, "%s%s", used ? "," : "", names[i]);
            if (w < 0 || (size_t)w >= dn - used)
                break;
            used += (size_t)w;
        }
}

/* 外部串入列前的安全化: CPU 型号(/proc/cpuinfo)与主机名(gethostname)里若出现
 * 双引号, 会被 CSV 解析器当成转义起始而毁掉整行 —— 换成单引号。逗号不需要动:
 * 这两个单元是带引号输出的(见 pmul_meta_line)。 */
static void pmul_strip_quote(char *s)
{
    for (; *s; s++)
        if (*s == '"')
            *s = '\'';
}

static void pmul_meta_line(void)
{
    char cpu[64], host[80], is[64], fs[64];

    pmul_cpu_brand(cpu, sizeof cpu);
    pmul_host_name(host, sizeof host);
    pmul_join_sel(g_sel_i, g_impl, IMPL_N, is, sizeof is);
    pmul_join_sel(g_sel_f, g_fam, FAM_N, fs, sizeof fs);
    pmul_strip_quote(cpu);
    pmul_strip_quote(host);
    /* meta 行不再是"# 开头的注释风格": 第一列就是记录类型, 整个文件只有一套
     * 语法。串仍是 k=v 逗号分隔 —— 这些名字(abi/os/bits/window_sec/cpu/host)正是
     * isbench.py 允许自己规划的那批(主键/引用键/测试标识), 不是度量列名。
     * ⚠ 值里可能带逗号的单元(cpu/host/impls/families)必须整单元加双引号: 一个
     * 逗号就能把一列撑成几列(impls=base,ref,hw,t4,t8 实测就这么被切成了五段,
     * 下游拿到的是 impls=base 加四个无键碎片 —— 静默失真)。 */
    printf(IB_REC_META ",%s=%s,%s=%s,%s=%s,%s=%d,%s=%.3f,\"%s=%s\",\"%s=%s\","
           "\"%s=%s\",\"%s=%s\"\n",
           IB_F_PMUL_VER, IB_PMUL_GOLD_V, IB_F_ABI, g_abi, IB_F_OS, g_os,
           IB_F_BITS, (int)(sizeof(void *) * 8),
           IB_F_WINDOW_SEC, (double)g_tput_ms / 1000.0,
           IB_F_CPU, cpu, IB_F_HOST, host, IB_F_IMPLS, is, IB_F_FAMILIES, fs);
}

/* ==================== 9. 参数与入口 ==================== */

static int g_help;

/* 逗号分隔选择器: 未给(NULL) = 全选; 认不出的词必须当场报到 stderr ——
 * "看起来绿了的空表"是这类工具最坏的一种失败。返回命中数。
 * 不用 strtok/strtok_r: 前者带全局态、后者在 -std=c11 + mingw 下根本没声明。 */
static int pmul_pick(const char *csv, const char **names, int n, int *sel,
                     const char *what, const char *valid)
{
    int i, hit = 0;

    if (!csv) {
        for (i = 0; i < n; i++)
            sel[i] = 1;
        return n;
    }
    if (!*csv) {
        fprintf(stderr, "pmul: %s 选择器给了空值 -> 什么都不选(main 会拒跑)\n", what);
        return 0;
    }
    while (*csv) {
        const char *e = csv;
        size_t len;
        int one = 0;

        while (*e && *e != ',')
            e++;
        len = (size_t)(e - csv);
        for (i = 0; i < n; i++)
            if (len == strlen(names[i]) && !memcmp(csv, names[i], len)) {
                sel[i] = 1;
                one = hit = 1;
            }
        if (!one && len)
            fprintf(stderr, "pmul: %s 名 %.*s 不存在(可选: %s) -> 本项被忽略\n",
                    what, (int)len, csv, valid);
        csv = (*e == ',') ? e + 1 : e;
    }
    return hit;
}

static int pmul_any(const int *sel, int n)
{
    int i, c = 0;

    for (i = 0; i < n; i++)
        c += sel[i] != 0;
    return c;
}

/* ib.h 自己吃的参数(前缀匹配同时受理 --x=y): 认不得的参数必须告警,
 * 但不能退出 —— 拼错一个字母就静默跑出一个与预期完全不同的集, 比告警难受得多。 */
static int pmul_extern_flag(const char *s)
{
    static const char *k[] = { "--time", "--iters", "--only",
                               "--no-lat", "--no-tput", "--no-b8", "--no-sem",
                               "--debug", "--help", NULL };
    int i;

    for (i = 0; k[i]; i++) {
        size_t l = strlen(k[i]);
        if (!strncmp(s, k[i], l) && (s[l] == 0 || s[l] == '='))
            return 1;
    }
    return 0;
}

static void pmul_usage(const char *av)
{
    fprintf(stderr, "usage: %s [--collect] [--list] [--time MS] [--debug]\n", av);
    fprintf(stderr, "          [--impl base,ref,hw,t4,t8] [--family bit,wone,whi,dual,rnd]\n");
    fprintf(stderr, "          [--gen-gold [--gold-ver STR]]\n");
    fprintf(stderr, "通用参数(ib.h 口径): --time MS / --only=<档名前缀[,..]> /\n");
    fprintf(stderr, "  --no-lat / --no-tput / --help|-h(全部走 stderr)。\n");
    fprintf(stderr, "本组不适用的参数: --iters(lat 用自适应拟合, 实跑次数在 <档>_iters 列) /\n");
    fprintf(stderr, "  --no-b8|--no-sem(本组没有这两种测试方式)。\n");
    fprintf(stderr, "--gen-gold: 本组自己的真值表自己生成 —— 在真 x86_64 机器上用硬件\n");
    fprintf(stderr, "            pclmulqdq 直算 96 档, 逐档打成完整 isb_pmul_gold.h 打到\n");
    fprintf(stderr, "            stdout(不写文件, 回填由 pack/gen_gold_pmul.sh 做完形状自检与\n");
    fprintf(stderr, "            备份后进行)。这份采集值就是判定标准: 实测 != 表 -> FAIL。\n");
    fprintf(stderr, "输出: 每行第一列 = 记录类型(meta|field|label|data|func|dbg|group), 按 field 行分段:\n");
    fprintf(stderr, "      meta  = 本场标识与环境(k=v 分隔)\n");
    fprintf(stderr, "      field = 英文列名(= 数据库列名, 解析侧现读现建, 不在 Python 存名)\n");
    fprintf(stderr, "      label = 中文列名(与 field 严格同列序)\n");
    fprintf(stderr, "      data  = 性能行, 每 (实现,档族) 一行, 每档 2 列: <档>_ns <档>_ops_s\n");
    fprintf(stderr, "      func  = 功能行, 每 (实现,档族) 一行, 列 = 各档, 值 true/false\n");
    fprintf(stderr, "      dbg   = 详细行(仅 --debug): in/gold/got/status/inbits/minpop\n");
    fprintf(stderr, "      group = 组尾(ok/total)\n");
    fprintf(stderr, "--collect: 缺真值时不告警(采集通道用), 不是\"禁止判定\" ——\n");
    fprintf(stderr, "           有可信真值时照判, 多一个信息不会有害。\n");
}

static void pmul_pick_args(int argc, char **argv)
{
    int i;

    for (i = 1; i < argc; i++) {
        const char *s = argv[i];

        if (!strcmp(s, "--collect")) {
            g_collect = 1;
        } else if (!strcmp(s, "--list")) {
            g_list = 1;
        } else if (!strcmp(s, "--help") || !strcmp(s, "-h")) {
            g_help = 1;
        } else if (!strcmp(s, "--gen-gold")) {
            g_gen_gold = 1;
        } else if (!strncmp(s, "--gold-ver=", 11)) {
            g_gold_ver = s + 11;
        } else if (!strcmp(s, "--gold-ver") && i + 1 < argc) {
            g_gold_ver = argv[++i];
        } else if (!strncmp(s, "--impl=", 7)) {
            g_i_given = 1;
            pmul_pick(s + 7, g_impl, IMPL_N, g_sel_i, "实现", "base,ref,hw,t4,t8");
        } else if (!strcmp(s, "--impl") && i + 1 < argc) {
            g_i_given = 1;
            pmul_pick(argv[++i], g_impl, IMPL_N, g_sel_i, "实现", "base,ref,hw,t4,t8");
        } else if (!strncmp(s, "--family=", 9)) {
            g_f_given = 1;
            pmul_pick(s + 9, g_fam, FAM_N, g_sel_f, "档族", "bit,wone,whi,dual,rnd");
        } else if (!strcmp(s, "--family") && i + 1 < argc) {
            g_f_given = 1;
            pmul_pick(argv[++i], g_fam, FAM_N, g_sel_f, "档族", "bit,wone,whi,dual,rnd");
        } else if (s[0] == '-' && s[1] == '-' && !pmul_extern_flag(s)) {
            fprintf(stderr, "pmul: 未识别的参数 %s (已忽略)\n", s);
        }
    }
}

static void pmul_list_tiers(void)
{
    int i;

    printf("idx,family,name,a,b,bits,minpop\n");
    for (i = 0; i < g_pt_n; i++) {
        int wa = pmul_width(g_pt[i].a), wb = pmul_width(g_pt[i].b);
        printf("%d,%s,%s,%016llx,%016llx,%d,%d\n", i, g_fam[g_pt[i].fam],
               g_pt[i].name,
               (unsigned long long)g_pt[i].a, (unsigned long long)g_pt[i].b,
               wa + wb, wa < wb ? wa : wb);
    }
}

/* ==================== 8b. 自生成常量表(真机采集值 = 判定标准) ====================
 * 真值就是**真机(Windows PE / 构建机 / 参考机)上硬件 pclmulqdq 采进
 * 来的那一套输入输出常量**, 测试时实测与它不同就是错(st=FAIL)。不再拿第二套实现
 * 去证明第一套没算错 —— 原先这里的"硬件 vs ref 逐位模型复算"与"交换序同积 /
 * 自乘==位扩散恒等式"两条互检已全部删除: 它们与 Python 侧那份第三方对拍是同一
 * 件事的三份副本, 副本越多越没人说得清哪个才是标准。
 * 只留两条与"对拍"无关的出表前置有效性检查:
 *   1) 采集机必须是真 x86_64(见 pmul_gold_host_ok), 否则锁进表的是翻译器输出;
 *   2) 积不得超出 128 位 —— 64x64->128 上数学不可能, h[2] 非 0 即本机指令行为
 *      异常, 这份值不能当真值。
 * 为什么生成器在探针里而不是外面另写一个: 档位表只能有一份。外面再写一份公式的
 * 生成器, 早晚与 pmul_build_tiers() 漂移(改了那边忘了这边 = 真值错档)。
 * 输出是完整的 .h 文本(含注释/guard/N), 由 pack/gen_gold_pmul.sh 做形状自检后备份回填。
 * 不带日期等易变量: 同一台真机上重跑必得逐字节相同的文件。 */

/* 真机守卫: 真值表只能由真 x86 硬件采集。
 * LATX 下(翻译机)跑的是同一份 x86_64 ELF、编译期宏完全一致, 只有内核机器名会
 * 露出 loongarch64 —— 那时 pclmulqdq 的执行结果是翻译器的产物, 把它回填成"真值"
 * 等于让被测者自己出题(本仓已有多条 LATX 语义缺陷的实测记录)。
 * 判不出来就不出表, 而不是出一份来历不明的表。 */
static int pmul_gold_host_ok(void)
{
#ifdef _WIN32
    return 1;   /* PE 侧只在真 x86 Windows 上跑; 本仓 gen-gold 只走 构建机 通路 */
#else
    struct utsname u;

    if (uname(&u) != 0)
        return 0;
    return strcmp(u.machine, "x86_64") == 0;
#endif
}

static void pmul_gen_gold(void)
{
    int i, nbad = 0;
    uint64_t lo[PT_MAX], hi[PT_MAX];

    if (!pmul_gold_host_ok()) {
        fprintf(stderr, "pmul: 本机机器名不是 x86_64(疑似跑在 LATX 等翻译层上)"
                        " -> 翻译层上的执行结果不能当真值, 不出表\n");
        g_gen_gold_fail = 1;
        return;
    }
    if (!ib_cpu_ok("pclmul")) {
        fprintf(stderr, "pmul: 本机 CPUID 无 pclmul -> 不能用硬件直算真值, 不出表\n");
        g_gen_gold_fail = 1;
        return;
    }
    for (i = 0; i < g_pt_n; i++) {
        uint64_t h[3];

        memset(h, 0, sizeof h);
        mul_hw(g_pt[i].a, g_pt[i].b, h);
        if (h[2]) {
            fprintf(stderr, "pmul: 第 %d 档 %s 的积超出 128 位(hw=%016llx:%016llx+"
                            "%016llx) -> 本机指令行为异常, 这份值不能当真值\n",
                    i, g_pt[i].name,
                    (unsigned long long)h[0], (unsigned long long)h[1],
                    (unsigned long long)h[2]);
            nbad++;
            continue;
        }
        lo[i] = h[0];
        hi[i] = h[1];
    }
    if (nbad) {
        fprintf(stderr, "pmul: %d 档未通过自检 -> 一个字节都不写\n", nbad);
        g_gen_gold_fail = 1;
        return;
    }
    printf("/* isb_pmul_gold.h —— pmul 组 %d 档「64x64 -> 128 无进位乘」输入输出真值表"
           "(生成物, 请勿手改)\n *\n", PT_MAX);
    printf(" * 由本组探针自己生成: pack/gen_gold_pmul.sh 调 %s --gen-gold,\n", "isb_pmul");
    printf(" * 在真 x86_64 机器上用硬件 pclmulqdq 直算 96 档(ctrl=0x00、低 64 位放操作数)。\n");
    printf(" * **这份采集值就是判定标准**: 测试时实测 != 本表即 st=FAIL,\n");
    printf(" * 不再拿第二套实现互证 —— 出表前只验两条: 采集机机器名是 x86_64(排除 LATX\n");
    printf(" * 翻译层)、且积未溢出 128 位。不带日期: 同一台真机重跑必得逐字节相同。\n");
    printf(" * 字段序 = {a, b, lo, hi}, 16 位定宽裸 16 进制(与探针 %%016llx 同形), 每档一行、\n");
    printf(" * 按 pmul_build_tiers() 的档位序(bit/wone/whi/dual/rnd)排列。\n");
    printf(" *\n");
    printf(" * 改档位必须重跑 --gen-gold: 探针启动即逐档核 (a,b), 错档判 TIERMISMATCH,\n");
    printf(" * 不会退化成\"A 档的真值判 B 档结果\"那种静默假绿。\n");
    printf(" *\n");
    printf(" * 行尾: 本仓统一 LF, pack/gen_gold_pmul.sh 回填前验 CR 字节数为 0。\n");
    printf(" */\n#ifndef ISB_PMUL_GOLD_H\n#define ISB_PMUL_GOLD_H\n\n");
    printf("/* 自带 stdint 而不依赖包含者(ib.h)已先带进来: 本文件要能被单独编译做形状自检\n");
    printf(" * (而不必链整个探针), 依赖包含顺序会让那个自检假失败。 */\n#include <stdint.h>\n\n");
    printf("/* 版本串: 真值来源标识, 随探针 meta 行的 pmul_ver 入库 —— 任何一条度量都能\n");
    printf(" * 反查它是按哪一版真值判的。 */\n");
    printf("#define IB_PMUL_GOLD_V \"%s\"\n\n", g_gold_ver);
    printf("#define IB_PMUL_GOLD_N %d\n\n", g_pt_n);
    printf("/* 表体 = #define 花括号初始化列表(同 isb_*_kat.h 的既有形态): 两 ABI 共用\n");
    printf(" * 一份, 且生成侧只需替换这一段文本, 不必理解 C 语法。 */\n");
    printf("#define IB_PMUL_GOLD { \\\n");
    for (i = 0; i < g_pt_n; i++)
        printf("    { 0x%016llxULL, 0x%016llxULL, 0x%016llxULL, 0x%016llxULL }%s\n",
               (unsigned long long)g_pt[i].a, (unsigned long long)g_pt[i].b,
               (unsigned long long)lo[i], (unsigned long long)hi[i],
               i == g_pt_n - 1 ? " \\" : ", \\");
    printf("}\n\n");
    printf("/* 行数 = 表体行数: 生成物里 N 恒等于档数(占位表才需要 N?N:1 兜底)。 */\n");
    printf("#define IB_PMUL_GOLD_ROWS IB_PMUL_GOLD_N\n\n");
    printf("static const uint64_t g_pmul_gold[IB_PMUL_GOLD_ROWS][4] = IB_PMUL_GOLD;\n\n");
    printf("#endif /* ISB_PMUL_GOLD_H */\n");
    fprintf(stderr, "pmul: %d 档已由本机硬件 pclmulqdq 采集完成, 真值表已出(版本 %s)\n",
            g_pt_n, g_gold_ver);
}

int main(int argc, char **argv)
{
    int impl, fam, n_i, n_f;

    memset(g_sel_i, 0, sizeof g_sel_i);
    memset(g_sel_f, 0, sizeof g_sel_f);
    pmul_pick_args(argc, argv);
    if (g_help) {
        pmul_usage(argv[0]);
        return 0;
    }
    /* 先改默认窗口再进 ib_init: 这样未给 --time 时用本组的 50 ms,
     * 给了则 ib_init 覆盖之 —— 一个参数两个默认值谁赢是歧义, 用顺序消除。 */
    g_tput_ms = PMUL_TMS_DEF;
    ib_init(argc, argv);
    if (g_tput_ms <= 0)
        g_tput_ms = PMUL_TMS_DEF;
    if (!g_gold_ver) {
        snprintf(g_gold_ver_buf, sizeof g_gold_ver_buf, "selfgen-hw-%s", g_abi);
        g_gold_ver = g_gold_ver_buf;
    }

    pmul_build_tiers();
    if (g_list) {
        pmul_list_tiers();
        return 0;
    }
    if (g_gen_gold) {
        pmul_gen_gold();
        fflush(stdout);
        return g_gen_gold_fail ? 3 : 0;
    }
    pmul_check_gold();
    pmul_build_tables();
    g_hw_ok = ib_cpu_ok("pclmul");

    /* 未给选择器才填全选; 给了但一个都没命中 = 配置错了, 必须拒跑 ——
     * 不能被全选的默认态顺手救活(那正好把一个拼错的参数变成一次意外的全量) */
    if (!g_i_given)
        pmul_pick(NULL, g_impl, IMPL_N, g_sel_i, "实现", "");
    if (!g_f_given)
        pmul_pick(NULL, g_fam, FAM_N, g_sel_f, "档族", "");
    n_i = pmul_any(g_sel_i, IMPL_N);
    n_f = pmul_any(g_sel_f, FAM_N);
    if (!n_i || !n_f) {
        fprintf(stderr, "pmul: 选择器没有任何命中 -> 拒跑空集(输出一份假绿的空表比不跑更坏)\n");
        return 2;
    }
    /* --only 一个档名都不命中时必须拒跑: 否则它看起来就是"没生效", 而输出仍是一
     * 份完好的 96 档全量表 —— 没人会怀疑自己拿到的不是想要的那四条。 */
    if (g_only) {
        int ti, hit = 0;

        for (ti = 0; ti < g_pt_n; ti++)
            if (ib_name_ok(g_pt[ti].name))
                hit++;
        if (!hit) {
            fprintf(stderr, "pmul: --only=%s 没有任何档位命中 -> 拒跑空集\n", g_only);
            return 2;
        }
        fprintf(stderr, "pmul: --only=%s 命中 %d/%d 档\n", g_only, hit, g_pt_n);
    }
    if (!g_sel_i[IMPL_REF] &&
        (g_sel_i[IMPL_HW] || g_sel_i[IMPL_T4] || g_sel_i[IMPL_T8]))
        fprintf(stderr, "pmul: 本次未选 ref -> 少一条软件参考实现的性能对照行"
                        "(不影响判对错: 标准是真值表)\n");

    pmul_meta_line();
    /* 表头固定为全 96 档 x 4 列、与过滤无关: 列序稳定才能直接把两次 run 的
     * CSV 对列比, 比少几列值钱得多 */
    pmul_print_header();
    for (impl = 0; impl < IMPL_N; impl++) {
        if (!g_sel_i[impl])
            continue;
        for (fam = 0; fam < FAM_N; fam++) {
            if (!g_sel_f[fam])
                continue;
            pmul_measure_block(impl, fam);
            pmul_print_row(impl, fam);
        }
    }

    if (IB_PMUL_GOLD_N == 0 && !g_collect)
        fprintf(stderr, "pmul: 真值表未回填(IB_PMUL_GOLD_N=0) -> 全档 st=NOGOLD,"
                        " 本次只可采集不可判对错\n");
    if (g_ovf)
        fprintf(stderr, "pmul: %d 档的结果超出 128 位(got[2] 非 0) -> 内核有 bug\n", g_ovf);
    /* 组尾行 + 功能段 + 详细段(仅 --debug): 与标准组同序 —— 三段各自成块, 组尾行之后
     * 只剩功能区段, 不再有 data 行, 所以段的 field 行不会切错列。 */
    printf("%s,pmul,%d,%d\n", IB_REC_GROUP, g_ok_n, g_tot_n);
    pmul_emit_func();
    ib_dbg_emit(IB_PMUL_DBG_FIELD, IB_PMUL_DBG_LABEL);
    fflush(stdout);
    return g_tier_mismatch ? 3 : 0;
}
