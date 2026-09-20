/* isb_shift.c —— 移位/循环移家族形态组(grp=shift): shl shr sar rol ror shld shrd + BMI2
 *
 * 用例来源 = 实测 三层映射 round5_form_weights.csv 的实测 k90 形态, 共 21 条,
 * 与计划表同数(shl 3 + shr 4 + sar 2 + rol 3 + ror 2 + shld 2 + shrd 1 + BMI2 4),
 * 两处差异以实测为准:
 *   - shld 计划写 1 条, 实测 k90 里 `shld r.i.l`(0.0034%) 与 `shld r.i.q`(0.0014%)
 *     两条都在 90% 线内 -> 按实测收 2 条(所以 rol 那 3 条与 sar 的 2 条不变)。
 *   - ror 与 BMI2 四条(shlx/sarx/shrx/rorx)在 CSV 里 nf=0(采样窗内没抓到; BMI2 是
 *     静态清单里的贵形态, 计划按「锚点不可丢」保留) -> 名字按同一机械变换从
 *     `ror r.i.q` / `shlx r.r.q` 合成, 权重列一律标 nf=0。
 *
 * 为什么独立成组: 移位类的 LATX 成本结构是「一条 x86 移位 = 目标端 1~2 条(带
 * 移位量取模与标志补齐)」, 与 add/logic 的 1:1 翻译不是一个量级; 而且移位量来源
 * (立即数 / %cl / 隐式 1 / 第三操作数)在 ISA 上是四种不同编码, 必须分开登记才能
 * 看出哪一种来源译错。BMI2 四条还额外承担「目标机是否支持 VEX/BMI2」的探测: 不
 * 支持则 SIGILL, 由 ib_case_* 的 sigsetjmp 兜住并记进 sig 列, 不拖整组。
 *
 * 内核分工(骨架条数不同 => 绝对值不横比, 见 ib_gen.h 头注纪律 1):
 *   r.i.l/q/w 由 GCC 自由分配 -> IB_K_SHI;  r.r(=%cl) -> IB_K_SHC
 *   r.i.b/w(8/16 位) 钉显式累加器保 legacy 编码 -> IB_K_SHI8
 *   r..l(隐式 1, 无操作数) -> IB_K_SH1;  shld/shrd -> IB_K_SHD;  BMI2 -> IB_K_SHX
 *   (细节见 ib_gen.h 第 12/13 与第 25 节头注)
 *
 * 64 位形态只存在于 x86_64: 内核实例与表项一起 #ifdef(i386 侧 21->8 条)。
 *
 * 链尾的 ROLL 两条(adc $0,%[v] + add %[v],%[a], 见 ib_gen.h 12/13 与 25 节注):
 * 移位会把位洗出界 -> 光有被测一条时链十几轮就进不动点(旧版实测 7 条 case
 * lat_sig 全等于 1、sarx/shrx/rorx 三条同签名), 错译移位量/符号扩展看不出来;
 * ROLL 把每轮移入 CF 的那一位收进累加器 v 再灌回链主 -> 位流历史全进签名。
 * v 的初值必须是 IB_TOPBIT(TY)(最高位置 1 再 |1): 种子最高位为 0 时链主恒正,
 * sar 的符号扩展分支从头到尾不走, 实测 sar_r_i_q 与 shr_r_i_q 逐位相同。
 * 代价: 每轮多 2 条 1 周期骨架(全组同模板恒量, 不破坏组内横比)。
 *
 * 签名列可检出性自检(签名重复自检实测): 21 条里只剩 2 对同签名 —— shl 与 shr 各自的
 * `$3` 与 `%%cl=3` 两条。那是同一条运算的两种编码(AT&T 的 F7 /6 ib 与 D3 /6),
 * 值流必然逐位相同, 不属漏检; 其余 17 条(含 sar/sarx/shrx/shlx/rorx/rol/ror/
 * shld/shrd/8-16 位四对)lat 与 tput 签名全离散。
 *
 * KAT(与 flag/alu/logic 组同一机制): 每个计时内核下面紧跟一行 IB_KT_SHA/SHD
 * 探针 —— 同一条指令、同一操作数拼法、同一计数来源, 但只执行 1 次、不进循环。
 * 表里的 i1 就是**真实计数值**(不是随机数), 所以审计端能按 i0/i1/inf 复算。
 * 三处口径(全部来自 SDM 的标志章节, 目的是只上架构承诺有定义的位,
 * 否则 LATX 上的差异分不清是错译还是本来就可以不同):
 *   - 计数一律落在 1 <= 计数 < 宽度: 计数=0 时六个标志全不受影响、计数>=宽度
 *     时 CF 机型相关 -> 这两种情形的真值都不上表, 所以探针先把计数钳进区间;
 *   - 计数>1 -> OF 未定义, 所以移位用 IB_FLG_MASK_SHIFT(无 OF/AF)、循环移用
 *     IB_FLG_MASK_ROT(SF/ZF/AF/PF 不受影响 + CF 有定义, 只剔 OF); 计数=1 的
 *     sar r,1 才有 IB_FLG_MASK_SH1(含 OF);
 *   - BMI2 四条不写标志 -> 拿全掩码 IB_FLG_MASK, outf 应恒等于 inf(比只比
 *     结果更严: 翻译器把 shlx 译成会踩标志的实现就报 KATFAIL)。
 * 未定义位一律靠掩码排除而不是「采一次当真理」: alu 组实测 mul/div 若上了未定义
 * 标志, 跨机比对就会出假不匹配 -> 本组预先按 SDM 分好类避开。
 */
#include "ib_core.h"
#include "ib_buf.h"
#include "isb_shift_kat.h"    /* KAT 真值表(采集后生成; 未取数时全 UNSET) */

/* ---------------- 64 位形态(仅 x86_64) ---------------- */
#ifdef __x86_64__
/* ---- shl_r_i_q: IB_K_SHI ---- */
static uint64_t k_shl_r_i_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), v = IB_TOPBIT(IB_UQ);                                     
    for (i = 0; i < it; i++)                                                      
        __asm__("shlq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : : "cc");                             
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_shl_r_i_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    IB_UQ v = IB_TOPBIT(IB_UQ), w = IB_TOPBIT(IB_UQ), x = IB_TOPBIT(IB_UQ), y = IB_TOPBIT(IB_UQ); 
    for (i = 0; i < it; i++) {                                                    
        __asm__("shlq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : : "cc");                             
        __asm__("shlq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(c), [v] "+r"(w) : : "cc");                             
        __asm__("shlq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(e), [v] "+r"(x) : : "cc");                             
        __asm__("shlq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(g), [v] "+r"(y) : : "cc");                             
    }                                                                             
    return IB_S4(a, c, e, g) + IB_S4(v, w, x, y);                                 
}

/* ---- shl_r_i_q: IB_KT_SHA ---- */
static inline void k_shl_r_i_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("shl_r_i_q", kk, 0, IB_UQ);                                            
    IB_UQ ain = a, n = (IB_UQ)(3);                                                   
    void *p = ib_kbuf_fill((uint64_t)n);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("shl_r_i_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "shlq" " " "$3,%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [c] "c"(n), [p] "r"(p), [fv] "r"(fv)                          
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)n;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)n;                                     
    g->outf = (uint64_t)fl & (IB_FLG_MASK_SHIFT);                                                
}

/* ---- shl_r_r_q: IB_K_SHC ---- */
static uint64_t k_shl_r_r_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), v = IB_TOPBIT(IB_UQ);                                     
    uint8_t n = 3;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("shlq" " %%cl,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                 
                : [a] "+r"(a), [v] "+r"(v) : "c"(n) : "cc");                      
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_shl_r_r_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    IB_UQ v = IB_TOPBIT(IB_UQ), w = IB_TOPBIT(IB_UQ), x = IB_TOPBIT(IB_UQ), y = IB_TOPBIT(IB_UQ); 
    uint8_t n = 3;                                                                
    for (i = 0; i < it; i++) {                                                    
        __asm__("shlq" " %%cl,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                 
                : [a] "+r"(a), [v] "+r"(v) : "c"(n) : "cc");                      
        __asm__("shlq" " %%cl,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                 
                : [a] "+r"(c), [v] "+r"(w) : "c"(n) : "cc");                      
        __asm__("shlq" " %%cl,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                 
                : [a] "+r"(e), [v] "+r"(x) : "c"(n) : "cc");                      
        __asm__("shlq" " %%cl,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                 
                : [a] "+r"(g), [v] "+r"(y) : "c"(n) : "cc");                      
    }                                                                             
    return IB_S4(a, c, e, g) + IB_S4(v, w, x, y);                                 
}

/* ---- shl_r_r_q: IB_KT_SHA ---- */
static inline void k_shl_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("shl_r_r_q", kk, 0, IB_UQ);                                            
    IB_UQ ain = a, n = (IB_UQ)(3);                                                   
    void *p = ib_kbuf_fill((uint64_t)n);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("shl_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "shlq" " " "%%cl,%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [c] "c"(n), [p] "r"(p), [fv] "r"(fv)                          
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)n;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)n;                                     
    g->outf = (uint64_t)fl & (IB_FLG_MASK_SHIFT);                                                
}

/* ---- shr_r_r_q: IB_K_SHC ---- */
static uint64_t k_shr_r_r_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), v = IB_TOPBIT(IB_UQ);                                     
    uint8_t n = 3;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("shrq" " %%cl,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                 
                : [a] "+r"(a), [v] "+r"(v) : "c"(n) : "cc");                      
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_shr_r_r_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    IB_UQ v = IB_TOPBIT(IB_UQ), w = IB_TOPBIT(IB_UQ), x = IB_TOPBIT(IB_UQ), y = IB_TOPBIT(IB_UQ); 
    uint8_t n = 3;                                                                
    for (i = 0; i < it; i++) {                                                    
        __asm__("shrq" " %%cl,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                 
                : [a] "+r"(a), [v] "+r"(v) : "c"(n) : "cc");                      
        __asm__("shrq" " %%cl,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                 
                : [a] "+r"(c), [v] "+r"(w) : "c"(n) : "cc");                      
        __asm__("shrq" " %%cl,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                 
                : [a] "+r"(e), [v] "+r"(x) : "c"(n) : "cc");                      
        __asm__("shrq" " %%cl,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                 
                : [a] "+r"(g), [v] "+r"(y) : "c"(n) : "cc");                      
    }                                                                             
    return IB_S4(a, c, e, g) + IB_S4(v, w, x, y);                                 
}

/* ---- shr_r_r_q: IB_KT_SHA ---- */
static inline void k_shr_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("shr_r_r_q", kk, 0, IB_UQ);                                            
    IB_UQ ain = a, n = (IB_UQ)(3);                                                   
    void *p = ib_kbuf_fill((uint64_t)n);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("shr_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "shrq" " " "%%cl,%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [c] "c"(n), [p] "r"(p), [fv] "r"(fv)                          
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)n;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)n;                                     
    g->outf = (uint64_t)fl & (IB_FLG_MASK_SHIFT);                                                
}

/* ---- shr_r_i_q: IB_K_SHI ---- */
static uint64_t k_shr_r_i_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), v = IB_TOPBIT(IB_UQ);                                     
    for (i = 0; i < it; i++)                                                      
        __asm__("shrq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : : "cc");                             
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_shr_r_i_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    IB_UQ v = IB_TOPBIT(IB_UQ), w = IB_TOPBIT(IB_UQ), x = IB_TOPBIT(IB_UQ), y = IB_TOPBIT(IB_UQ); 
    for (i = 0; i < it; i++) {                                                    
        __asm__("shrq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : : "cc");                             
        __asm__("shrq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(c), [v] "+r"(w) : : "cc");                             
        __asm__("shrq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(e), [v] "+r"(x) : : "cc");                             
        __asm__("shrq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(g), [v] "+r"(y) : : "cc");                             
    }                                                                             
    return IB_S4(a, c, e, g) + IB_S4(v, w, x, y);                                 
}

/* ---- shr_r_i_q: IB_KT_SHA ---- */
static inline void k_shr_r_i_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("shr_r_i_q", kk, 0, IB_UQ);                                            
    IB_UQ ain = a, n = (IB_UQ)(3);                                                   
    void *p = ib_kbuf_fill((uint64_t)n);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("shr_r_i_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "shrq" " " "$3,%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [c] "c"(n), [p] "r"(p), [fv] "r"(fv)                          
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)n;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)n;                                     
    g->outf = (uint64_t)fl & (IB_FLG_MASK_SHIFT);                                                
}

/* ---- sar_r_i_q: IB_K_SHI ---- */
static uint64_t k_sar_r_i_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), v = IB_TOPBIT(IB_UQ);                                     
    for (i = 0; i < it; i++)                                                      
        __asm__("sarq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : : "cc");                             
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_sar_r_i_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    IB_UQ v = IB_TOPBIT(IB_UQ), w = IB_TOPBIT(IB_UQ), x = IB_TOPBIT(IB_UQ), y = IB_TOPBIT(IB_UQ); 
    for (i = 0; i < it; i++) {                                                    
        __asm__("sarq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : : "cc");                             
        __asm__("sarq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(c), [v] "+r"(w) : : "cc");                             
        __asm__("sarq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(e), [v] "+r"(x) : : "cc");                             
        __asm__("sarq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(g), [v] "+r"(y) : : "cc");                             
    }                                                                             
    return IB_S4(a, c, e, g) + IB_S4(v, w, x, y);                                 
}

/* ---- sar_r_i_q: IB_KT_SHA ---- */
static inline void k_sar_r_i_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("sar_r_i_q", kk, 0, IB_UQ);                                            
    IB_UQ ain = a, n = (IB_UQ)(3);                                                   
    void *p = ib_kbuf_fill((uint64_t)n);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("sar_r_i_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "sarq" " " "$3,%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [c] "c"(n), [p] "r"(p), [fv] "r"(fv)                          
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)n;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)n;                                     
    g->outf = (uint64_t)fl & (IB_FLG_MASK_SHIFT);                                                
}

/* ---- rol_r_i_q: IB_K_SHI ---- */
static uint64_t k_rol_r_i_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), v = IB_TOPBIT(IB_UQ);                                     
    for (i = 0; i < it; i++)                                                      
        __asm__("rolq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : : "cc");                             
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_rol_r_i_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    IB_UQ v = IB_TOPBIT(IB_UQ), w = IB_TOPBIT(IB_UQ), x = IB_TOPBIT(IB_UQ), y = IB_TOPBIT(IB_UQ); 
    for (i = 0; i < it; i++) {                                                    
        __asm__("rolq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : : "cc");                             
        __asm__("rolq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(c), [v] "+r"(w) : : "cc");                             
        __asm__("rolq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(e), [v] "+r"(x) : : "cc");                             
        __asm__("rolq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(g), [v] "+r"(y) : : "cc");                             
    }                                                                             
    return IB_S4(a, c, e, g) + IB_S4(v, w, x, y);                                 
}

/* ---- rol_r_i_q: IB_KT_SHA ---- */
static inline void k_rol_r_i_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("rol_r_i_q", kk, 0, IB_UQ);                                            
    IB_UQ ain = a, n = (IB_UQ)(3);                                                   
    void *p = ib_kbuf_fill((uint64_t)n);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("rol_r_i_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "rolq" " " "$3,%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [c] "c"(n), [p] "r"(p), [fv] "r"(fv)                          
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)n;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)n;                                     
    g->outf = (uint64_t)fl & (IB_FLG_MASK_ROT);                                                
}

/* ---- ror_r_i_q: IB_K_SHI ---- */
static uint64_t k_ror_r_i_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), v = IB_TOPBIT(IB_UQ);                                     
    for (i = 0; i < it; i++)                                                      
        __asm__("rorq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : : "cc");                             
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_ror_r_i_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    IB_UQ v = IB_TOPBIT(IB_UQ), w = IB_TOPBIT(IB_UQ), x = IB_TOPBIT(IB_UQ), y = IB_TOPBIT(IB_UQ); 
    for (i = 0; i < it; i++) {                                                    
        __asm__("rorq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : : "cc");                             
        __asm__("rorq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(c), [v] "+r"(w) : : "cc");                             
        __asm__("rorq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(e), [v] "+r"(x) : : "cc");                             
        __asm__("rorq" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(g), [v] "+r"(y) : : "cc");                             
    }                                                                             
    return IB_S4(a, c, e, g) + IB_S4(v, w, x, y);                                 
}

/* ---- ror_r_i_q: IB_KT_SHA ---- */
static inline void k_ror_r_i_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("ror_r_i_q", kk, 0, IB_UQ);                                            
    IB_UQ ain = a, n = (IB_UQ)(3);                                                   
    void *p = ib_kbuf_fill((uint64_t)n);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("ror_r_i_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "rorq" " " "$3,%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [c] "c"(n), [p] "r"(p), [fv] "r"(fv)                          
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)n;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)n;                                     
    g->outf = (uint64_t)fl & (IB_FLG_MASK_ROT);                                                
}

/* ---- shld_r_i_q: IB_K_SHD ---- */
static uint64_t k_shld_r_i_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), v = IB_TOPBIT(IB_UQ), b = (IB_UQ)IB_SEED(1);                 
    for (i = 0; i < it; i++)                                                      
        __asm__("shldq" " $3,%[b],%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"              
                : [a] "+r"(a), [v] "+r"(v) : [b] "r"(b) : "cc");                  
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_shld_r_i_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2);                                    
    IB_UQ v = IB_TOPBIT(IB_UQ), w = IB_TOPBIT(IB_UQ);                                      
    IB_UQ b = (IB_UQ)IB_SEED(1);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("shldq" " $3,%[b],%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"              
                : [a] "+r"(a), [v] "+r"(v) : [b] "r"(b) : "cc");                  
        __asm__("shldq" " $3,%[b],%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"              
                : [a] "+r"(c), [v] "+r"(w) : [b] "r"(b) : "cc");                  
    }                                                                             
    return IB_S2(a, c) + IB_S2(v, w);                                             
}

/* ---- shld_r_i_q: IB_KT_SHD ---- */
static inline void k_shld_r_i_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("shld_r_i_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("shld_r_i_q", kk, 1, IB_UQ);            
    IB_UQ ain = a, bin = b, n = (IB_UQ)(3);                                            
    void *p = ib_kbuf_fill((uint64_t)bin);                                          
    uintptr_t fv = (uintptr_t)IB_KFL("shld_r_i_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "shldq" " " "$3,%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                   
                    : [b] "r"(bin), [c] "c"(n), [p] "r"(p), [fv] "r"(fv)              
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)bin;  g->inf = (uint64_t)fv;            
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)bin;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK_SHIFT);                                                
}

/* ---- shrd_r_i_q: IB_K_SHD ---- */
static uint64_t k_shrd_r_i_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), v = IB_TOPBIT(IB_UQ), b = (IB_UQ)IB_SEED(1);                 
    for (i = 0; i < it; i++)                                                      
        __asm__("shrdq" " $3,%[b],%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"              
                : [a] "+r"(a), [v] "+r"(v) : [b] "r"(b) : "cc");                  
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_shrd_r_i_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2);                                    
    IB_UQ v = IB_TOPBIT(IB_UQ), w = IB_TOPBIT(IB_UQ);                                      
    IB_UQ b = (IB_UQ)IB_SEED(1);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("shrdq" " $3,%[b],%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"              
                : [a] "+r"(a), [v] "+r"(v) : [b] "r"(b) : "cc");                  
        __asm__("shrdq" " $3,%[b],%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"              
                : [a] "+r"(c), [v] "+r"(w) : [b] "r"(b) : "cc");                  
    }                                                                             
    return IB_S2(a, c) + IB_S2(v, w);                                             
}

/* ---- shrd_r_i_q: IB_KT_SHD ---- */
static inline void k_shrd_r_i_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("shrd_r_i_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("shrd_r_i_q", kk, 1, IB_UQ);            
    IB_UQ ain = a, bin = b, n = (IB_UQ)(3);                                            
    void *p = ib_kbuf_fill((uint64_t)bin);                                          
    uintptr_t fv = (uintptr_t)IB_KFL("shrd_r_i_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "shrdq" " " "$3,%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                   
                    : [b] "r"(bin), [c] "c"(n), [p] "r"(p), [fv] "r"(fv)              
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)bin;  g->inf = (uint64_t)fv;            
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)bin;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK_SHIFT);                                                
}

/* BMI2: 计数在普通寄存器里 -> 探针用 %[c](=%ecx) 而计时内核用 GCC 分配的 %[b];
 * 同一形态类(VEX 三操作数), 只是寄存器编号不同 -> 对翻译器同样有效 */
/* ---- shlx_r_r_q: IB_K_SHX ---- */
static uint64_t k_shlx_r_r_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), v = IB_TOPBIT(IB_UQ), b = (IB_UQ)3;                    
    for (i = 0; i < it; i++)                                                      
        __asm__("shlx" " " "%[b],%[a],%[a]" "\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : [b] "r"(b) : "cc");                  
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_shlx_r_r_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), c = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ v = IB_TOPBIT(IB_UQ), w = IB_TOPBIT(IB_UQ), b = (IB_UQ)3;                           
    for (i = 0; i < it; i++) {                                                    
        __asm__("shlx" " " "%[b],%[a],%[a]" "\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : [b] "r"(b) : "cc");                  
        __asm__("shlx" " " "%[b],%[a],%[a]" "\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(c), [v] "+r"(w) : [b] "r"(b) : "cc");                  
    }                                                                             
    return IB_S2(a, c) + IB_S2(v, w);                                             
}

/* ---- shlx_r_r_q: IB_KT_SHA ---- */
static inline void k_shlx_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("shlx_r_r_q", kk, 0, IB_UQ);                                            
    IB_UQ ain = a, n = (IB_UQ)(((IB_UQ)((IB_KIN("shlx_r_r_q", kk, 1) & (8 * (int)sizeof(IB_UQ) - 1)) | 1)));                                                   
    void *p = ib_kbuf_fill((uint64_t)n);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("shlx_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "shlx" " " "%[c],%[a],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [c] "c"(n), [p] "r"(p), [fv] "r"(fv)                          
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)n;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)n;                                     
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- sarx_r_r_q: IB_K_SHX ---- */
static uint64_t k_sarx_r_r_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), v = IB_TOPBIT(IB_UQ), b = (IB_UQ)3;                    
    for (i = 0; i < it; i++)                                                      
        __asm__("sarx" " " "%[b],%[a],%[a]" "\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : [b] "r"(b) : "cc");                  
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_sarx_r_r_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), c = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ v = IB_TOPBIT(IB_UQ), w = IB_TOPBIT(IB_UQ), b = (IB_UQ)3;                           
    for (i = 0; i < it; i++) {                                                    
        __asm__("sarx" " " "%[b],%[a],%[a]" "\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : [b] "r"(b) : "cc");                  
        __asm__("sarx" " " "%[b],%[a],%[a]" "\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(c), [v] "+r"(w) : [b] "r"(b) : "cc");                  
    }                                                                             
    return IB_S2(a, c) + IB_S2(v, w);                                             
}

/* ---- sarx_r_r_q: IB_KT_SHA ---- */
static inline void k_sarx_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("sarx_r_r_q", kk, 0, IB_UQ);                                            
    IB_UQ ain = a, n = (IB_UQ)(((IB_UQ)((IB_KIN("sarx_r_r_q", kk, 1) & (8 * (int)sizeof(IB_UQ) - 1)) | 1)));                                                   
    void *p = ib_kbuf_fill((uint64_t)n);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("sarx_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "sarx" " " "%[c],%[a],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [c] "c"(n), [p] "r"(p), [fv] "r"(fv)                          
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)n;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)n;                                     
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- shrx_r_r_q: IB_K_SHX ---- */
static uint64_t k_shrx_r_r_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), v = IB_TOPBIT(IB_UQ), b = (IB_UQ)3;                    
    for (i = 0; i < it; i++)                                                      
        __asm__("shrx" " " "%[b],%[a],%[a]" "\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : [b] "r"(b) : "cc");                  
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_shrx_r_r_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), c = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ v = IB_TOPBIT(IB_UQ), w = IB_TOPBIT(IB_UQ), b = (IB_UQ)3;                           
    for (i = 0; i < it; i++) {                                                    
        __asm__("shrx" " " "%[b],%[a],%[a]" "\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : [b] "r"(b) : "cc");                  
        __asm__("shrx" " " "%[b],%[a],%[a]" "\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(c), [v] "+r"(w) : [b] "r"(b) : "cc");                  
    }                                                                             
    return IB_S2(a, c) + IB_S2(v, w);                                             
}

/* ---- shrx_r_r_q: IB_KT_SHA ---- */
static inline void k_shrx_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("shrx_r_r_q", kk, 0, IB_UQ);                                            
    IB_UQ ain = a, n = (IB_UQ)(((IB_UQ)((IB_KIN("shrx_r_r_q", kk, 1) & (8 * (int)sizeof(IB_UQ) - 1)) | 1)));                                                   
    void *p = ib_kbuf_fill((uint64_t)n);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("shrx_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "shrx" " " "%[c],%[a],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [c] "c"(n), [p] "r"(p), [fv] "r"(fv)                          
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)n;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)n;                                     
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- rorx_r_i_q: IB_K_SHX ---- */
static uint64_t k_rorx_r_i_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), v = IB_TOPBIT(IB_UQ), b = (IB_UQ)3;                    
    for (i = 0; i < it; i++)                                                      
        __asm__("rorx" " " "$3,%[a],%[a]" "\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : [b] "r"(b) : "cc");                  
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_rorx_r_i_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), c = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ v = IB_TOPBIT(IB_UQ), w = IB_TOPBIT(IB_UQ), b = (IB_UQ)3;                           
    for (i = 0; i < it; i++) {                                                    
        __asm__("rorx" " " "$3,%[a],%[a]" "\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : [b] "r"(b) : "cc");                  
        __asm__("rorx" " " "$3,%[a],%[a]" "\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(c), [v] "+r"(w) : [b] "r"(b) : "cc");                  
    }                                                                             
    return IB_S2(a, c) + IB_S2(v, w);                                             
}

/* ---- rorx_r_i_q: IB_KT_SHA ---- */
static inline void k_rorx_r_i_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("rorx_r_i_q", kk, 0, IB_UQ);                                            
    IB_UQ ain = a, n = (IB_UQ)(3);                                                   
    void *p = ib_kbuf_fill((uint64_t)n);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("rorx_r_i_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "rorx" " " "$3,%[a],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [c] "c"(n), [p] "r"(p), [fv] "r"(fv)                          
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)n;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)n;                                     
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

#endif

/* ---------------- 两 ABI 共有形态 ---------------- */
/* ---- shl_r_i_l: IB_K_SHI ---- */
static uint64_t k_shl_r_i_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), v = IB_TOPBIT(IB_UL);                                     
    for (i = 0; i < it; i++)                                                      
        __asm__("shll" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : : "cc");                             
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_shl_r_i_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    IB_UL v = IB_TOPBIT(IB_UL), w = IB_TOPBIT(IB_UL), x = IB_TOPBIT(IB_UL), y = IB_TOPBIT(IB_UL); 
    for (i = 0; i < it; i++) {                                                    
        __asm__("shll" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : : "cc");                             
        __asm__("shll" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(c), [v] "+r"(w) : : "cc");                             
        __asm__("shll" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(e), [v] "+r"(x) : : "cc");                             
        __asm__("shll" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(g), [v] "+r"(y) : : "cc");                             
    }                                                                             
    return IB_S4(a, c, e, g) + IB_S4(v, w, x, y);                                 
}

/* ---- shl_r_i_l: IB_KT_SHA ---- */
static inline void k_shl_r_i_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("shl_r_i_l", kk, 0, IB_UL);                                            
    IB_UL ain = a, n = (IB_UL)(3);                                                   
    void *p = ib_kbuf_fill((uint64_t)n);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("shl_r_i_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "shll" " " "$3,%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [c] "c"(n), [p] "r"(p), [fv] "r"(fv)                          
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)n;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)n;                                     
    g->outf = (uint64_t)fl & (IB_FLG_MASK_SHIFT);                                                
}

/* ---- shr_r_i_l: IB_K_SHI ---- */
static uint64_t k_shr_r_i_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), v = IB_TOPBIT(IB_UL);                                     
    for (i = 0; i < it; i++)                                                      
        __asm__("shrl" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : : "cc");                             
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_shr_r_i_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    IB_UL v = IB_TOPBIT(IB_UL), w = IB_TOPBIT(IB_UL), x = IB_TOPBIT(IB_UL), y = IB_TOPBIT(IB_UL); 
    for (i = 0; i < it; i++) {                                                    
        __asm__("shrl" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : : "cc");                             
        __asm__("shrl" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(c), [v] "+r"(w) : : "cc");                             
        __asm__("shrl" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(e), [v] "+r"(x) : : "cc");                             
        __asm__("shrl" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(g), [v] "+r"(y) : : "cc");                             
    }                                                                             
    return IB_S4(a, c, e, g) + IB_S4(v, w, x, y);                                 
}

/* ---- shr_r_i_l: IB_KT_SHA ---- */
static inline void k_shr_r_i_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("shr_r_i_l", kk, 0, IB_UL);                                            
    IB_UL ain = a, n = (IB_UL)(3);                                                   
    void *p = ib_kbuf_fill((uint64_t)n);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("shr_r_i_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "shrl" " " "$3,%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [c] "c"(n), [p] "r"(p), [fv] "r"(fv)                          
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)n;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)n;                                     
    g->outf = (uint64_t)fl & (IB_FLG_MASK_SHIFT);                                                
}

/* ---- shr_r_i_b: IB_K_SHI8 ---- */
static uint64_t k_shr_r_i_b(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UB a = (IB_UB)IB_SEED(0), v = IB_TOPBIT(IB_UB);                                     
    for (i = 0; i < it; i++)                                                      
        __asm__("shrb" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+a"(a), [v] "+b"(v) : : "cc");                             
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_shr_r_i_b_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UB a = (IB_UB)IB_SEED(0), c = (IB_UB)IB_SEED(2);                                    
    IB_UB v = IB_TOPBIT(IB_UB), w = IB_TOPBIT(IB_UB);                                      
    for (i = 0; i < it; i++) {                                                    
        __asm__("shrb" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+a"(a), [v] "+b"(v) : : "cc");                             
        __asm__("shrb" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+c"(c), [v] "+d"(w) : : "cc");                             
    }                                                                             
    return IB_S2(a, c) + IB_S2(v, w);                                             
}

/* ---- shr_r_i_b: IB_KT_SHA ---- */
static inline void k_shr_r_i_b_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UB a = (IB_UB)IB_KIN8("shr_r_i_b", kk, 0, IB_UB);                                            
    IB_UB ain = a, n = (IB_UB)(3);                                                   
    void *p = ib_kbuf_fill((uint64_t)n);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("shr_r_i_b", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "shrb" " " "$3,%[a]" IB_GETF                                   
                    : [a] "+a"(a), [fl] "=&r"(fl)                                     
                    : [c] "c"(n), [p] "r"(p), [fv] "r"(fv)                          
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)n;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)n;                                     
    g->outf = (uint64_t)fl & (IB_FLG_MASK_SHIFT);                                                
}

/* ---- sar_r__l: IB_K_SH1 ---- */
static uint64_t k_sar_r__l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), v = IB_TOPBIT(IB_UL);                                     
    for (i = 0; i < it; i++)                                                      
        __asm__("sarl" " %[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                      
                : [a] "+r"(a), [v] "+r"(v) : : "cc");                             
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_sar_r__l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    IB_UL v = IB_TOPBIT(IB_UL), w = IB_TOPBIT(IB_UL), x = IB_TOPBIT(IB_UL), y = IB_TOPBIT(IB_UL); 
    for (i = 0; i < it; i++) {                                                    
        __asm__("sarl" " %[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                      
                : [a] "+r"(a), [v] "+r"(v) : : "cc");                             
        __asm__("sarl" " %[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                      
                : [a] "+r"(c), [v] "+r"(w) : : "cc");                             
        __asm__("sarl" " %[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                      
                : [a] "+r"(e), [v] "+r"(x) : : "cc");                             
        __asm__("sarl" " %[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                      
                : [a] "+r"(g), [v] "+r"(y) : : "cc");                             
    }                                                                             
    return IB_S4(a, c, e, g) + IB_S4(v, w, x, y);                                 
}

/* ---- sar_r__l: IB_KT_SHA ---- */
static inline void k_sar_r__l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("sar_r__l", kk, 0, IB_UL);                                            
    IB_UL ain = a, n = (IB_UL)(1);                                                   
    void *p = ib_kbuf_fill((uint64_t)n);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("sar_r__l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "sarl" " " "%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [c] "c"(n), [p] "r"(p), [fv] "r"(fv)                          
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)n;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)n;                                     
    g->outf = (uint64_t)fl & (IB_FLG_MASK_SH1);                                                
}

/* ---- rol_r_i_l: IB_K_SHI ---- */
static uint64_t k_rol_r_i_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), v = IB_TOPBIT(IB_UL);                                     
    for (i = 0; i < it; i++)                                                      
        __asm__("roll" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : : "cc");                             
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_rol_r_i_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    IB_UL v = IB_TOPBIT(IB_UL), w = IB_TOPBIT(IB_UL), x = IB_TOPBIT(IB_UL), y = IB_TOPBIT(IB_UL); 
    for (i = 0; i < it; i++) {                                                    
        __asm__("roll" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : : "cc");                             
        __asm__("roll" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(c), [v] "+r"(w) : : "cc");                             
        __asm__("roll" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(e), [v] "+r"(x) : : "cc");                             
        __asm__("roll" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(g), [v] "+r"(y) : : "cc");                             
    }                                                                             
    return IB_S4(a, c, e, g) + IB_S4(v, w, x, y);                                 
}

/* ---- rol_r_i_l: IB_KT_SHA ---- */
static inline void k_rol_r_i_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("rol_r_i_l", kk, 0, IB_UL);                                            
    IB_UL ain = a, n = (IB_UL)(3);                                                   
    void *p = ib_kbuf_fill((uint64_t)n);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("rol_r_i_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "roll" " " "$3,%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [c] "c"(n), [p] "r"(p), [fv] "r"(fv)                          
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)n;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)n;                                     
    g->outf = (uint64_t)fl & (IB_FLG_MASK_ROT);                                                
}

/* ---- rol_r_i_w: IB_K_SHI8 ---- */
static uint64_t k_rol_r_i_w(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UW a = (IB_UW)IB_SEED(0), v = IB_TOPBIT(IB_UW);                                     
    for (i = 0; i < it; i++)                                                      
        __asm__("rolw" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+a"(a), [v] "+b"(v) : : "cc");                             
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_rol_r_i_w_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UW a = (IB_UW)IB_SEED(0), c = (IB_UW)IB_SEED(2);                                    
    IB_UW v = IB_TOPBIT(IB_UW), w = IB_TOPBIT(IB_UW);                                      
    for (i = 0; i < it; i++) {                                                    
        __asm__("rolw" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+a"(a), [v] "+b"(v) : : "cc");                             
        __asm__("rolw" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+c"(c), [v] "+d"(w) : : "cc");                             
    }                                                                             
    return IB_S2(a, c) + IB_S2(v, w);                                             
}

/* ---- rol_r_i_w: IB_KT_SHA ---- */
static inline void k_rol_r_i_w_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UW a = (IB_UW)IB_KIN8("rol_r_i_w", kk, 0, IB_UW);                                            
    IB_UW ain = a, n = (IB_UW)(3);                                                   
    void *p = ib_kbuf_fill((uint64_t)n);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("rol_r_i_w", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "rolw" " " "$3,%[a]" IB_GETF                                   
                    : [a] "+a"(a), [fl] "=&r"(fl)                                     
                    : [c] "c"(n), [p] "r"(p), [fv] "r"(fv)                          
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)n;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)n;                                     
    g->outf = (uint64_t)fl & (IB_FLG_MASK_ROT);                                                
}

/* ---- ror_r_i_l: IB_K_SHI ---- */
static uint64_t k_ror_r_i_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), v = IB_TOPBIT(IB_UL);                                     
    for (i = 0; i < it; i++)                                                      
        __asm__("rorl" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : : "cc");                             
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_ror_r_i_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    IB_UL v = IB_TOPBIT(IB_UL), w = IB_TOPBIT(IB_UL), x = IB_TOPBIT(IB_UL), y = IB_TOPBIT(IB_UL); 
    for (i = 0; i < it; i++) {                                                    
        __asm__("rorl" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(a), [v] "+r"(v) : : "cc");                             
        __asm__("rorl" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(c), [v] "+r"(w) : : "cc");                             
        __asm__("rorl" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(e), [v] "+r"(x) : : "cc");                             
        __asm__("rorl" " $3,%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"                   
                : [a] "+r"(g), [v] "+r"(y) : : "cc");                             
    }                                                                             
    return IB_S4(a, c, e, g) + IB_S4(v, w, x, y);                                 
}

/* ---- ror_r_i_l: IB_KT_SHA ---- */
static inline void k_ror_r_i_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("ror_r_i_l", kk, 0, IB_UL);                                            
    IB_UL ain = a, n = (IB_UL)(3);                                                   
    void *p = ib_kbuf_fill((uint64_t)n);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("ror_r_i_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "rorl" " " "$3,%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [c] "c"(n), [p] "r"(p), [fv] "r"(fv)                          
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)n;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)n;                                     
    g->outf = (uint64_t)fl & (IB_FLG_MASK_ROT);                                                
}

/* ---- shld_r_i_l: IB_K_SHD ---- */
static uint64_t k_shld_r_i_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), v = IB_TOPBIT(IB_UL), b = (IB_UL)IB_SEED(1);                 
    for (i = 0; i < it; i++)                                                      
        __asm__("shldl" " $3,%[b],%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"              
                : [a] "+r"(a), [v] "+r"(v) : [b] "r"(b) : "cc");                  
    return IB_S2((uint64_t)a, (uint64_t)v);                                       
}                                                                                 
static uint64_t k_shld_r_i_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2);                                    
    IB_UL v = IB_TOPBIT(IB_UL), w = IB_TOPBIT(IB_UL);                                      
    IB_UL b = (IB_UL)IB_SEED(1);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("shldl" " $3,%[b],%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"              
                : [a] "+r"(a), [v] "+r"(v) : [b] "r"(b) : "cc");                  
        __asm__("shldl" " $3,%[b],%[a]\n\tadc $0,%[v]\n\tadd %[v],%[a]"              
                : [a] "+r"(c), [v] "+r"(w) : [b] "r"(b) : "cc");                  
    }                                                                             
    return IB_S2(a, c) + IB_S2(v, w);                                             
}

/* ---- shld_r_i_l: IB_KT_SHD ---- */
static inline void k_shld_r_i_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("shld_r_i_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("shld_r_i_l", kk, 1, IB_UL);            
    IB_UL ain = a, bin = b, n = (IB_UL)(3);                                            
    void *p = ib_kbuf_fill((uint64_t)bin);                                          
    uintptr_t fv = (uintptr_t)IB_KFL("shld_r_i_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "shldl" " " "$3,%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                   
                    : [b] "r"(bin), [c] "c"(n), [p] "r"(p), [fv] "r"(fv)              
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)bin;  g->inf = (uint64_t)fv;            
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)bin;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK_SHIFT);                                                
}


/* ---------------- 用例表(bpop = 每 op 处理字节数, 供 tput 折 MB/s) ------------ */
static const ib_case g_cases[] = {
    /* 两 ABI 共有 */
    IB_ROW_K("x86_shr__r_i_l",        NULL, shr_r_i_l,   4),
    IB_ROW_K("x86_shl__r_i_l",        NULL, shl_r_i_l,   4),
    IB_ROW_K("x86_sar__r__l",         NULL, sar_r__l,    4),
    IB_ROW_K("x86_shr__r_i_b",        NULL, shr_r_i_b,   1),
    IB_ROW_K("x86_rol__r_i_l",        NULL, rol_r_i_l,   4),
    IB_ROW_K("x86_rol__r_i_w",        NULL, rol_r_i_w,   2),
    IB_ROW_K("x86_ror__r_i_l",        NULL, ror_r_i_l,   4),
    IB_ROW_K("x86_shld__r_i_l",       NULL, shld_r_i_l,  4),
#ifdef __x86_64__
    /* 64 位专有形态 */
    IB_ROW_K("x86_shl__r_i_q",        NULL, shl_r_i_q,   8),
    IB_ROW_K("x86_shr__r_r_q",        NULL, shr_r_r_q,   8),
    IB_ROW_K("x86_shr__r_i_q",        NULL, shr_r_i_q,   8),
    IB_ROW_K("x86_sar__r_i_q",        NULL, sar_r_i_q,   8),
    IB_ROW_K("x86_shl__r_r_q",        NULL, shl_r_r_q,   8),
    IB_ROW_K("x86_rol__r_i_q",        NULL, rol_r_i_q,   8),
    IB_ROW_K("x86_ror__r_i_q",        NULL, ror_r_i_q,   8),
    IB_ROW_K("x86_shrd__r_i_q",       NULL, shrd_r_i_q,  8),
    IB_ROW_K("x86_shld__r_i_q",       NULL, shld_r_i_q,  8),
    IB_ROW_K("x86_shlx__r_r_q",       NULL, shlx_r_r_q,  8),
    IB_ROW_K("x86_sarx__r_r_q",       NULL, sarx_r_r_q,  8),
    IB_ROW_K("x86_shrx__r_r_q",       NULL, shrx_r_r_q,  8),
    IB_ROW_K("x86_rorx__r_i_q",       NULL, rorx_r_i_q,  8),
#endif
};
#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

int main(int argc, char **argv)
{
    ib_init(argc, argv);
    ib_abuf_init();                 /* 只读/写区确定性预置(签名跨机可复现的前提) */
    ib_hdr("shift", NCASES);
    ib_run_cases("shift", g_cases, NCASES);
    return 0;
}
