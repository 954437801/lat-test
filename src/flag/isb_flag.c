/* isb_flag.c —— 产标志家族形态组(grp=flag): cmp/test(只改标志、不写结果)
 *
 * 用例来源 = 实测 三层映射 round5_form_weights.csv 里 cmp/test 的 k90 形态
 * (Pareto-90%), 共 18 条(cmp 14 + test 4, 覆盖全量采样的 23.32%); case 名 =
 * x86_<助记符>__<形态段> 与 form_key 1:1(' '->'__', '.'->'_', '/'->'_'),
 * 故 --only=x86_cmp__m_i 可直接切出全部「内存+立即数」比较形态。
 *
 * 为什么单独立组: cmp/test 是全权重第一梯队(test 12.25% + cmp 11.06% > mov),
 * 但它们的「结果」在标志里 —— lat 必须靠 adc 把 CF 回灌进链主才构成真依赖链,
 * 与 add/or 那类结果写回的算术组内核结构不同, 混在一起会看不清谁拖了谁。
 *
 * 骨架纪律(全组统一 3 条, 被测占 1 条):
 *     add<SUF> $1,%[a]     ; 链步进, 产标志
 *     <被测 cmp/test>      ; 覆盖标志(若其寄存器输入含 %[a] 则标志依赖链主)
 *     adc<SUF> $0,%[a]     ; 消费 CF -> 闭环
 * 三类被测形态的链可构成性不同, 分别用不同模板:
 *   - r.r / r.i / m.r / r.m: 被测含寄存器 -> 标志依赖 %[a], 是真依赖链;
 *   - m.i(mem+imm): 被测不含寄存器 -> CF 只与内存常量有关, 链退化为骨架两条,
 *     其 lat 是被测指令的下界(仍含被测指令在窗口内发射), tput 才是主指标。
 *   - 8/16 位一律走 IB_K_FLG8 与 IB_K_FLG8P: 链主钉 %al/%ax、源钉 %bl/%bx, 防 GCC 把
 *     字节变量分配到需 REX 的高半字节寄存器而改掉被测编码。
 *   - base_sp 形态: 栈槽内容不确定 -> 入口预置定值(FLG8P), 否则跨机签名不可复现。
 *
 * 64 位形态只存在于 x86_64: 内核实例与表项一起 #ifdef(i386 侧 18->12 条)。
 *
 * 正确性从哪来(不再靠上面那套链形): 每条 case 另有一具 KAT 探针
 * (IB_KT_* 模板, 由 IB_K_*K 一行与计时内核同时实例化), 每组 8 个确定性输入、
 * 各只执行被测指令 1 次, 把 {i0,i1,inf,o0,o1,outf} 与编译期真值表逐位比对:
 *   - 真值表(isb_flag_kat.h)还是空的 -> 本次运行即采集, kat_st=COLLECT, K 附表行
 *     落 stdout, pack/gen_val.sh 收割后回填 -> x86 真机只需跑一次;
 *   - 表已回填 -> kat_st=OK/KATFAIL; LATX 等翻译机不需采集、不需对拍。
 * 因此骨架/链形如何设计只影响计时, 不影响正确判定。
 *
 * 计时签名撞车(不视为缺陷, 口径见 docs/设计/功能测试与KAT.md):
 * 签名重复自检实测 18 条里 lat_sig 只剩 11 个唯一值、tput_sig 14 个, 几组都是
 * 「同宽度的若干 cmp 形态 + 对应 test 形态」 撞在一起(如 cmp r.i.l / cmp r.r.l /
 * cmp m.i.l-base / test r.r.l 四条同值)。机制: 链主每轮只经 `adc $0` 加进一个
 * CF, 而 CF 恒 0 时所有被测形态的递推完全重合(只剩骨架 `add $1`) —— test 按定义
 * 把 CF 清 0, 所以“cmp 与 test 同签名”反过来就是“本窗口内 cmp 的 CF 恒 0”的
 * 实测证据(链主与 b 都是大常数, `add $1` 又单调, 窗口内 a<b 不成立)。
 * 这一族的语义判定不拿签名当证据(上面那段正是它的不足): 本组 18 条全接
 * KAT, 单发执行 + 逐字段比对(标志也上表), 错一个标志位就翻 KATFAIL。
 */
#include "ib_core.h"
#include "ib_buf.h"
#include "isb_flag_kat.h"      /* KAT 真值表(采集后生成; 未取数时全 UNSET) */

/* ---------------- 64 位形态(仅 x86_64) ---------------- */
#ifdef __x86_64__
/* 约定(与 mov 组一致): insn = 被测助记符**全名含尺寸后缀**(cmpb/cmpl/cmpq),
 * SUF 只用于骨架的 add/adc。不写后缀则被测操作数无寄存器时(m.i/m.sp) gas 会
 * 按默认宽度汇编 -> cmpb 被当 cmpl 测, 且多读的字节是栈上/区外未初始化内容
 * -> 标志不确定 -> 签名不可复现(实测)。 */
/* ---- cmp_r_r_q: IB_K_FLGK ---- */
static uint64_t k_cmp_r_r_q(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " "%[b],%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_cmp_r_r_q_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " "%[b],%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " "%[b],%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(c) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " "%[b],%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(e) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " "%[b],%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(g) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}    
        static inline void k_cmp_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("cmp_r_r_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("cmp_r_r_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("cmp_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "cmpq" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- cmp_r_i_q: IB_K_FLGK ---- */
static uint64_t k_cmp_r_i_q(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " "$5,%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_cmp_r_i_q_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " "$5,%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " "$5,%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(c) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " "$5,%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(e) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " "$5,%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(g) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}    
        static inline void k_cmp_r_i_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("cmp_r_i_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("cmp_r_i_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("cmp_r_i_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "cmpq" " " "$5,%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- cmp_m_r_q_base: IB_K_FLGK ---- */
static uint64_t k_cmp_m_r_q_base(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " "%[a]," IB_M_BASE "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_cmp_m_r_q_base_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " "%[a]," IB_M_BASE "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " "%[a]," IB_M_BASE "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(c) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " "%[a]," IB_M_BASE "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(e) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " "%[a]," IB_M_BASE "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(g) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}    
        static inline void k_cmp_m_r_q_base_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("cmp_m_r_q_base", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("cmp_m_r_q_base", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("cmp_m_r_q_base", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "cmpq" " " "%[a]," IB_M_BASE IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- cmp_r_m_q_base: IB_K_FLGK ---- */
static uint64_t k_cmp_r_m_q_base(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " IB_M_BASE ",%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_cmp_r_m_q_base_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " IB_M_BASE ",%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " IB_M_BASE ",%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(c) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " IB_M_BASE ",%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(e) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " IB_M_BASE ",%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(g) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}    
        static inline void k_cmp_r_m_q_base_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("cmp_r_m_q_base", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("cmp_r_m_q_base", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("cmp_r_m_q_base", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "cmpq" " " IB_M_BASE ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- cmp_m_i_q_base: IB_K_FLGMK ---- */
static uint64_t k_cmp_m_i_q_base(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " "$5," IB_M_BASE "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(a) : [p] "r"(p), [ix] "r"(ix) : "cc", "memory");                  
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_cmp_m_i_q_base_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "q" " $1,%[a]\n\t" "cmpq" " " "$5," IB_M_BASE "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(a) : [p] "r"(p), [ix] "r"(ix) : "cc", "memory");                  
        __asm__("add" "q" " $1,%[c]\n\t" "cmpq" " " "$5," IB_M_BASE "\n\t"                      
                "adc" "q" " $0,%[c]"                                              
                : [c] "+r"(c) : [p] "r"(p), [ix] "r"(ix) : "cc", "memory");                  
    }                                                                             
    return IB_S2(a, c);                                                           
}   
        static inline void k_cmp_m_i_q_base_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("cmp_m_i_q_base", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("cmp_m_i_q_base", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("cmp_m_i_q_base", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "cmpq" " " "$5," IB_M_BASE IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- test_r_r_q: IB_K_FLGK ---- */
static uint64_t k_test_r_r_q(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "q" " $1,%[a]\n\t" "testq" " " "%[b],%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_test_r_r_q_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "q" " $1,%[a]\n\t" "testq" " " "%[b],%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "testq" " " "%[b],%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(c) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "testq" " " "%[b],%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(e) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "testq" " " "%[b],%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(g) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}    
        static inline void k_test_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("test_r_r_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("test_r_r_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("test_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "testq" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

#endif

/* ---------------- 两 ABI 共有形态 ---------------- */
/* ---- cmp_r_i_l: IB_K_FLGK ---- */
static uint64_t k_cmp_r_i_l(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " "$5,%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_cmp_r_i_l_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " "$5,%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " "$5,%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(c) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " "$5,%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(e) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " "$5,%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(g) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}    
        static inline void k_cmp_r_i_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("cmp_r_i_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("cmp_r_i_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("cmp_r_i_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "cmpl" " " "$5,%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- cmp_r_r_l: IB_K_FLGK ---- */
static uint64_t k_cmp_r_r_l(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " "%[b],%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_cmp_r_r_l_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " "%[b],%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " "%[b],%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(c) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " "%[b],%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(e) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " "%[b],%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(g) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}    
        static inline void k_cmp_r_r_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("cmp_r_r_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("cmp_r_r_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("cmp_r_r_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "cmpl" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- cmp_r_m_l_base: IB_K_FLGK ---- */
static uint64_t k_cmp_r_m_l_base(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " IB_M_BASE ",%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_cmp_r_m_l_base_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " IB_M_BASE ",%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " IB_M_BASE ",%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(c) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " IB_M_BASE ",%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(e) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " IB_M_BASE ",%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(g) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}    
        static inline void k_cmp_r_m_l_base_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("cmp_r_m_l_base", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("cmp_r_m_l_base", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("cmp_r_m_l_base", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "cmpl" " " IB_M_BASE ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- cmp_m_r_l_index: IB_K_FLGK ---- */
static uint64_t k_cmp_m_r_l_index(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " "%[a]," IB_M_IDX "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_cmp_m_r_l_index_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " "%[a]," IB_M_IDX "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " "%[a]," IB_M_IDX "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(c) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " "%[a]," IB_M_IDX "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(e) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " "%[a]," IB_M_IDX "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(g) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}    
        static inline void k_cmp_m_r_l_index_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("cmp_m_r_l_index", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("cmp_m_r_l_index", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("cmp_m_r_l_index", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "cmpl" " " "%[a]," IB_M_IDX IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- cmp_m_i_l_base: IB_K_FLGMK ---- */
static uint64_t k_cmp_m_i_l_base(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " "$5," IB_M_BASE "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(a) : [p] "r"(p), [ix] "r"(ix) : "cc", "memory");                  
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_cmp_m_i_l_base_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "l" " $1,%[a]\n\t" "cmpl" " " "$5," IB_M_BASE "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(a) : [p] "r"(p), [ix] "r"(ix) : "cc", "memory");                  
        __asm__("add" "l" " $1,%[c]\n\t" "cmpl" " " "$5," IB_M_BASE "\n\t"                      
                "adc" "l" " $0,%[c]"                                              
                : [c] "+r"(c) : [p] "r"(p), [ix] "r"(ix) : "cc", "memory");                  
    }                                                                             
    return IB_S2(a, c);                                                           
}   
        static inline void k_cmp_m_i_l_base_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("cmp_m_i_l_base", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("cmp_m_i_l_base", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("cmp_m_i_l_base", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "cmpl" " " "$5," IB_M_BASE IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- cmp_r_i_b: IB_K_FLG8K ---- */
static uint64_t k_cmp_r_i_b(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UB a = (IB_UB)IB_SEED(0), b = (IB_UB)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "b" " $1,%[a]\n\t" "cmpb" " " "$5,%[a]" "\n\t"                       
                "adc" "b" " $0,%[a]"                                              
                : [a] "+a"(a) : [b] "b"(b), [p] "r"(p), [ix] "r"(ix)              
                : "cc", "memory");                                                
    }                                                                             
    return IB_S1(a);                                                              
}                                                                                 
static uint64_t k_cmp_r_i_b_tp(ib_uw it)                                
{                                                                                 
    return k_cmp_r_i_b(it);                                                            
}       
        static inline void k_cmp_r_i_b_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UB a = (IB_UB)IB_KIN8("cmp_r_i_b", kk, 0, IB_UB), b = (IB_UB)IB_KIN8("cmp_r_i_b", kk, 1, IB_UB);            
    IB_UB ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("cmp_r_i_b", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "cmpb" " " "$5,%[a]" IB_GETF                                   
                    : [a] "+a"(a), [fl] "=&r"(fl)                                   
                    : [b] "b"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- cmp_m_r_b_index: IB_K_FLG8K ---- */
static uint64_t k_cmp_m_r_b_index(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UB a = (IB_UB)IB_SEED(0), b = (IB_UB)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "b" " $1,%[a]\n\t" "cmpb" " " "%[a]," IB_M_IDX "\n\t"                       
                "adc" "b" " $0,%[a]"                                              
                : [a] "+a"(a) : [b] "b"(b), [p] "r"(p), [ix] "r"(ix)              
                : "cc", "memory");                                                
    }                                                                             
    return IB_S1(a);                                                              
}                                                                                 
static uint64_t k_cmp_m_r_b_index_tp(ib_uw it)                                
{                                                                                 
    return k_cmp_m_r_b_index(it);                                                            
}       
        static inline void k_cmp_m_r_b_index_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UB a = (IB_UB)IB_KIN8("cmp_m_r_b_index", kk, 0, IB_UB), b = (IB_UB)IB_KIN8("cmp_m_r_b_index", kk, 1, IB_UB);            
    IB_UB ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("cmp_m_r_b_index", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "cmpb" " " "%[a]," IB_M_IDX IB_GETF                                   
                    : [a] "+a"(a), [fl] "=&r"(fl)                                   
                    : [b] "b"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- cmp_m_i_b_base: IB_K_FLGMK ---- */
static uint64_t k_cmp_m_i_b_base(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UB a = (IB_UB)IB_SEED(0);                                                        
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "b" " $1,%[a]\n\t" "cmpb" " " "$5," IB_M_BASE "\n\t"                      
                "adc" "b" " $0,%[a]"                                              
                : [a] "+a"(a) : [p] "r"(p), [ix] "r"(ix) : "cc", "memory");                  
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_cmp_m_i_b_base_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UB a = (IB_UB)IB_SEED(0), c = (IB_UB)IB_SEED(2);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "b" " $1,%[a]\n\t" "cmpb" " " "$5," IB_M_BASE "\n\t"                      
                "adc" "b" " $0,%[a]"                                              
                : [a] "+a"(a) : [p] "r"(p), [ix] "r"(ix) : "cc", "memory");                  
        __asm__("add" "b" " $1,%[c]\n\t" "cmpb" " " "$5," IB_M_BASE "\n\t"                      
                "adc" "b" " $0,%[c]"                                              
                : [c] "+a"(c) : [p] "r"(p), [ix] "r"(ix) : "cc", "memory");                  
    }                                                                             
    return IB_S2(a, c);                                                           
}   
        static inline void k_cmp_m_i_b_base_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UB a = (IB_UB)IB_KIN8("cmp_m_i_b_base", kk, 0, IB_UB), b = (IB_UB)IB_KIN8("cmp_m_i_b_base", kk, 1, IB_UB);            
    IB_UB ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("cmp_m_i_b_base", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "cmpb" " " "$5," IB_M_BASE IB_GETF                                   
                    : [a] "+a"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- cmp_m_i_b_base_sp: IB_K_FLG8PK ---- */
static uint64_t k_cmp_m_i_b_base_sp(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UB a = (IB_UB)IB_SEED(0);                                                        
    __asm__ volatile("mov" "b" " $0x3c," IB_M_SP ::: "memory");                        
    for (i = 0; i < it; i++)                                                      
        __asm__("add" "b" " $1,%[a]\n\t" "cmpb" " " "$5," IB_M_SP "\n\t"                       
                "adc" "b" " $0,%[a]"                                              
                : [a] "+a"(a) : : "cc", "memory");                                
    return IB_S1(a);                                                              
}                                                                                 
static uint64_t k_cmp_m_i_b_base_sp_tp(ib_uw it)                                
{                                                                                 
    return k_cmp_m_i_b_base_sp(it);                                                            
}  
        static inline void k_cmp_m_i_b_base_sp_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UB a = (IB_UB)IB_KIN8("cmp_m_i_b_base_sp", kk, 0, IB_UB), b = (IB_UB)IB_KIN8("cmp_m_i_b_base_sp", kk, 1, IB_UB);            
    IB_UB ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("cmp_m_i_b_base_sp", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "mov" "b" " %[b], " IB_M_SP "\n\t" "cmpb" " " "$5," IB_M_SP IB_GETF      
                    : [a] "+a"(a), [fl] "=&r"(fl)                                   
                    : [b] "q"(b), [p] "r"(p), [fv] "r"(fv) : "cc", "memory");         
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                           
}

/* ---- test_r_r_l: IB_K_FLGK ---- */
static uint64_t k_test_r_r_l(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "l" " $1,%[a]\n\t" "testl" " " "%[b],%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_test_r_r_l_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "l" " $1,%[a]\n\t" "testl" " " "%[b],%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "testl" " " "%[b],%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(c) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "testl" " " "%[b],%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(e) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "testl" " " "%[b],%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(g) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}    
        static inline void k_test_r_r_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("test_r_r_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("test_r_r_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("test_r_r_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "testl" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- test_r_i_b: IB_K_FLG8K ---- */
static uint64_t k_test_r_i_b(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UB a = (IB_UB)IB_SEED(0), b = (IB_UB)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "b" " $1,%[a]\n\t" "testb" " " "$5,%[a]" "\n\t"                       
                "adc" "b" " $0,%[a]"                                              
                : [a] "+a"(a) : [b] "b"(b), [p] "r"(p), [ix] "r"(ix)              
                : "cc", "memory");                                                
    }                                                                             
    return IB_S1(a);                                                              
}                                                                                 
static uint64_t k_test_r_i_b_tp(ib_uw it)                                
{                                                                                 
    return k_test_r_i_b(it);                                                            
}       
        static inline void k_test_r_i_b_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UB a = (IB_UB)IB_KIN8("test_r_i_b", kk, 0, IB_UB), b = (IB_UB)IB_KIN8("test_r_i_b", kk, 1, IB_UB);            
    IB_UB ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("test_r_i_b", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "testb" " " "$5,%[a]" IB_GETF                                   
                    : [a] "+a"(a), [fl] "=&r"(fl)                                   
                    : [b] "b"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- test_r_r_b: IB_K_FLG8K ---- */
static uint64_t k_test_r_r_b(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UB a = (IB_UB)IB_SEED(0), b = (IB_UB)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "b" " $1,%[a]\n\t" "testb" " " "%[b],%[a]" "\n\t"                       
                "adc" "b" " $0,%[a]"                                              
                : [a] "+a"(a) : [b] "b"(b), [p] "r"(p), [ix] "r"(ix)              
                : "cc", "memory");                                                
    }                                                                             
    return IB_S1(a);                                                              
}                                                                                 
static uint64_t k_test_r_r_b_tp(ib_uw it)                                
{                                                                                 
    return k_test_r_r_b(it);                                                            
}       
        static inline void k_test_r_r_b_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UB a = (IB_UB)IB_KIN8("test_r_r_b", kk, 0, IB_UB), b = (IB_UB)IB_KIN8("test_r_r_b", kk, 1, IB_UB);            
    IB_UB ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("test_r_r_b", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "testb" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+a"(a), [fl] "=&r"(fl)                                   
                    : [b] "b"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}


/* ---------------- 用例表(bpop = 每 op 处理字节数, 供 tput 折 MB/s) ---------------- */
static const ib_case g_cases[] = {
    /* 两 ABI 共有 */
    IB_ROW_K("x86_cmp__r_i_l",        NULL, cmp_r_i_l,         4),
    IB_ROW_K("x86_cmp__r_r_l",        NULL, cmp_r_r_l,         4),
    IB_ROW_K("x86_cmp__r_m_l_base",   NULL, cmp_r_m_l_base,    4),
    IB_ROW_K("x86_cmp__m_r_l_index",  NULL, cmp_m_r_l_index,   4),
    IB_ROW_K("x86_cmp__m_i_l_base",   NULL, cmp_m_i_l_base,    4),
    IB_ROW_K("x86_cmp__r_i_b",        NULL, cmp_r_i_b,         1),
    IB_ROW_K("x86_cmp__m_r_b_index",  NULL, cmp_m_r_b_index,   1),
    IB_ROW_K("x86_cmp__m_i_b_base",   NULL, cmp_m_i_b_base,    1),
    IB_ROW_K("x86_cmp__m_i_b_base_sp", NULL, cmp_m_i_b_base_sp, 1),
    IB_ROW_K("x86_test__r_r_l",       NULL, test_r_r_l,        4),
    IB_ROW_K("x86_test__r_i_b",       NULL, test_r_i_b,        1),
    IB_ROW_K("x86_test__r_r_b",       NULL, test_r_r_b,        1),
#ifdef __x86_64__
    /* 64 位专有形态 */
    IB_ROW_K("x86_cmp__r_r_q",        NULL, cmp_r_r_q,         8),
    IB_ROW_K("x86_cmp__r_i_q",        NULL, cmp_r_i_q,         8),
    IB_ROW_K("x86_cmp__m_r_q_base",   NULL, cmp_m_r_q_base,    8),
    IB_ROW_K("x86_cmp__r_m_q_base",   NULL, cmp_r_m_q_base,    8),
    IB_ROW_K("x86_cmp__m_i_q_base",   NULL, cmp_m_i_q_base,    8),
    IB_ROW_K("x86_test__r_r_q",       NULL, test_r_r_q,        8),
#endif
};
#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

int main(int argc, char **argv)
{
    ib_init(argc, argv);
    ib_abuf_init();                 /* 只读/写区确定性预置(签名跨机可复现的前提) */
    ib_hdr("flag", NCASES);
    ib_run_cases("flag", g_cases, NCASES);
    return 0;
}
