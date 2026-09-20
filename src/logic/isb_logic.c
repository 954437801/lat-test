/* isb_logic.c —— 位运算家族形态组(grp=logic): and/or/xor/not
 *
 * 用例来源 = xperf 三层映射 round5_form_weights.csv 里 and/or/xor/not 的 k90
 * 形态, 共 15 条(and 4 + or 6 + xor 2 + not 3, 覆盖全量采样的 5.42%); case 名
 * = x86_<助记符>__<形态段> 与 form_key 1:1。
 *
 * 为什么不并进 alu 组: 成本结构与 alu 同族, 但 and/or/xor 是「会收敛」的运算
 * (a &= b、a |= b 至多一轮就到不动点), 其 lat 链虽真存在但值恒定, 一旦 LATX
 * 侧引入值相关的优化(常量传播/不动点消除), 只有独立成组才能在对比里把这类
 * 「译码正确但被折叠」的情况与真正的算术差异区分开。not 是唯一不收敛的单目
 * 位运算, 与 bnot 类一起作为该假设的反证。
 *
 * 内核与 alu 组共用模板(同骨架才能同组横比):
 *   r.r -> IB_K_RR / r.i -> IB_K_RI / 单目 -> IB_K_R1(8 位走 IB_K_R18)
 *   r.m(rip 相对) -> IB_K_SRC; insn 一律写含尺寸后缀的全名(纪律 9)。
 *
 * 64 位形态只存在于 x86_64: 内核实例与表项一起 #ifdef(i386 侧 15->8 条)。
 *
 * KAT(与 flag/alu 组同一机制): 每个计时内核下面紧跟一行 IB_KT_* 探针 ——
 * 同一条指令、同一操作数拼法, 但只执行 1 次、不进循环, 每组 8 个确定性
 * 输入, 把 {i0,i1,inf,o0,o1,outf} 与编译期真值表(isb_logic_kat.h)逐位比:
 * 表未回填 -> 本次即采集(kat_st=COLLECT + K 附表行), 表已回填 -> OK/KATFAIL。
 * 本组的两处特殊口径(由探针掩码表达, 不影响计时链):
 *   - and/or/xor: AF 在逻辑运算后未定义(SDM) -> 走 IB_FLG_MASK_LOGIC(剔 AF),
 *     否则跨机(尤其 LATX 翻译)会报假不匹配; CF/OF 恒 0 本身就是要比的断言。
 *   - not: 架构承诺不改标志 -> 反倒该拿全掩码 IB_FLG_MASK 上表: outf 应恒等于
 *     inf, 翻译器若把 not 译成会踩标志的实现, 这里就会 KATFAIL。
 */
#include "ib_core.h"
#include "ib_buf.h"
#include "isb_logic_kat.h"    /* KAT 真值表(采集后生成; 未取数时全 UNSET) */

/* ---------------- 64 位形态(仅 x86_64) ---------------- */
#ifdef __x86_64__
/* ---- and_r_r_q: IB_K_RR ---- */
static uint64_t k_and_r_r_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++)                                                      
        __asm__("andq" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_and_r_r_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    IB_UQ c = (IB_UQ)IB_SEED(2), d = (IB_UQ)IB_SEED(3);                                    
    IB_UQ e = (IB_UQ)IB_SEED(4), f = (IB_UQ)IB_SEED(5);                                    
    IB_UQ g = (IB_UQ)IB_SEED(6), h = (IB_UQ)IB_SEED(7);                                    
    for (i = 0; i < it; i++) {                                                    
        __asm__("andq" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
        __asm__("andq" " %[d],%[c]" : [c] "+r"(c) : [d] "r"(d) : "cc");             
        __asm__("andq" " %[f],%[e]" : [e] "+r"(e) : [f] "r"(f) : "cc");             
        __asm__("andq" " %[h],%[g]" : [g] "+r"(g) : [h] "r"(h) : "cc");             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- and_r_r_q: IB_KT_LOGIC ---- */
static inline void k_and_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("and_r_r_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("and_r_r_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("and_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "andq" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK_LOGIC);                                                
}

/* ---- and_r_i_q: IB_K_RI ---- */
static uint64_t k_and_r_i_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("andq" " " IB_IMM ",%[a]" : [a] "+r"(a) : : "cc");                  
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_and_r_i_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("andq" " " IB_IMM ",%[a]" : [a] "+r"(a) : : "cc");                  
        __asm__("andq" " " IB_IMM ",%[c]" : [c] "+r"(c) : : "cc");                  
        __asm__("andq" " " IB_IMM ",%[e]" : [e] "+r"(e) : : "cc");                  
        __asm__("andq" " " IB_IMM ",%[g]" : [g] "+r"(g) : : "cc");                  
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- and_r_i_q: IB_KT_LOGIC ---- */
static inline void k_and_r_i_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("and_r_i_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("and_r_i_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("and_r_i_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "andq" " " IB_IMM ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK_LOGIC);                                                
}

/* ---- or_r_m_q_rip: IB_K_SRC ---- */
static uint64_t k_or_r_m_q_rip(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("orq" " " IB_M_RIP ",%[a]" : [a] "+r"(a) : [p] "r"(p), [ix] "r"(ix)              
                 : "cc", "memory");                                               
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_or_r_m_q_rip_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("orq" " " IB_M_RIP ",%[a]" : [a] "+r"(a) : [p] "r"(p), [ix] "r"(ix)              
                 : "cc", "memory");                                               
        __asm__("orq" " " IB_M_RIP ",%[a]" : [a] "+r"(c) : [p] "r"(p), [ix] "r"(ix)              
                 : "cc", "memory");                                               
        __asm__("orq" " " IB_M_RIP ",%[a]" : [a] "+r"(e) : [p] "r"(p), [ix] "r"(ix)              
                 : "cc", "memory");                                               
        __asm__("orq" " " IB_M_RIP ",%[a]" : [a] "+r"(g) : [p] "r"(p), [ix] "r"(ix)              
                 : "cc", "memory");                                               
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* rip 形态的内存侧改成读 g_kbuf(整窗广播 = i1): 探针要的是「内存里那个值
 * 就是表里记的 i1」, 而 g_rbuf 内容由骨架预置决定 -> 不记入表就不可审 */
/* ---- or_r_m_q_rip: IB_KT_LOGIC ---- */
/* ---- or_r_m_q_rip: IB_KT_FLGA (manually expanded) ---- */
static inline void k_or_r_m_q_rip_kat(int kk, ib_kv *g)
{
    IB_UQ a = (IB_UQ)IB_KIN8("or_r_m_q_rip", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("or_r_m_q_rip", kk, 1, IB_UQ);
    IB_UQ ain = a;
    void *p = ib_kbuf_fill((uint64_t)b);
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);
    uintptr_t fv = (uintptr_t)IB_KFL("or_r_m_q_rip", kk), fl = 0;
    __asm__ volatile(IB_SETF "orq " "g_kbuf+8(%%rip),%[a]" IB_GETF
            : [a] "+r"(a), [fl] "=&r"(fl)
            : [b] "r"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)
            : "cc", "memory");
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b; g->inf = (uint64_t)fv;
    g->o0 = (uint64_t)a; g->o1 = (uint64_t)b;
    g->outf = (uint64_t)fl & (IB_FLG_MASK_LOGIC);
}

static uint64_t k_or_r_r_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++)                                                      
        __asm__("orq" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_or_r_r_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    IB_UQ c = (IB_UQ)IB_SEED(2), d = (IB_UQ)IB_SEED(3);                                    
    IB_UQ e = (IB_UQ)IB_SEED(4), f = (IB_UQ)IB_SEED(5);                                    
    IB_UQ g = (IB_UQ)IB_SEED(6), h = (IB_UQ)IB_SEED(7);                                    
    for (i = 0; i < it; i++) {                                                    
        __asm__("orq" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
        __asm__("orq" " %[d],%[c]" : [c] "+r"(c) : [d] "r"(d) : "cc");             
        __asm__("orq" " %[f],%[e]" : [e] "+r"(e) : [f] "r"(f) : "cc");             
        __asm__("orq" " %[h],%[g]" : [g] "+r"(g) : [h] "r"(h) : "cc");             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- or_r_r_q: IB_KT_LOGIC ---- */
static inline void k_or_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("or_r_r_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("or_r_r_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("or_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "orq" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK_LOGIC);                                                
}

/* ---- or_r_i_q: IB_K_RI ---- */
static uint64_t k_or_r_i_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("orq" " " IB_IMM ",%[a]" : [a] "+r"(a) : : "cc");                  
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_or_r_i_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("orq" " " IB_IMM ",%[a]" : [a] "+r"(a) : : "cc");                  
        __asm__("orq" " " IB_IMM ",%[c]" : [c] "+r"(c) : : "cc");                  
        __asm__("orq" " " IB_IMM ",%[e]" : [e] "+r"(e) : : "cc");                  
        __asm__("orq" " " IB_IMM ",%[g]" : [g] "+r"(g) : : "cc");                  
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- or_r_i_q: IB_KT_LOGIC ---- */
static inline void k_or_r_i_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("or_r_i_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("or_r_i_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("or_r_i_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "orq" " " IB_IMM ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK_LOGIC);                                                
}

/* ---- xor_r_r_q: IB_K_RR ---- */
static uint64_t k_xor_r_r_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++)                                                      
        __asm__("xorq" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_xor_r_r_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    IB_UQ c = (IB_UQ)IB_SEED(2), d = (IB_UQ)IB_SEED(3);                                    
    IB_UQ e = (IB_UQ)IB_SEED(4), f = (IB_UQ)IB_SEED(5);                                    
    IB_UQ g = (IB_UQ)IB_SEED(6), h = (IB_UQ)IB_SEED(7);                                    
    for (i = 0; i < it; i++) {                                                    
        __asm__("xorq" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
        __asm__("xorq" " %[d],%[c]" : [c] "+r"(c) : [d] "r"(d) : "cc");             
        __asm__("xorq" " %[f],%[e]" : [e] "+r"(e) : [f] "r"(f) : "cc");             
        __asm__("xorq" " %[h],%[g]" : [g] "+r"(g) : [h] "r"(h) : "cc");             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- xor_r_r_q: IB_KT_LOGIC ---- */
static inline void k_xor_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("xor_r_r_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("xor_r_r_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("xor_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "xorq" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK_LOGIC);                                                
}

/* ---- not_r_r_q: IB_K_R1 ---- */
static uint64_t k_not_r_r_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("notq" " %[a]" : [a] "+r"(a) : : "cc");                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_not_r_r_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("notq" " %[a]" : [a] "+r"(a) : : "cc");                             
        __asm__("notq" " %[c]" : [c] "+r"(c) : : "cc");                             
        __asm__("notq" " %[e]" : [e] "+r"(e) : : "cc");                             
        __asm__("notq" " %[g]" : [g] "+r"(g) : : "cc");                             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- not_r_r_q: IB_KT_FLG ---- */
static inline void k_not_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("not_r_r_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("not_r_r_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("not_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "notq" " " "%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

#endif

/* ---------------- 两 ABI 共有形态 ---------------- */
/* ---- and_r_i_l: IB_K_RI ---- */
static uint64_t k_and_r_i_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("andl" " " IB_IMM ",%[a]" : [a] "+r"(a) : : "cc");                  
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_and_r_i_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("andl" " " IB_IMM ",%[a]" : [a] "+r"(a) : : "cc");                  
        __asm__("andl" " " IB_IMM ",%[c]" : [c] "+r"(c) : : "cc");                  
        __asm__("andl" " " IB_IMM ",%[e]" : [e] "+r"(e) : : "cc");                  
        __asm__("andl" " " IB_IMM ",%[g]" : [g] "+r"(g) : : "cc");                  
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- and_r_i_l: IB_KT_LOGIC ---- */
static inline void k_and_r_i_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("and_r_i_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("and_r_i_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("and_r_i_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "andl" " " IB_IMM ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK_LOGIC);                                                
}

/* ---- and_r_r_l: IB_K_RR ---- */
static uint64_t k_and_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++)                                                      
        __asm__("andl" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_and_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    IB_UL c = (IB_UL)IB_SEED(2), d = (IB_UL)IB_SEED(3);                                    
    IB_UL e = (IB_UL)IB_SEED(4), f = (IB_UL)IB_SEED(5);                                    
    IB_UL g = (IB_UL)IB_SEED(6), h = (IB_UL)IB_SEED(7);                                    
    for (i = 0; i < it; i++) {                                                    
        __asm__("andl" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
        __asm__("andl" " %[d],%[c]" : [c] "+r"(c) : [d] "r"(d) : "cc");             
        __asm__("andl" " %[f],%[e]" : [e] "+r"(e) : [f] "r"(f) : "cc");             
        __asm__("andl" " %[h],%[g]" : [g] "+r"(g) : [h] "r"(h) : "cc");             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- and_r_r_l: IB_KT_LOGIC ---- */
static inline void k_and_r_r_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("and_r_r_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("and_r_r_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("and_r_r_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "andl" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK_LOGIC);                                                
}

/* ---- or_r_r_l: IB_K_RR ---- */
static uint64_t k_or_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++)                                                      
        __asm__("orl" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_or_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    IB_UL c = (IB_UL)IB_SEED(2), d = (IB_UL)IB_SEED(3);                                    
    IB_UL e = (IB_UL)IB_SEED(4), f = (IB_UL)IB_SEED(5);                                    
    IB_UL g = (IB_UL)IB_SEED(6), h = (IB_UL)IB_SEED(7);                                    
    for (i = 0; i < it; i++) {                                                    
        __asm__("orl" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
        __asm__("orl" " %[d],%[c]" : [c] "+r"(c) : [d] "r"(d) : "cc");             
        __asm__("orl" " %[f],%[e]" : [e] "+r"(e) : [f] "r"(f) : "cc");             
        __asm__("orl" " %[h],%[g]" : [g] "+r"(g) : [h] "r"(h) : "cc");             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- or_r_r_l: IB_KT_LOGIC ---- */
static inline void k_or_r_r_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("or_r_r_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("or_r_r_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("or_r_r_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "orl" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK_LOGIC);                                                
}

/* ---- or_r_r_b: IB_K_RR8 ---- */
static uint64_t k_or_r_r_b(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UB a = (IB_UB)IB_SEED(0), b = (IB_UB)IB_SEED(1);                                    
    for (i = 0; i < it; i++)                                                      
        __asm__("orb" " %[b],%[a]" : [a] "+a"(a) : [b] "b"(b) : "cc");             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_or_r_r_b_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UB a = (IB_UB)IB_SEED(0), b = (IB_UB)IB_SEED(1);                                    
    IB_UB c = (IB_UB)IB_SEED(2), d = (IB_UB)IB_SEED(3);                                    
    for (i = 0; i < it; i++) {                                                    
        __asm__("orb" " %[b],%[a]" : [a] "+a"(a) : [b] "b"(b) : "cc");             
        __asm__("orb" " %[d],%[c]" : [c] "+c"(c) : [d] "d"(d) : "cc");             
    }                                                                             
    return IB_S4(a, b, c, d);                                                     
}

/* ---- or_r_r_b: IB_KT_LOGIC8 ---- */
static inline void k_or_r_r_b_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UB a = (IB_UB)IB_KIN8("or_r_r_b", kk, 0, IB_UB), b = (IB_UB)IB_KIN8("or_r_r_b", kk, 1, IB_UB);            
    IB_UB ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("or_r_r_b", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "orb" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+a"(a), [fl] "=&r"(fl)                                   
                    : [b] "b"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK_LOGIC);                                                
}

/* ---- or_r_i_l: IB_K_RI ---- */
static uint64_t k_or_r_i_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("orl" " " IB_IMM ",%[a]" : [a] "+r"(a) : : "cc");                  
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_or_r_i_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("orl" " " IB_IMM ",%[a]" : [a] "+r"(a) : : "cc");                  
        __asm__("orl" " " IB_IMM ",%[c]" : [c] "+r"(c) : : "cc");                  
        __asm__("orl" " " IB_IMM ",%[e]" : [e] "+r"(e) : : "cc");                  
        __asm__("orl" " " IB_IMM ",%[g]" : [g] "+r"(g) : : "cc");                  
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- or_r_i_l: IB_KT_LOGIC ---- */
static inline void k_or_r_i_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("or_r_i_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("or_r_i_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("or_r_i_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "orl" " " IB_IMM ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK_LOGIC);                                                
}

/* ---- xor_r_r_l: IB_K_RR ---- */
static uint64_t k_xor_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++)                                                      
        __asm__("xorl" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_xor_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    IB_UL c = (IB_UL)IB_SEED(2), d = (IB_UL)IB_SEED(3);                                    
    IB_UL e = (IB_UL)IB_SEED(4), f = (IB_UL)IB_SEED(5);                                    
    IB_UL g = (IB_UL)IB_SEED(6), h = (IB_UL)IB_SEED(7);                                    
    for (i = 0; i < it; i++) {                                                    
        __asm__("xorl" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
        __asm__("xorl" " %[d],%[c]" : [c] "+r"(c) : [d] "r"(d) : "cc");             
        __asm__("xorl" " %[f],%[e]" : [e] "+r"(e) : [f] "r"(f) : "cc");             
        __asm__("xorl" " %[h],%[g]" : [g] "+r"(g) : [h] "r"(h) : "cc");             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- xor_r_r_l: IB_KT_LOGIC ---- */
static inline void k_xor_r_r_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("xor_r_r_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("xor_r_r_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("xor_r_r_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "xorl" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK_LOGIC);                                                
}

/* ---- not_r_r_l: IB_K_R1 ---- */
static uint64_t k_not_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("notl" " %[a]" : [a] "+r"(a) : : "cc");                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_not_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("notl" " %[a]" : [a] "+r"(a) : : "cc");                             
        __asm__("notl" " %[c]" : [c] "+r"(c) : : "cc");                             
        __asm__("notl" " %[e]" : [e] "+r"(e) : : "cc");                             
        __asm__("notl" " %[g]" : [g] "+r"(g) : : "cc");                             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- not_r_r_l: IB_KT_FLG ---- */
static inline void k_not_r_r_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("not_r_r_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("not_r_r_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("not_r_r_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "notl" " " "%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- not_r_r_b: IB_K_R18 ---- */
static uint64_t k_not_r_r_b(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UB a = (IB_UB)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("notb" " %[a]" : [a] "+a"(a) : : "cc");                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_not_r_r_b_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UB a = (IB_UB)IB_SEED(0), c = (IB_UB)IB_SEED(2);                                    
    for (i = 0; i < it; i++) {                                                    
        __asm__("notb" " %[a]" : [a] "+a"(a) : : "cc");                             
        __asm__("notb" " %[c]" : [c] "+c"(c) : : "cc");                             
    }                                                                             
    return IB_S2(a, c);                                                           
}

/* ---- not_r_r_b: IB_KT_FLG8 ---- */
static inline void k_not_r_r_b_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UB a = (IB_UB)IB_KIN8("not_r_r_b", kk, 0, IB_UB), b = (IB_UB)IB_KIN8("not_r_r_b", kk, 1, IB_UB);            
    IB_UB ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("not_r_r_b", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "notb" " " "%[a]" IB_GETF                                   
                    : [a] "+a"(a), [fl] "=&r"(fl)                                   
                    : [b] "b"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}


/* ---------------- 用例表(bpop = 每 op 处理字节数) ---------------- */
static const ib_case g_cases[] = {
    /* 两 ABI 共有 */
    IB_ROW_K("x86_and__r_i_l",        NULL, and_r_i_l,        4),
    IB_ROW_K("x86_and__r_r_l",        NULL, and_r_r_l,        4),
    IB_ROW_K("x86_or__r_r_l",         NULL, or_r_r_l,         4),
    IB_ROW_K("x86_or__r_r_b",         NULL, or_r_r_b,         1),
    IB_ROW_K("x86_or__r_i_l",         NULL, or_r_i_l,         4),
    IB_ROW_K("x86_xor__r_r_l",        NULL, xor_r_r_l,        4),
    IB_ROW_K("x86_not__r_r_l",        NULL, not_r_r_l,        0),
    IB_ROW_K("x86_not__r_r_b",        NULL, not_r_r_b,        1),
#ifdef __x86_64__
    /* 64 位专有形态 */
    IB_ROW_K("x86_and__r_r_q",        NULL, and_r_r_q,        8),
    IB_ROW_K("x86_and__r_i_q",        NULL, and_r_i_q,        8),
    IB_ROW_K("x86_or__r_m_q_rip",     NULL, or_r_m_q_rip,     8),
    IB_ROW_K("x86_or__r_r_q",         NULL, or_r_r_q,         8),
    IB_ROW_K("x86_or__r_i_q",         NULL, or_r_i_q,         8),
    IB_ROW_K("x86_xor__r_r_q",        NULL, xor_r_r_q,        8),
    IB_ROW_K("x86_not__r_r_q",        NULL, not_r_r_q,        0),
#endif
};
#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

int main(int argc, char **argv)
{
    ib_init(argc, argv);
    ib_abuf_init();                 /* 只读/写区确定性预置(签名跨机可复现的前提) */
    ib_hdr("logic", NCASES);
    ib_run_cases("logic", g_cases, NCASES);
    return 0;
}
