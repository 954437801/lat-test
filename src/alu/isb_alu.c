/* isb_alu.c —— 算术家族形态组(grp=alu): add/sub/inc/dec/neg/adc/sbb/mul/imul/div/idiv
 *
 * 用例来源 = 实测 三层映射 round5_form_weights.csv 里这些助记符的 k90 形态,
 * 共 31 条(全量采样的 8.67%); case 名 = x86_<助记符>__<形态段> 与 form_key 1:1。
 * 与计划表的 30 条差 1: 计划按 imul 3 形态估算, 实测 imul 的 k90 = 4 形态
 * (r.i.q 0.0381% / r.m.q/base 0.0347% / r.r.q 0.0340% / r.i.l 0.0129%), 按
 * 「粒度 = 形态级 Pareto-90%」的规则取实测 4 条。
 * 另 div 在 CSV 里 nf=0(采样窗内没抓到 div 的形态), 但 idiv 有 2 条且 div 是
 * x86 唯一会 #DE 的算术指令 -> 计划要求保留 1 条 div r..q 作为异常路径锚点。
 *
 * 与 flag 组的分工: flag 组的 cmp/test 只产标志; 本组的指令把结果写回寄存器或
 * 内存, 所以 lat 链直接走「结果 -> 下一轮同一指令的输入」, 不需要 adc 回灌。
 *
 * 骨架(每模板恒定, 被测占 1 条):
 *   r.r/r.i/单目    1 条被测(IB_K_RR/RI/R1), tput 4 条独立链
 *   r.m(op mem,reg) 1 条被测(IB_K_SRC)
 *   m.m(inc/dec 内存自增) IB_K_SOM: 固定写槽 + 清 0 + 出口读回 -> 内存串行链
 *                   (TY 必传与 SUF 同宽的整数型, 否则回读 mov<SUF>,%[x] 在
 *                    x86_64 撞上 %rax / 在 i386 撞上偶奇寄存器对)
 *   adc/sbb         IB_K_ADC: 每轮先 cmp 重建 CF(否则 CF 初值不定)再被测
 *   mul/imul        IB_K_ACC/RR/R3/SRC
 *   div/idiv        IB_K_DIV: 每轮必须清 %rdx 再回灌被除数 —— 上一轮余数留在
 *                   %rdx 会让下一轮 rdx:rax 变大 -> 商溢出 #DE(SIGFPE) 整组崩
 *                   (这就是 div/idiv 必须单独模板、且表项必须配 lits 的原因)
 *
 * 64 位形态只存在于 x86_64: 内核实例、探针实例与表项一起 #ifdef
 * (i386 侧 31->15 条)。
 *
 * KAT(编译期真值对拍, 与 flag 组同一机制): 每个计时内核下面紧跟一行
 * IB_KT_* 探针 —— 同一条指令、同一操作数拼法, 但只执行 1 次、不进循环,
 * 把 {i0,i1,inf,o0,o1,outf} 与 isb_alu_kat.h 逐位比。表未回填 -> 本次运行即
 * 采集(kat_st=COLLECT + K 附表行); 表已回填 -> OK/KATFAIL, 被测机(LATX 翻译机)
 * 不需采集也不需对拍。标志上表范围按指令选: add/sub/adc/sbb/inc/dec/neg 六个
 * 全上, imul/mul 只 CF/OF, div/idiv 全未定义 -> outf 恒 0(否则跨机假不匹配)。
 */
#include "ib_core.h"
#include "ib_buf.h"
#include "isb_alu_kat.h"      /* KAT 真值表(采集后生成; 未取数时全 UNSET) */

/* ---------------- 64 位形态(仅 x86_64) ---------------- */
/* 每行下面是它的 KAT 探针(IB_KT_*): 同一条指令、同一操作数拼法, 但只执行 1 次
 * 且不进任何循环。两边机器跑同一探针 -> 输入由词干哈希重导, 输出跟表比。 */
#ifdef __x86_64__
/* ---- add_r_r_q: IB_K_RR ---- */
static uint64_t k_add_r_r_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++)                                                      
        __asm__("addq" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_add_r_r_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    IB_UQ c = (IB_UQ)IB_SEED(2), d = (IB_UQ)IB_SEED(3);                                    
    IB_UQ e = (IB_UQ)IB_SEED(4), f = (IB_UQ)IB_SEED(5);                                    
    IB_UQ g = (IB_UQ)IB_SEED(6), h = (IB_UQ)IB_SEED(7);                                    
    for (i = 0; i < it; i++) {                                                    
        __asm__("addq" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
        __asm__("addq" " %[d],%[c]" : [c] "+r"(c) : [d] "r"(d) : "cc");             
        __asm__("addq" " %[f],%[e]" : [e] "+r"(e) : [f] "r"(f) : "cc");             
        __asm__("addq" " %[h],%[g]" : [g] "+r"(g) : [h] "r"(h) : "cc");             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- add_r_r_q: IB_KT_FLG ---- */
static inline void k_add_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("add_r_r_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("add_r_r_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("add_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "addq" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- add_r_i_q: IB_K_RI ---- */
static uint64_t k_add_r_i_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("addq" " " IB_IMM ",%[a]" : [a] "+r"(a) : : "cc");                  
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_add_r_i_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("addq" " " IB_IMM ",%[a]" : [a] "+r"(a) : : "cc");                  
        __asm__("addq" " " IB_IMM ",%[c]" : [c] "+r"(c) : : "cc");                  
        __asm__("addq" " " IB_IMM ",%[e]" : [e] "+r"(e) : : "cc");                  
        __asm__("addq" " " IB_IMM ",%[g]" : [g] "+r"(g) : : "cc");                  
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- add_r_i_q: IB_KT_FLG ---- */
static inline void k_add_r_i_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("add_r_i_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("add_r_i_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("add_r_i_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "addq" " " IB_IMM ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- sub_r_i_q: IB_K_RI ---- */
static uint64_t k_sub_r_i_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("subq" " " IB_IMM ",%[a]" : [a] "+r"(a) : : "cc");                  
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_sub_r_i_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("subq" " " IB_IMM ",%[a]" : [a] "+r"(a) : : "cc");                  
        __asm__("subq" " " IB_IMM ",%[c]" : [c] "+r"(c) : : "cc");                  
        __asm__("subq" " " IB_IMM ",%[e]" : [e] "+r"(e) : : "cc");                  
        __asm__("subq" " " IB_IMM ",%[g]" : [g] "+r"(g) : : "cc");                  
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- sub_r_i_q: IB_KT_FLG ---- */
static inline void k_sub_r_i_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("sub_r_i_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("sub_r_i_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("sub_r_i_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "subq" " " IB_IMM ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- sub_r_r_q: IB_K_RR ---- */
static uint64_t k_sub_r_r_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++)                                                      
        __asm__("subq" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_sub_r_r_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    IB_UQ c = (IB_UQ)IB_SEED(2), d = (IB_UQ)IB_SEED(3);                                    
    IB_UQ e = (IB_UQ)IB_SEED(4), f = (IB_UQ)IB_SEED(5);                                    
    IB_UQ g = (IB_UQ)IB_SEED(6), h = (IB_UQ)IB_SEED(7);                                    
    for (i = 0; i < it; i++) {                                                    
        __asm__("subq" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
        __asm__("subq" " %[d],%[c]" : [c] "+r"(c) : [d] "r"(d) : "cc");             
        __asm__("subq" " %[f],%[e]" : [e] "+r"(e) : [f] "r"(f) : "cc");             
        __asm__("subq" " %[h],%[g]" : [g] "+r"(g) : [h] "r"(h) : "cc");             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- sub_r_r_q: IB_KT_FLG ---- */
static inline void k_sub_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("sub_r_r_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("sub_r_r_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("sub_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "subq" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- inc_r_r_q: IB_K_R1 ---- */
static uint64_t k_inc_r_r_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("incq" " %[a]" : [a] "+r"(a) : : "cc");                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_inc_r_r_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("incq" " %[a]" : [a] "+r"(a) : : "cc");                             
        __asm__("incq" " %[c]" : [c] "+r"(c) : : "cc");                             
        __asm__("incq" " %[e]" : [e] "+r"(e) : : "cc");                             
        __asm__("incq" " %[g]" : [g] "+r"(g) : : "cc");                             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- inc_r_r_q: IB_KT_FLG ---- */
static inline void k_inc_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("inc_r_r_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("inc_r_r_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("inc_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "incq" " " "%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- inc_m_m_q_base: IB_K_SOM ---- */
static uint64_t k_inc_m_m_q_base(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ x = 0;                                                                     
    void *w = (void *)IB_WBASE();                                                 
    uintptr_t ix = 0;                                                             
    __asm__ volatile("mov" "q" " $0," IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory"); 
    for (i = 0; i < it; i++)                                                      
        __asm__("incq" " " IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory", "cc");        
    __asm__ volatile("mov" "q" " " IB_W_BASE ",%[x]"                                    
                     : [x] "=r"(x) : [w] "r"(w), [ix] "r"(ix) : "memory");          
    return (uint64_t)x;                                                           
}                                                                                 
static uint64_t k_inc_m_m_q_base_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ x = 0;                                                                     
    void *w = (void *)IB_WBASE();                                                 
    uintptr_t ix = 0;                                                             
    __asm__ volatile("mov" "q" " $0," IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory"); 
    for (i = 0; i < it; i++) {                                                    
        __asm__("incq" " " IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory", "cc");        
        __asm__("incq" " " IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory", "cc");        
        __asm__("incq" " " IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory", "cc");        
        __asm__("incq" " " IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory", "cc");        
    }                                                                             
    __asm__ volatile("mov" "q" " " IB_W_BASE ",%[x]"                                    
                     : [x] "=r"(x) : [w] "r"(w), [ix] "r"(ix) : "memory");          
    return (uint64_t)x;                                                           
}

/* ---- inc_m_m_q_base: IB_KT_SOM ---- */
static inline void k_inc_m_m_q_base_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ i0 = (IB_UQ)IB_KIN8("inc_m_m_q_base", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("inc_m_m_q_base", kk, 1, IB_UQ);           
    void *w = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("inc_m_m_q_base", kk), fl = 0;                              
    IB_UQ x = 0;                                                                      
    __asm__ volatile(IB_SETF "mov" "q" " %[i0]," IB_W_BASE "\n\t" "incq" " " IB_W_BASE              
                     IB_GETF "\n\tmov" "q" " " IB_W_BASE ",%[x]"                            
                    : [x] "=&r"(x), [fl] "=&r"(fl)                                   
                    : [i0] "r"(i0), [w] "r"(w), [ix] "r"(ix), [fv] "r"(fv)            
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)i0; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;              
    g->o0 = (uint64_t)x;  g->o1 = (uint64_t)x;                                      
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                           
}

/* ---- dec_r_r_q: IB_K_R1 ---- */
static uint64_t k_dec_r_r_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("decq" " %[a]" : [a] "+r"(a) : : "cc");                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_dec_r_r_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("decq" " %[a]" : [a] "+r"(a) : : "cc");                             
        __asm__("decq" " %[c]" : [c] "+r"(c) : : "cc");                             
        __asm__("decq" " %[e]" : [e] "+r"(e) : : "cc");                             
        __asm__("decq" " %[g]" : [g] "+r"(g) : : "cc");                             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- dec_r_r_q: IB_KT_FLG ---- */
static inline void k_dec_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("dec_r_r_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("dec_r_r_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("dec_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "decq" " " "%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- neg_r_r_q: IB_K_R1 ---- */
static uint64_t k_neg_r_r_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("negq" " %[a]" : [a] "+r"(a) : : "cc");                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_neg_r_r_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("negq" " %[a]" : [a] "+r"(a) : : "cc");                             
        __asm__("negq" " %[c]" : [c] "+r"(c) : : "cc");                             
        __asm__("negq" " %[e]" : [e] "+r"(e) : : "cc");                             
        __asm__("negq" " %[g]" : [g] "+r"(g) : : "cc");                             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- neg_r_r_q: IB_KT_FLG ---- */
static inline void k_neg_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("neg_r_r_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("neg_r_r_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("neg_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "negq" " " "%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* adc/sbb 读 CF 当输入: 计时骨架用 cmp 重建 CF, 探针则直接 IB_SETF 注入(更诚实) */
/* ---- adc_r_r_q: IB_K_ADC ---- */
static uint64_t k_adc_r_r_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("" "\n\t" "cmp" "q" " $1,%[a]\n\t" "adcq" " " "%[b],%[a]"                   
                : [a] "+a"(a) : [b] "b"(b), [p] "r"(p), [ix] "r"(ix)                
                : "cc", "memory");                                                
    }                                                                             
    return IB_S1(a);                                                              
}                                                                                 
static uint64_t k_adc_r_r_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), b = (IB_UQ)IB_SEED(1),                
       d = (IB_UQ)IB_SEED(3);                                                        
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("" "\n\t" "cmp" "q" " $1,%[a]\n\t" "adcq" " " "%[b],%[a]"                   
                : [a] "+a"(a) : [b] "b"(b), [p] "r"(p), [ix] "r"(ix)              
                : "cc", "memory");                                                
        /* 第二链: 操作数**名字**必须与 "%[b],%[a]" 里引的一致([a]/[b]), 只换绑定的变量 */ 
        __asm__("" "\n\t" "cmp" "q" " $1,%[a]\n\t" "adcq" " " "%[b],%[a]"                   
                : [a] "+c"(c) : [b] "d"(d), [p] "r"(p), [ix] "r"(ix)              
                : "cc", "memory");                                                
    }                                                                             
    return IB_S2(a, c);                                                           
}

/* ---- adc_r_r_q: IB_KT_FLG ---- */
static inline void k_adc_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("adc_r_r_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("adc_r_r_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("adc_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "adcq" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+a"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* 被测读栈槽 -> 预置必须在同一个 asm 块内(见骨架注), 探针用 IB_KT_FLG8P 同形 */
/* ---- adc_r_m_q_base_sp: IB_K_ADC ---- */
static uint64_t k_adc_r_m_q_base_sp(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("movq $0x5a5a5a," IB_M_SP "\n\t" "cmp" "q" " $1,%[a]\n\t" "adcq" " " IB_M_SP ",%[a]"                   
                : [a] "+a"(a) : [b] "b"(b), [p] "r"(p), [ix] "r"(ix)                
                : "cc", "memory");                                                
    }                                                                             
    return IB_S1(a);                                                              
}                                                                                 
static uint64_t k_adc_r_m_q_base_sp_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), b = (IB_UQ)IB_SEED(1),                
       d = (IB_UQ)IB_SEED(3);                                                        
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("movq $0x5a5a5a," IB_M_SP "\n\t" "cmp" "q" " $1,%[a]\n\t" "adcq" " " IB_M_SP ",%[a]"                   
                : [a] "+a"(a) : [b] "b"(b), [p] "r"(p), [ix] "r"(ix)              
                : "cc", "memory");                                                
        /* 第二链: 操作数**名字**必须与 IB_M_SP ",%[a]" 里引的一致([a]/[b]), 只换绑定的变量 */ 
        __asm__("movq $0x5a5a5a," IB_M_SP "\n\t" "cmp" "q" " $1,%[a]\n\t" "adcq" " " IB_M_SP ",%[a]"                   
                : [a] "+c"(c) : [b] "d"(d), [p] "r"(p), [ix] "r"(ix)              
                : "cc", "memory");                                                
    }                                                                             
    return IB_S2(a, c);                                                           
}

/* ---- adc_r_m_q_base_sp: IB_KT_FLG8P ---- */
static inline void k_adc_r_m_q_base_sp_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("adc_r_m_q_base_sp", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("adc_r_m_q_base_sp", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("adc_r_m_q_base_sp", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "mov" "q" " %[b], " IB_M_SP "\n\t" "adcq" " " IB_M_SP ",%[a]" IB_GETF      
                    : [a] "+a"(a), [fl] "=&r"(fl)                                   
                    : [b] "q"(b), [p] "r"(p), [fv] "r"(fv) : "cc", "memory");         
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                           
}

/* ---- mul_r__q: IB_K_ACC ---- */
static uint64_t k_mul_r__q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)((IB_SEED(0) & 0xffff) | 1), b = (IB_UQ)((IB_SEED(1) & 0xffff) | 3);  
    IB_UQ dl = (IB_UQ)0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("mulq" " %[b]" : "+a"(a), "+d"(dl) : [b] "r"(b) : "cc");            
    return IB_S2(a, dl);                                                          
}                                                                                 
static uint64_t k_mul_r__q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)((IB_SEED(0) & 0xffff) | 1), b = (IB_UQ)((IB_SEED(1) & 0xffff) | 3);  
    IB_UQ dl = (IB_UQ)0;                                                                
    for (i = 0; i < it; i++) {                                                    
        __asm__("mulq" " %[b]" : "+a"(a), "+d"(dl) : [b] "r"(b) : "cc");            
        __asm__("mulq" " %[b]" : "+a"(a), "+d"(dl) : [b] "r"(b) : "cc");            
        __asm__("mulq" " %[b]" : "+a"(a), "+d"(dl) : [b] "r"(b) : "cc");            
        __asm__("mulq" " %[b]" : "+a"(a), "+d"(dl) : [b] "r"(b) : "cc");            
    }                                                                             
    return IB_S2(a, dl);                                                          
}

/* ---- mul_r__q: IB_KT_MUL ---- */
static inline void k_mul_r__q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)(IB_KIN("mul_r__q", kk, 0) | 1), b = (IB_UQ)(IB_KIN("mul_r__q", kk, 1) | 3);          
    IB_UQ ain = a, bin = b, d = (IB_UQ)0;                                                
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("mul_r__q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "xor" "q" " %[d],%[d]\n\t" "mulq" " " "%[b]" IB_GETF          
                    : [a] "+a"(a), [d] "+d"(d), [fl] "=&r"(fl)                       
                    : [b] "r"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)              
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)bin;   g->inf = (uint64_t)fv;           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)d;                                      
    g->outf = (uint64_t)fl & IB_FLG_MASK_CFOF;                                      
}

/* ---- imul_r_i_q: IB_K_R3 ---- */
static uint64_t k_imul_r_i_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)(IB_SEED(1) | 3), c = (IB_UQ)IB_SEED(2);          
    for (i = 0; i < it; i++)                                                      
        __asm__("imulq" " " "$5,%[b],%[a]" : [a] "+r"(a) : [b] "r"(b), [c] "r"(c) : "cc");      
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_imul_r_i_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2);                                    
    IB_UQ b = (IB_UQ)(IB_SEED(1) | 3), d = (IB_UQ)IB_SEED(3);                              
    for (i = 0; i < it; i++) {                                                    
        __asm__("imulq" " " "$5,%[b],%[a]" : [a] "+r"(a) : [b] "r"(b), [c] "r"(c) : "cc");      
        __asm__("imulq" " " "$5,%[b],%[a]" : [a] "+r"(c) : [b] "r"(b), [c] "r"(d) : "cc");      
    }                                                                             
    return IB_S2(a, c);                                                           
}

/* ---- imul_r_i_q: IB_KT_FLGO ---- */
static inline void k_imul_r_i_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("imul_r_i_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("imul_r_i_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("imul_r_i_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "imulq" " " "$5,%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK_CFOF);                                                
}

/* ---- imul_r_m_q_base: IB_K_SRC ---- */
static uint64_t k_imul_r_m_q_base(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("imulq" " " IB_M_BASE ",%[a]" : [a] "+r"(a) : [p] "r"(p), [ix] "r"(ix)              
                 : "cc", "memory");                                               
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_imul_r_m_q_base_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("imulq" " " IB_M_BASE ",%[a]" : [a] "+r"(a) : [p] "r"(p), [ix] "r"(ix)              
                 : "cc", "memory");                                               
        __asm__("imulq" " " IB_M_BASE ",%[a]" : [a] "+r"(c) : [p] "r"(p), [ix] "r"(ix)              
                 : "cc", "memory");                                               
        __asm__("imulq" " " IB_M_BASE ",%[a]" : [a] "+r"(e) : [p] "r"(p), [ix] "r"(ix)              
                 : "cc", "memory");                                               
        __asm__("imulq" " " IB_M_BASE ",%[a]" : [a] "+r"(g) : [p] "r"(p), [ix] "r"(ix)              
                 : "cc", "memory");                                               
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- imul_r_m_q_base: IB_KT_FLGO ---- */
static inline void k_imul_r_m_q_base_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("imul_r_m_q_base", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("imul_r_m_q_base", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("imul_r_m_q_base", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "imulq" " " IB_M_BASE ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK_CFOF);                                                
}

/* ---- imul_r_r_q: IB_K_RR ---- */
static uint64_t k_imul_r_r_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++)                                                      
        __asm__("imulq" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_imul_r_r_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    IB_UQ c = (IB_UQ)IB_SEED(2), d = (IB_UQ)IB_SEED(3);                                    
    IB_UQ e = (IB_UQ)IB_SEED(4), f = (IB_UQ)IB_SEED(5);                                    
    IB_UQ g = (IB_UQ)IB_SEED(6), h = (IB_UQ)IB_SEED(7);                                    
    for (i = 0; i < it; i++) {                                                    
        __asm__("imulq" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
        __asm__("imulq" " %[d],%[c]" : [c] "+r"(c) : [d] "r"(d) : "cc");             
        __asm__("imulq" " %[f],%[e]" : [e] "+r"(e) : [f] "r"(f) : "cc");             
        __asm__("imulq" " %[h],%[g]" : [g] "+r"(g) : [h] "r"(h) : "cc");             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- imul_r_r_q: IB_KT_FLGO ---- */
static inline void k_imul_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("imul_r_r_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("imul_r_r_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("imul_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "imulq" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK_CFOF);                                                
}

/* ---- div_r__q: IB_K_DIV ---- */
static uint64_t k_div_r__q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)((IB_SEED(0) & 0xffff) | 1), b = (IB_UQ)((IB_SEED(1) & 0xffff) | 3);  
    IB_UQ d = (IB_UQ)0;                                                                 
    const void *p = (const void *)IB_RBASE();                                      
    for (i = 0; i < it; i++)                                                      
        __asm__("xor" "q" " %[d],%[d]\n\tadd" "q" " $1,%[a]\n\t"                   
                "div" " " "%[b]"                                                      
                : [a] "+a"(a), [d] "+d"(d)                                        
                : [b] "r"(b), [p] "r"(p), [ix] "r"((uintptr_t)0)                   
                : "cc", "memory");                                                
    return IB_S2(a, d);                                                           
}                                                                                 
static uint64_t k_div_r__q_tp(unsigned long long it)                                
{                                                                                 
    return k_div_r__q(it);                                                            
}

/* ---- div_r__q: IB_KT_DIV ---- */
static inline void k_div_r__q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)((IB_KIN("div_r__q", kk, 0) & 0xffffULL) | 1);                             
    IB_UQ b = (IB_UQ)((IB_KIN("div_r__q", kk, 1) & 0xffffULL) | 3);                             
    IB_UQ ain = a, bin = b, d = (IB_UQ)0;                                                
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("div_r__q", kk);                                      
    __asm__ volatile(IB_SETF "xor" "q" " %[d],%[d]\n\t" "div" " " "%[b]"                  
                    : [a] "+a"(a), [d] "+d"(d)                                      
                    : [b] "r"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)              
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)bin;   g->inf = (uint64_t)fv;           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)d;   g->outf = 0;                       
}

/* rip 形态的除数改成读 g_kbuf(整窗广播 = 除数 b): 探针要的是「除数已知非 0」,
 * 而 g_rbuf 的内容由骨架预置决定, 不保证非 0 -> 上表会随机 #DE */
/* ---- idiv_m__q_rip: IB_K_DIV ---- */
static uint64_t k_idiv_m__q_rip(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)((IB_SEED(0) & 0xffff) | 1), b = (IB_UQ)((IB_SEED(1) & 0xffff) | 3);  
    IB_UQ d = (IB_UQ)0;                                                                 
    const void *p = (const void *)IB_RBASE();                                      
    for (i = 0; i < it; i++)                                                      
        __asm__("xor" "q" " %[d],%[d]\n\tadd" "q" " $1,%[a]\n\t"                   
                "idivq" " " IB_M_RIP                                                      
                : [a] "+a"(a), [d] "+d"(d)                                        
                : [b] "r"(b), [p] "r"(p), [ix] "r"((uintptr_t)0)                   
                : "cc", "memory");                                                
    return IB_S2(a, d);                                                           
}                                                                                 
static uint64_t k_idiv_m__q_rip_tp(unsigned long long it)                                
{                                                                                 
    return k_idiv_m__q_rip(it);                                                            
}

/* ---- idiv_m__q_rip: IB_KT_DIV ---- */
static inline void k_idiv_m__q_rip_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)((IB_KIN("idiv_m__q_rip", kk, 0) & 0xffffULL) | 1);                             
    IB_UQ b = (IB_UQ)((IB_KIN("idiv_m__q_rip", kk, 1) & 0xffffULL) | 3);                             
    IB_UQ ain = a, bin = b, d = (IB_UQ)0;                                                
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("idiv_m__q_rip", kk);                                      
    __asm__ volatile(IB_SETF "xor" "q" " %[d],%[d]\n\t" "idivq" " " "g_kbuf+8(%%rip)"                  
                    : [a] "+a"(a), [d] "+d"(d)                                      
                    : [b] "r"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)              
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)bin;   g->inf = (uint64_t)fv;           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)d;   g->outf = 0;                       
}

#endif

/* ---------------- 两 ABI 共有形态 ---------------- */
/* ---- add_r_i_l: IB_K_RI ---- */
static uint64_t k_add_r_i_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("addl" " " IB_IMM ",%[a]" : [a] "+r"(a) : : "cc");                  
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_add_r_i_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("addl" " " IB_IMM ",%[a]" : [a] "+r"(a) : : "cc");                  
        __asm__("addl" " " IB_IMM ",%[c]" : [c] "+r"(c) : : "cc");                  
        __asm__("addl" " " IB_IMM ",%[e]" : [e] "+r"(e) : : "cc");                  
        __asm__("addl" " " IB_IMM ",%[g]" : [g] "+r"(g) : : "cc");                  
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- add_r_i_l: IB_KT_FLG ---- */
static inline void k_add_r_i_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("add_r_i_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("add_r_i_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("add_r_i_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "addl" " " IB_IMM ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- add_r_r_l: IB_K_RR ---- */
static uint64_t k_add_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++)                                                      
        __asm__("addl" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_add_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    IB_UL c = (IB_UL)IB_SEED(2), d = (IB_UL)IB_SEED(3);                                    
    IB_UL e = (IB_UL)IB_SEED(4), f = (IB_UL)IB_SEED(5);                                    
    IB_UL g = (IB_UL)IB_SEED(6), h = (IB_UL)IB_SEED(7);                                    
    for (i = 0; i < it; i++) {                                                    
        __asm__("addl" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
        __asm__("addl" " %[d],%[c]" : [c] "+r"(c) : [d] "r"(d) : "cc");             
        __asm__("addl" " %[f],%[e]" : [e] "+r"(e) : [f] "r"(f) : "cc");             
        __asm__("addl" " %[h],%[g]" : [g] "+r"(g) : [h] "r"(h) : "cc");             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- add_r_r_l: IB_KT_FLG ---- */
static inline void k_add_r_r_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("add_r_r_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("add_r_r_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("add_r_r_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "addl" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- sub_r_r_l: IB_K_RR ---- */
static uint64_t k_sub_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++)                                                      
        __asm__("subl" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_sub_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    IB_UL c = (IB_UL)IB_SEED(2), d = (IB_UL)IB_SEED(3);                                    
    IB_UL e = (IB_UL)IB_SEED(4), f = (IB_UL)IB_SEED(5);                                    
    IB_UL g = (IB_UL)IB_SEED(6), h = (IB_UL)IB_SEED(7);                                    
    for (i = 0; i < it; i++) {                                                    
        __asm__("subl" " %[b],%[a]" : [a] "+r"(a) : [b] "r"(b) : "cc");             
        __asm__("subl" " %[d],%[c]" : [c] "+r"(c) : [d] "r"(d) : "cc");             
        __asm__("subl" " %[f],%[e]" : [e] "+r"(e) : [f] "r"(f) : "cc");             
        __asm__("subl" " %[h],%[g]" : [g] "+r"(g) : [h] "r"(h) : "cc");             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- sub_r_r_l: IB_KT_FLG ---- */
static inline void k_sub_r_r_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("sub_r_r_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("sub_r_r_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("sub_r_r_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "subl" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- sub_r_i_l: IB_K_RI ---- */
static uint64_t k_sub_r_i_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("subl" " " IB_IMM ",%[a]" : [a] "+r"(a) : : "cc");                  
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_sub_r_i_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("subl" " " IB_IMM ",%[a]" : [a] "+r"(a) : : "cc");                  
        __asm__("subl" " " IB_IMM ",%[c]" : [c] "+r"(c) : : "cc");                  
        __asm__("subl" " " IB_IMM ",%[e]" : [e] "+r"(e) : : "cc");                  
        __asm__("subl" " " IB_IMM ",%[g]" : [g] "+r"(g) : : "cc");                  
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- sub_r_i_l: IB_KT_FLG ---- */
static inline void k_sub_r_i_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("sub_r_i_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("sub_r_i_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("sub_r_i_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "subl" " " IB_IMM ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- inc_r_r_l: IB_K_R1 ---- */
static uint64_t k_inc_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("incl" " %[a]" : [a] "+r"(a) : : "cc");                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_inc_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("incl" " %[a]" : [a] "+r"(a) : : "cc");                             
        __asm__("incl" " %[c]" : [c] "+r"(c) : : "cc");                             
        __asm__("incl" " %[e]" : [e] "+r"(e) : : "cc");                             
        __asm__("incl" " %[g]" : [g] "+r"(g) : : "cc");                             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- inc_r_r_l: IB_KT_FLG ---- */
static inline void k_inc_r_r_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("inc_r_r_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("inc_r_r_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("inc_r_r_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "incl" " " "%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- inc_m_m_l_base: IB_K_SOM ---- */
static uint64_t k_inc_m_m_l_base(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL x = 0;                                                                     
    void *w = (void *)IB_WBASE();                                                 
    uintptr_t ix = 0;                                                             
    __asm__ volatile("mov" "l" " $0," IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory"); 
    for (i = 0; i < it; i++)                                                      
        __asm__("incl" " " IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory", "cc");        
    __asm__ volatile("mov" "l" " " IB_W_BASE ",%[x]"                                    
                     : [x] "=r"(x) : [w] "r"(w), [ix] "r"(ix) : "memory");          
    return (uint64_t)x;                                                           
}                                                                                 
static uint64_t k_inc_m_m_l_base_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL x = 0;                                                                     
    void *w = (void *)IB_WBASE();                                                 
    uintptr_t ix = 0;                                                             
    __asm__ volatile("mov" "l" " $0," IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory"); 
    for (i = 0; i < it; i++) {                                                    
        __asm__("incl" " " IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory", "cc");        
        __asm__("incl" " " IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory", "cc");        
        __asm__("incl" " " IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory", "cc");        
        __asm__("incl" " " IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory", "cc");        
    }                                                                             
    __asm__ volatile("mov" "l" " " IB_W_BASE ",%[x]"                                    
                     : [x] "=r"(x) : [w] "r"(w), [ix] "r"(ix) : "memory");          
    return (uint64_t)x;                                                           
}

/* ---- inc_m_m_l_base: IB_KT_SOM ---- */
static inline void k_inc_m_m_l_base_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL i0 = (IB_UL)IB_KIN8("inc_m_m_l_base", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("inc_m_m_l_base", kk, 1, IB_UL);           
    void *w = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("inc_m_m_l_base", kk), fl = 0;                              
    IB_UL x = 0;                                                                      
    __asm__ volatile(IB_SETF "mov" "l" " %[i0]," IB_W_BASE "\n\t" "incl" " " IB_W_BASE              
                     IB_GETF "\n\tmov" "l" " " IB_W_BASE ",%[x]"                            
                    : [x] "=&r"(x), [fl] "=&r"(fl)                                   
                    : [i0] "r"(i0), [w] "r"(w), [ix] "r"(ix), [fv] "r"(fv)            
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)i0; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;              
    g->o0 = (uint64_t)x;  g->o1 = (uint64_t)x;                                      
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                           
}

/* ---- dec_r_r_l: IB_K_R1 ---- */
static uint64_t k_dec_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("decl" " %[a]" : [a] "+r"(a) : : "cc");                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_dec_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("decl" " %[a]" : [a] "+r"(a) : : "cc");                             
        __asm__("decl" " %[c]" : [c] "+r"(c) : : "cc");                             
        __asm__("decl" " %[e]" : [e] "+r"(e) : : "cc");                             
        __asm__("decl" " %[g]" : [g] "+r"(g) : : "cc");                             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- dec_r_r_l: IB_KT_FLG ---- */
static inline void k_dec_r_r_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("dec_r_r_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("dec_r_r_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("dec_r_r_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "decl" " " "%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- dec_m_m_l_base: IB_K_SOM ---- */
static uint64_t k_dec_m_m_l_base(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL x = 0;                                                                     
    void *w = (void *)IB_WBASE();                                                 
    uintptr_t ix = 0;                                                             
    __asm__ volatile("mov" "l" " $0," IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory"); 
    for (i = 0; i < it; i++)                                                      
        __asm__("decl" " " IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory", "cc");        
    __asm__ volatile("mov" "l" " " IB_W_BASE ",%[x]"                                    
                     : [x] "=r"(x) : [w] "r"(w), [ix] "r"(ix) : "memory");          
    return (uint64_t)x;                                                           
}                                                                                 
static uint64_t k_dec_m_m_l_base_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL x = 0;                                                                     
    void *w = (void *)IB_WBASE();                                                 
    uintptr_t ix = 0;                                                             
    __asm__ volatile("mov" "l" " $0," IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory"); 
    for (i = 0; i < it; i++) {                                                    
        __asm__("decl" " " IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory", "cc");        
        __asm__("decl" " " IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory", "cc");        
        __asm__("decl" " " IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory", "cc");        
        __asm__("decl" " " IB_W_BASE : : [w] "r"(w), [ix] "r"(ix) : "memory", "cc");        
    }                                                                             
    __asm__ volatile("mov" "l" " " IB_W_BASE ",%[x]"                                    
                     : [x] "=r"(x) : [w] "r"(w), [ix] "r"(ix) : "memory");          
    return (uint64_t)x;                                                           
}

/* ---- dec_m_m_l_base: IB_KT_SOM ---- */
static inline void k_dec_m_m_l_base_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL i0 = (IB_UL)IB_KIN8("dec_m_m_l_base", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("dec_m_m_l_base", kk, 1, IB_UL);           
    void *w = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("dec_m_m_l_base", kk), fl = 0;                              
    IB_UL x = 0;                                                                      
    __asm__ volatile(IB_SETF "mov" "l" " %[i0]," IB_W_BASE "\n\t" "decl" " " IB_W_BASE              
                     IB_GETF "\n\tmov" "l" " " IB_W_BASE ",%[x]"                            
                    : [x] "=&r"(x), [fl] "=&r"(fl)                                   
                    : [i0] "r"(i0), [w] "r"(w), [ix] "r"(ix), [fv] "r"(fv)            
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)i0; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;              
    g->o0 = (uint64_t)x;  g->o1 = (uint64_t)x;                                      
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                           
}

/* ---- neg_r_r_l: IB_K_R1 ---- */
static uint64_t k_neg_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("negl" " %[a]" : [a] "+r"(a) : : "cc");                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_neg_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("negl" " %[a]" : [a] "+r"(a) : : "cc");                             
        __asm__("negl" " %[c]" : [c] "+r"(c) : : "cc");                             
        __asm__("negl" " %[e]" : [e] "+r"(e) : : "cc");                             
        __asm__("negl" " %[g]" : [g] "+r"(g) : : "cc");                             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- neg_r_r_l: IB_KT_FLG ---- */
static inline void k_neg_r_r_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("neg_r_r_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("neg_r_r_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("neg_r_r_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "negl" " " "%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- neg_r_r_b: IB_K_R18 ---- */
static uint64_t k_neg_r_r_b(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UB a = (IB_UB)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("negb" " %[a]" : [a] "+a"(a) : : "cc");                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_neg_r_r_b_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UB a = (IB_UB)IB_SEED(0), c = (IB_UB)IB_SEED(2);                                    
    for (i = 0; i < it; i++) {                                                    
        __asm__("negb" " %[a]" : [a] "+a"(a) : : "cc");                             
        __asm__("negb" " %[c]" : [c] "+c"(c) : : "cc");                             
    }                                                                             
    return IB_S2(a, c);                                                           
}

/* ---- neg_r_r_b: IB_KT_FLG8 ---- */
static inline void k_neg_r_r_b_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UB a = (IB_UB)IB_KIN8("neg_r_r_b", kk, 0, IB_UB), b = (IB_UB)IB_KIN8("neg_r_r_b", kk, 1, IB_UB);            
    IB_UB ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("neg_r_r_b", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "negb" " " "%[a]" IB_GETF                                   
                    : [a] "+a"(a), [fl] "=&r"(fl)                                   
                    : [b] "b"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- sbb_r_r_l: IB_K_ADC ---- */
static uint64_t k_sbb_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("" "\n\t" "cmp" "l" " $1,%[a]\n\t" "sbb" " " "%[b],%[a]"                   
                : [a] "+a"(a) : [b] "b"(b), [p] "r"(p), [ix] "r"(ix)                
                : "cc", "memory");                                                
    }                                                                             
    return IB_S1(a);                                                              
}                                                                                 
static uint64_t k_sbb_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), b = (IB_UL)IB_SEED(1),                
       d = (IB_UL)IB_SEED(3);                                                        
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("" "\n\t" "cmp" "l" " $1,%[a]\n\t" "sbb" " " "%[b],%[a]"                   
                : [a] "+a"(a) : [b] "b"(b), [p] "r"(p), [ix] "r"(ix)              
                : "cc", "memory");                                                
        /* 第二链: 操作数**名字**必须与 "%[b],%[a]" 里引的一致([a]/[b]), 只换绑定的变量 */ 
        __asm__("" "\n\t" "cmp" "l" " $1,%[a]\n\t" "sbb" " " "%[b],%[a]"                   
                : [a] "+c"(c) : [b] "d"(d), [p] "r"(p), [ix] "r"(ix)              
                : "cc", "memory");                                                
    }                                                                             
    return IB_S2(a, c);                                                           
}

/* ---- sbb_r_r_l: IB_KT_FLG ---- */
static inline void k_sbb_r_r_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("sbb_r_r_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("sbb_r_r_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("sbb_r_r_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "sbb" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+a"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- sbb_r_i_l: IB_K_ADC ---- */
static uint64_t k_sbb_r_i_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("" "\n\t" "cmp" "l" " $1,%[a]\n\t" "sbb" " " "$5,%[a]"                   
                : [a] "+a"(a) : [b] "b"(b), [p] "r"(p), [ix] "r"(ix)                
                : "cc", "memory");                                                
    }                                                                             
    return IB_S1(a);                                                              
}                                                                                 
static uint64_t k_sbb_r_i_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), b = (IB_UL)IB_SEED(1),                
       d = (IB_UL)IB_SEED(3);                                                        
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("" "\n\t" "cmp" "l" " $1,%[a]\n\t" "sbb" " " "$5,%[a]"                   
                : [a] "+a"(a) : [b] "b"(b), [p] "r"(p), [ix] "r"(ix)              
                : "cc", "memory");                                                
        /* 第二链: 操作数**名字**必须与 "$5,%[a]" 里引的一致([a]/[b]), 只换绑定的变量 */ 
        __asm__("" "\n\t" "cmp" "l" " $1,%[a]\n\t" "sbb" " " "$5,%[a]"                   
                : [a] "+c"(c) : [b] "d"(d), [p] "r"(p), [ix] "r"(ix)              
                : "cc", "memory");                                                
    }                                                                             
    return IB_S2(a, c);                                                           
}

/* ---- sbb_r_i_l: IB_KT_FLG ---- */
static inline void k_sbb_r_i_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("sbb_r_i_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("sbb_r_i_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("sbb_r_i_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "sbb" " " "$5,%[a]" IB_GETF                                   
                    : [a] "+a"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- sbb_r_r_w: IB_K_ADC ---- */
static uint64_t k_sbb_r_r_w(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UW a = (IB_UW)IB_SEED(0), b = (IB_UW)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("" "\n\t" "cmp" "w" " $1,%[a]\n\t" "sbb" " " "%[b],%[a]"                   
                : [a] "+a"(a) : [b] "b"(b), [p] "r"(p), [ix] "r"(ix)                
                : "cc", "memory");                                                
    }                                                                             
    return IB_S1(a);                                                              
}                                                                                 
static uint64_t k_sbb_r_r_w_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UW a = (IB_UW)IB_SEED(0), c = (IB_UW)IB_SEED(2), b = (IB_UW)IB_SEED(1),                
       d = (IB_UW)IB_SEED(3);                                                        
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("" "\n\t" "cmp" "w" " $1,%[a]\n\t" "sbb" " " "%[b],%[a]"                   
                : [a] "+a"(a) : [b] "b"(b), [p] "r"(p), [ix] "r"(ix)              
                : "cc", "memory");                                                
        /* 第二链: 操作数**名字**必须与 "%[b],%[a]" 里引的一致([a]/[b]), 只换绑定的变量 */ 
        __asm__("" "\n\t" "cmp" "w" " $1,%[a]\n\t" "sbb" " " "%[b],%[a]"                   
                : [a] "+c"(c) : [b] "d"(d), [p] "r"(p), [ix] "r"(ix)              
                : "cc", "memory");                                                
    }                                                                             
    return IB_S2(a, c);                                                           
}

/* ---- sbb_r_r_w: IB_KT_FLG8 ---- */
static inline void k_sbb_r_r_w_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UW a = (IB_UW)IB_KIN8("sbb_r_r_w", kk, 0, IB_UW), b = (IB_UW)IB_KIN8("sbb_r_r_w", kk, 1, IB_UW);            
    IB_UW ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("sbb_r_r_w", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "sbb" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+a"(a), [fl] "=&r"(fl)                                   
                    : [b] "b"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ==== BEGIN fn=k_adc_r_r_l ==== */
/* ---- adc_r_r_l: IB_K_ADC (32 位 adc r,r —— 补齐既有 sbb 有而 adc 缺的 32 位形态) ---- */
static uint64_t k_adc_r_r_l(unsigned long long it)
{
    unsigned long long i;
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);
    for (i = 0; i < it; i++) {
        IB_PROT_P(i);
        IB_PROT_X(i);
        __asm__("" "\n\t" "cmp" "l" " $1,%[a]\n\t" "adc" " " "%[b],%[a]"
                : [a] "+a"(a) : [b] "b"(b), [p] "r"(p), [ix] "r"(ix)
                : "cc", "memory");
    }
    return IB_S1(a);
}
/* ==== END fn=k_adc_r_r_l ==== */
static uint64_t k_adc_r_r_l_tp(unsigned long long it)
{
    unsigned long long i;
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), b = (IB_UL)IB_SEED(1),
       d = (IB_UL)IB_SEED(3);
    for (i = 0; i < it; i++) {
        IB_PROT_P(i);
        IB_PROT_X(i);
        __asm__("" "\n\t" "cmp" "l" " $1,%[a]\n\t" "adc" " " "%[b],%[a]"
                : [a] "+a"(a) : [b] "b"(b), [p] "r"(p), [ix] "r"(ix)
                : "cc", "memory");
        /* 第二链: 操作数**名字**必须与 "%[b],%[a]" 里引的一致([a]/[b]), 只换绑定的变量 */
        __asm__("" "\n\t" "cmp" "l" " $1,%[a]\n\t" "adc" " " "%[b],%[a]"
                : [a] "+c"(c) : [b] "d"(d), [p] "r"(p), [ix] "r"(ix)
                : "cc", "memory");
    }
    return IB_S2(a, c);
}

/* ---- adc_r_r_l: IB_KT_FLG ---- */
static inline void k_adc_r_r_l_kat(int kk, ib_kv *g)
{
    IB_UL a = (IB_UL)IB_KIN8("adc_r_r_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("adc_r_r_l", kk, 1, IB_UL);
    IB_UL ain = a;
    void *p = ib_kbuf_fill((uint64_t)b);
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);
    uintptr_t fv = (uintptr_t)IB_KFL("adc_r_r_l", kk), fl = 0;
    __asm__ volatile(IB_SETF "adc" " " "%[b],%[a]" IB_GETF
                    : [a] "+a"(a), [fl] "=&r"(fl)
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)
                    : "cc", "memory");
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;
    g->outf = (uint64_t)fl & (IB_FLG_MASK);
}

/* ==== BEGIN fn=k_add_adc_r_r_l ==== */
/* ---- add_adc_r_r_l: IB_K_ADDADC ----
 * S1 专门形态: add 的 CF 只被紧随的 adc 消费(64 位整数加法的低/高字进位对)。
 * lat 是循环内核, TB 出口无旗标读 -> 该 add/adc 对在 LATX 下走 S1 标量替换
 * (GPR 内算进位, 不发 LBT 旗标写); sbb 式的 cmp 重建在此换成 add, 正好构成进位链。 */
static uint64_t k_add_adc_r_r_l(unsigned long long it)
{
    unsigned long long i;
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);
    IB_UL c = (IB_UL)IB_SEED(2), d = (IB_UL)IB_SEED(3);
    for (i = 0; i < it; i++) {
        IB_PROT_P(i);
        IB_PROT_X(i);
        __asm__("" "\n\t" "add" "l" " %[b],%[a]\n\t" "adc" "l" " %[d],%[c]"
                : [a] "+a"(a), [c] "+c"(c)
                : [b] "b"(b), [d] "d"(d), [p] "r"(p), [ix] "r"(ix)
                : "cc", "memory");
    }
    return IB_S2(a, c);
}
/* ==== END fn=k_add_adc_r_r_l ==== */
static uint64_t k_add_adc_r_r_l_tp(unsigned long long it)
{
    return k_add_adc_r_r_l(it);   /* add->adc 进位对串行, 吞吐与延迟同核(见组头注) */
}

/* ---- add_adc_r_r_l: IB_KT_FLG ---- */
static inline void k_add_adc_r_r_l_kat(int kk, ib_kv *g)
{
    IB_UL a = (IB_UL)IB_KIN8("add_adc_r_r_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("add_adc_r_r_l", kk, 1, IB_UL);
    IB_UL c = (IB_UL)IB_KIN8("add_adc_r_r_l", kk, 2, IB_UL), d = (IB_UL)IB_KIN8("add_adc_r_r_l", kk, 3, IB_UL);
    IB_UL ain = a, cin = c;
    void *p = ib_kbuf_fill((uint64_t)b);
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);
    uintptr_t fv = (uintptr_t)IB_KFL("add_adc_r_r_l", kk), fl = 0;
    __asm__ volatile(IB_SETF "add" "l" " %[b],%[a]\n\t" "adc" "l" " %[d],%[c]" IB_GETF
                    : [a] "+a"(a), [c] "+c"(c), [fl] "=&r"(fl)
                    : [b] "q"(b), [d] "q"(d), [fv] "r"(fv)
                    : "cc", "memory");
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b; g->i2 = (uint64_t)cin; g->i3 = (uint64_t)d;
    g->inf = (uint64_t)fv;
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b; g->o2 = (uint64_t)c; g->o3 = (uint64_t)d;
    g->outf = (uint64_t)fl & (IB_FLG_MASK);
}

/* ---- imul_r_i_l: IB_K_R3 ---- */
static uint64_t k_imul_r_i_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)(IB_SEED(1) | 3), c = (IB_UL)IB_SEED(2);          
    for (i = 0; i < it; i++)                                                      
        __asm__("imull" " " "$5,%[b],%[a]" : [a] "+r"(a) : [b] "r"(b), [c] "r"(c) : "cc");      
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_imul_r_i_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2);                                    
    IB_UL b = (IB_UL)(IB_SEED(1) | 3), d = (IB_UL)IB_SEED(3);                              
    for (i = 0; i < it; i++) {                                                    
        __asm__("imull" " " "$5,%[b],%[a]" : [a] "+r"(a) : [b] "r"(b), [c] "r"(c) : "cc");      
        __asm__("imull" " " "$5,%[b],%[a]" : [a] "+r"(c) : [b] "r"(b), [c] "r"(d) : "cc");      
    }                                                                             
    return IB_S2(a, c);                                                           
}

/* ---- imul_r_i_l: IB_KT_FLGO ---- */
static inline void k_imul_r_i_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("imul_r_i_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("imul_r_i_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("imul_r_i_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "imull" " " "$5,%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK_CFOF);                                                
}

/* ---- idiv_r__l: IB_K_DIV ---- */
static uint64_t k_idiv_r__l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)((IB_SEED(0) & 0xffff) | 1), b = (IB_UL)((IB_SEED(1) & 0xffff) | 3);  
    IB_UL d = (IB_UL)0;                                                                 
    const void *p = (const void *)IB_RBASE();                                      
    for (i = 0; i < it; i++)                                                      
        __asm__("xor" "l" " %[d],%[d]\n\tadd" "l" " $1,%[a]\n\t"                   
                "idiv" " " "%[b]"                                                      
                : [a] "+a"(a), [d] "+d"(d)                                        
                : [b] "r"(b), [p] "r"(p), [ix] "r"((uintptr_t)0)                   
                : "cc", "memory");                                                
    return IB_S2(a, d);                                                           
}                                                                                 
static uint64_t k_idiv_r__l_tp(unsigned long long it)                                
{                                                                                 
    return k_idiv_r__l(it);                                                            
}

/* ---- idiv_r__l: IB_KT_DIV ---- */
static inline void k_idiv_r__l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)((IB_KIN("idiv_r__l", kk, 0) & 0xffffULL) | 1);                             
    IB_UL b = (IB_UL)((IB_KIN("idiv_r__l", kk, 1) & 0xffffULL) | 3);                             
    IB_UL ain = a, bin = b, d = (IB_UL)0;                                                
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("idiv_r__l", kk);                                      
    __asm__ volatile(IB_SETF "xor" "l" " %[d],%[d]\n\t" "idiv" " " "%[b]"                  
                    : [a] "+a"(a), [d] "+d"(d)                                      
                    : [b] "r"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)              
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)bin;   g->inf = (uint64_t)fv;           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)d;   g->outf = 0;                       
}


/* ---------------- 用例表(bpop = 每 op 处理字节数; lits = 用例级迭代上限) ----- */
static const ib_case g_cases[] = {
    /* 两 ABI 共有 */
    IB_ROW_K("x86_add__r_i_l",        NULL, add_r_i_l,        4),
    IB_ROW_K("x86_add__r_r_l",        NULL, add_r_r_l,        4),
    IB_ROW_K("x86_sub__r_r_l",        NULL, sub_r_r_l,        4),
    IB_ROW_K("x86_sub__r_i_l",        NULL, sub_r_i_l,        4),
    IB_ROW_K("x86_inc__r_r_l",        NULL, inc_r_r_l,        4),
    IB_ROW_K("x86_inc__m_m_l_base",   NULL, inc_m_m_l_base,   4),
    IB_ROW_K("x86_dec__r_r_l",        NULL, dec_r_r_l,        4),
    IB_ROW_K("x86_dec__m_m_l_base",   NULL, dec_m_m_l_base,   4),
    IB_ROW_K("x86_neg__r_r_l",        NULL, neg_r_r_l,        4),
    IB_ROW_K("x86_neg__r_r_b",        NULL, neg_r_r_b,        1),
    IB_ROW_K("x86_sbb__r_r_l",        NULL, sbb_r_r_l,        4),
    IB_ROW_K("x86_sbb__r_i_l",        NULL, sbb_r_i_l,        4),
    IB_ROW_K("x86_sbb__r_r_w",        NULL, sbb_r_r_w,        2),
    IB_ROW_K("x86_adc__r_r_l",        NULL, adc_r_r_l,        4),
    IB_ROW_K("x86_add_adc__r_r_l",    NULL, add_adc_r_r_l,    4),
    IB_ROW_K("x86_imul__r_i_l",       NULL, imul_r_i_l,       4),
    IB_ROW_KPL("x86_idiv__r__l",      NULL, idiv_r__l,        4, 20000),
#ifdef __x86_64__
    /* 64 位专有形态 */
    IB_ROW_K("x86_add__r_r_q",        NULL, add_r_r_q,        8),
    IB_ROW_K("x86_add__r_i_q",        NULL, add_r_i_q,        8),
    IB_ROW_K("x86_sub__r_i_q",        NULL, sub_r_i_q,        8),
    IB_ROW_K("x86_sub__r_r_q",        NULL, sub_r_r_q,        8),
    IB_ROW_K("x86_inc__r_r_q",        NULL, inc_r_r_q,        8),
    IB_ROW_K("x86_inc__m_m_q_base",   NULL, inc_m_m_q_base,   8),
    IB_ROW_K("x86_dec__r_r_q",        NULL, dec_r_r_q,        8),
    IB_ROW_K("x86_neg__r_r_q",        NULL, neg_r_r_q,        8),
    IB_ROW_K("x86_adc__r_r_q",        NULL, adc_r_r_q,        8),
    IB_ROW_K("x86_adc__r_m_q_base_sp", NULL, adc_r_m_q_base_sp, 8),
    IB_ROW_K("x86_mul__r__q",         NULL, mul_r__q,         8),
    IB_ROW_K("x86_imul__r_i_q",       NULL, imul_r_i_q,       8),
    IB_ROW_K("x86_imul__r_m_q_base",  NULL, imul_r_m_q_base,  8),
    IB_ROW_K("x86_imul__r_r_q",       NULL, imul_r_r_q,       8),
    IB_ROW_KPL("x86_div__r__q",       NULL, div_r__q,         8, 20000),
    IB_ROW_KPL("x86_idiv__m__q_rip",  NULL, idiv_m__q_rip,    8, 20000),
#endif
};
#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

int main(int argc, char **argv)
{
    ib_init(argc, argv);
    ib_abuf_init();                 /* 只读/写区确定性预置(签名跨机可复现的前提) */
    ib_hdr("alu", NCASES);
    ib_run_cases("alu", g_cases, NCASES);
    return 0;
}
