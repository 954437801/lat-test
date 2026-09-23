/* isb_mov.c —— mov 家族形态组(grp=mov): 搬运/零符号扩展/字节序/宽立即数
 *
 * 用例来源 = 实测 三层映射 round5_form_weights.csv 里 mov/movzb/movzw/movsb/
 * movsl/movsw/movabs/bswap/movbe/cltq/cqto/cwtl 的 k90 形态(Pareto-90%), 共 34
 * 条; case 名 = x86_<助记符>__<形态段> 与 form_key 1:1(变换: ' '->'__',
 * '.'->'_', '/'->'_'), 故 --only=x86_mov__r_m 可直接切出全部 load 形态。
 *
 * 分工说明:
 *   - `movsb str.b/base`(串操作) 不在此组 —— 它改 %rsi/%rdi/%rcx, 与被测语义
 *     无关但状态危险, 归 special 组(风险隔离)。此处的 movsb/movsl/movsw 是
 *     符号扩展族(movsbq/movslq/movswq 的 实测 截断名)。
 *   - 64 位 GPR 形态只存在于 x86_64: 内核实例与表项一起 #ifdef, i386 侧不注册
 *     (不输出全 '-' 噪音行), 由对应的 .l 形态承担 32 位权重。
 *
 * 内核全部来自 ib_gen.h 形态模板(lat + tput; block8/sem 本次一律空)。
 *
 * KAT(与 flag/alu/logic/shift/bits/cc 组同一机制): 每个计时内核下面紧跟一行
 * IB_KT_MOV* 探针 —— 同一条指令、同一操作数拼法, 但只执行 1 次、不进循环, 每组
 * 8 个确定性输入, 把 {i0,i1,inf,o0,o1,outf} 与编译期真值表(isb_mov_kat.h)逐位比:
 * 表未回填 -> 本次即采集(kat_st=COLLECT + K 附表行), 已回填 -> OK/KATFAIL。
 * 本组四处口径(全部由探针形状表达, 不影响计时链):
 *   - 掩码一律用全掩码 IB_FLG_MASK: 搬运族架构上不改标志 -> outf == inf 本身就
 *     是一条断言(翻译器把 mov 译成会踩 EFLAGS 的实现, 在这里直接 KATFAIL)。
 *   - store 形态(mov m,r): 不回读就只能记下寄存器入值(等于没审 store 路径) ->
 *     用 IB_KT_MOVM 从**同一槽**回读当 o0。
 *   - 栈槽 load(-64(%rsp)): 预置与被测必须在同一个 asm 块里 -> IB_KT_MOVP。
 *   - rip 形态的内存侧改成 g_kbuf(整窗广播 = i1, 与 logic 组同一处理): 表里得
 *     记「内存里真实那个值」, 而 g_rbuf 内容由计时骨架预置决定 -> 不可审。
 */
#include "ib_core.h"
#include "ib_buf.h"
#include "isb_mov_kat.h"    /* KAT 真值表(采集后生成; 未取数时全 UNSET) */

/* ---------------- 64 位形态(仅 x86_64) ---------------- */
#ifdef __x86_64__
/* ---- mov_r_m_q_base: IB_K_CHASE ---- */
static uint64_t k_mov_r_m_q_base(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p = (const void *)(b + (((uintptr_t)a << 3) & 448));          
        IB_PROT_X(i);                                                             
        __asm__("movq" " " IB_M_BASE ",%[a]" : [a] "=r"(a) : [p] "r"(p), [ix] "r"(ix)      
                 : "memory");                                                     
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_mov_r_m_q_base_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p0 = (const void *)(b + (((uintptr_t)a << 3) & 448));         
        const void *p1 = (const void *)(b + (((uintptr_t)c << 3) & 448));         
        const void *p2 = (const void *)(b + (((uintptr_t)e << 3) & 448));         
        const void *p3 = (const void *)(b + (((uintptr_t)g << 3) & 448));         
        IB_PROT_X(i);                                                             
        __asm__("movq" " " IB_M_BASE ",%[a]" : [a] "=r"(a) : [p] "r"(p0), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movq" " " IB_M_BASE ",%[a]" : [a] "=r"(c) : [p] "r"(p1), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movq" " " IB_M_BASE ",%[a]" : [a] "=r"(e) : [p] "r"(p2), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movq" " " IB_M_BASE ",%[a]" : [a] "=r"(g) : [p] "r"(p3), [ix] "r"(ix)     
                 : "memory");                                                     
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- mov_r_m_q_base: IB_KT_MOV ---- */
static inline void k_mov_r_m_q_base_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("mov_r_m_q_base", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("mov_r_m_q_base", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("mov_r_m_q_base", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movq" " " IB_M_BASE ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- mov_r_r_q: IB_K_MOVR ---- */
static uint64_t k_mov_r_r_q(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++)                                                      
        __asm__("movq" " %[a],%[b]\n\t" "movq" " %[b],%[a]"                            
                : [a] "+r"(a), [b] "+r"(b));                                      
    return IB_S2(a, b);                        /* a==b(见下注), 故不能异或 */      
}                                                                                 
static uint64_t k_mov_r_r_q_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    IB_UQ c = (IB_UQ)IB_SEED(2), d = (IB_UQ)IB_SEED(3);                                    
    for (i = 0; i < it; i++) {                                                    
        __asm__("movq" " %[a],%[b]\n\t" "movq" " %[b],%[a]"                            
                : [a] "+r"(a), [b] "+r"(b));                                      
        __asm__("movq" " %[c],%[d]\n\t" "movq" " %[d],%[c]"                            
                : [c] "+r"(c), [d] "+r"(d));                                      
    }                                                                             
    return IB_S4(a, b, c, d);                                                     
}

/* ---- mov_r_r_q: IB_KT_MOV ---- */
static inline void k_mov_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("mov_r_r_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("mov_r_r_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("mov_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movq" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- mov_r_m_q_index: IB_K_CHASE ---- */
static uint64_t k_mov_r_m_q_index(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p = (const void *)(b + (((uintptr_t)a << 3) & 448));          
        IB_PROT_X(i);                                                             
        __asm__("movq" " " IB_M_IDX ",%[a]" : [a] "=r"(a) : [p] "r"(p), [ix] "r"(ix)      
                 : "memory");                                                     
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_mov_r_m_q_index_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p0 = (const void *)(b + (((uintptr_t)a << 3) & 448));         
        const void *p1 = (const void *)(b + (((uintptr_t)c << 3) & 448));         
        const void *p2 = (const void *)(b + (((uintptr_t)e << 3) & 448));         
        const void *p3 = (const void *)(b + (((uintptr_t)g << 3) & 448));         
        IB_PROT_X(i);                                                             
        __asm__("movq" " " IB_M_IDX ",%[a]" : [a] "=r"(a) : [p] "r"(p0), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movq" " " IB_M_IDX ",%[a]" : [a] "=r"(c) : [p] "r"(p1), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movq" " " IB_M_IDX ",%[a]" : [a] "=r"(e) : [p] "r"(p2), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movq" " " IB_M_IDX ",%[a]" : [a] "=r"(g) : [p] "r"(p3), [ix] "r"(ix)     
                 : "memory");                                                     
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- mov_r_m_q_index: IB_KT_MOV ---- */
static inline void k_mov_r_m_q_index_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("mov_r_m_q_index", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("mov_r_m_q_index", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("mov_r_m_q_index", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movq" " " IB_M_IDX ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- mov_r_m_q_rip: IB_K_LD ---- */
static uint64_t k_mov_r_m_q_rip(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__ volatile("movq" " " IB_M_RIP ",%[a]" : [a] "+r"(a) : [p] "r"(p), [ix] "r"(ix)      
                         : "memory");                                             
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_mov_r_m_q_rip_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__ volatile("movq" " " IB_M_RIP ",%[a]" : [a] "+r"(a) : [p] "r"(p), [ix] "r"(ix)      
                         : "memory");                                             
        __asm__ volatile("movq" " " IB_M_RIP ",%[a]" : [a] "+r"(c) : [p] "r"(p), [ix] "r"(ix)      
                         : "memory");                                             
        __asm__ volatile("movq" " " IB_M_RIP ",%[a]" : [a] "+r"(e) : [p] "r"(p), [ix] "r"(ix)      
                         : "memory");                                             
        __asm__ volatile("movq" " " IB_M_RIP ",%[a]" : [a] "+r"(g) : [p] "r"(p), [ix] "r"(ix)      
                         : "memory");                                             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- mov_r_m_q_rip: IB_KT_FLGA ---- */
/* ---- mov_r_m_q_rip: IB_KT_FLGA (manually expanded) ---- */
static inline void k_mov_r_m_q_rip_kat(int kk, ib_kv *g)
{
    IB_UQ a = (IB_UQ)IB_KIN8("mov_r_m_q_rip", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("mov_r_m_q_rip", kk, 1, IB_UQ);
    IB_UQ ain = a;
    void *p = ib_kbuf_fill((uint64_t)b);
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);
    uintptr_t fv = (uintptr_t)IB_KFL("mov_r_m_q_rip", kk), fl = 0;
    __asm__ volatile(IB_SETF "movq " "g_kbuf+8(%%rip),%[a]" IB_GETF
            : [a] "+r"(a), [fl] "=&r"(fl)
            : [b] "r"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)
            : "cc", "memory");
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b; g->inf = (uint64_t)fv;
    g->o0 = (uint64_t)a; g->o1 = (uint64_t)b;
    g->outf = (uint64_t)fl & (IB_FLG_MASK);
}

static uint64_t k_mov_r_m_q_base_sp(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)0x11;                                                              
    __asm__ volatile("mov" "q" " $0x5a5a5a," IB_M_SP ::: "memory");                    
    for (i = 0; i < it; i++)                                                      
        __asm__ volatile("movq" " " IB_M_SP ",%[a]" : [a] "+r"(a) : : "memory");         
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_mov_r_m_q_base_sp_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)0x11, c = (IB_UQ)0x22, e = (IB_UQ)0x33, g = (IB_UQ)0x44;                    
    __asm__ volatile("mov" "q" " $0x5a5a5a," IB_M_SP ::: "memory");                    
    for (i = 0; i < it; i++) {                                                    
        __asm__ volatile("movq" " " IB_M_SP ",%[a]" : [a] "+r"(a) : : "memory");         
        __asm__ volatile("movq" " " IB_M_SP ",%[a]" : [a] "+r"(c) : : "memory");         
        __asm__ volatile("movq" " " IB_M_SP ",%[a]" : [a] "+r"(e) : : "memory");         
        __asm__ volatile("movq" " " IB_M_SP ",%[a]" : [a] "+r"(g) : : "memory");         
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- mov_r_m_q_base_sp: IB_KT_MOVP ---- */
static inline void k_mov_r_m_q_base_sp_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UQ a = (IB_UQ)IB_KIN8("mov_r_m_q_base_sp", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("mov_r_m_q_base_sp", kk, 1, IB_UQ);          
    IB_UQ ain = a;                                                                   
    void *p = ib_kbuf_fill((uint64_t)b);                                          
    uintptr_t fv = (uintptr_t)IB_KFL("mov_r_m_q_base_sp", kk), fl = 0;                            
    __asm__ volatile(IB_SETF "mov" "q" " %[b]," IB_M_SP "\n\t" "movq" " " IB_M_SP ",%[a]" IB_GETF 
                    : [a] "+r"(a), [fl] "=&r"(fl)                                 
                    : [b] "r"(b), [p] "r"(p), [fv] "r"(fv) : "cc", "memory");       
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- mov_m_r_q_base: IB_K_DST ---- */
static uint64_t k_mov_m_r_q_base(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_W(i);                                                             
        IB_PROT_X(i);                                                             
        a = (IB_UQ)((uint64_t)a + 1);                                                
        __asm__ volatile("movq" " %[a]," IB_W_BASE : [a] "+r"(a) : [w] "r"(w), [ix] "r"(ix)        
                         : "memory");                                             
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_mov_m_r_q_base_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_W(i);                                                             
        IB_PROT_X(i);                                                             
        a = (IB_UQ)((uint64_t)a + 1);                                                
        __asm__ volatile("movq" " %[a]," IB_W_BASE : [a] "+r"(a) : [w] "r"(w), [ix] "r"(ix)        
                         : "memory");                                             
        __asm__ volatile("movq" " %[a]," IB_W_BASE : [a] "+r"(c) : [w] "r"(w), [ix] "r"(ix)        
                         : "memory");                                             
        __asm__ volatile("movq" " %[a]," IB_W_BASE : [a] "+r"(e) : [w] "r"(w), [ix] "r"(ix)        
                         : "memory");                                             
        __asm__ volatile("movq" " %[a]," IB_W_BASE : [a] "+r"(g) : [w] "r"(w), [ix] "r"(ix)        
                         : "memory");                                             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- mov_m_r_q_base: IB_KT_MOVM ---- */
static inline void k_mov_m_r_q_base_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UQ a = (IB_UQ)IB_KIN8("mov_m_r_q_base", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("mov_m_r_q_base", kk, 1, IB_UQ);          
    IB_UQ x = (IB_UQ)0;                                                                 
    void *p = ib_kbuf_fill((uint64_t)b);                                          
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                
    uintptr_t fv = (uintptr_t)IB_KFL("mov_m_r_q_base", kk), fl = 0;                            
    __asm__ volatile(IB_SETF "movq" " %[a]," "8(%[p])" "\n\t" "mov" "q" " " "8(%[p])" ",%[x]" IB_GETF 
                    : [a] "+r"(a), [x] "=&r"(x), [fl] "=&r"(fl)                   
                    : [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv) : "cc", "memory");    
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;           
    g->o0 = (uint64_t)x;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- mov_m_r_q_base_sp: IB_K_DST ---- */
static uint64_t k_mov_m_r_q_base_sp(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_W(i);                                                             
        IB_PROT_X(i);                                                             
        a = (IB_UQ)((uint64_t)a + 1);                                                
        __asm__ volatile("movq" " %[a]," IB_M_SP : [a] "+r"(a) : [w] "r"(w), [ix] "r"(ix)        
                         : "memory");                                             
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_mov_m_r_q_base_sp_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_W(i);                                                             
        IB_PROT_X(i);                                                             
        a = (IB_UQ)((uint64_t)a + 1);                                                
        __asm__ volatile("movq" " %[a]," IB_M_SP : [a] "+r"(a) : [w] "r"(w), [ix] "r"(ix)        
                         : "memory");                                             
        __asm__ volatile("movq" " %[a]," IB_M_SP : [a] "+r"(c) : [w] "r"(w), [ix] "r"(ix)        
                         : "memory");                                             
        __asm__ volatile("movq" " %[a]," IB_M_SP : [a] "+r"(e) : [w] "r"(w), [ix] "r"(ix)        
                         : "memory");                                             
        __asm__ volatile("movq" " %[a]," IB_M_SP : [a] "+r"(g) : [w] "r"(w), [ix] "r"(ix)        
                         : "memory");                                             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- mov_m_r_q_base_sp: IB_KT_MOVM ---- */
static inline void k_mov_m_r_q_base_sp_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UQ a = (IB_UQ)IB_KIN8("mov_m_r_q_base_sp", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("mov_m_r_q_base_sp", kk, 1, IB_UQ);          
    IB_UQ x = (IB_UQ)0;                                                                 
    void *p = ib_kbuf_fill((uint64_t)b);                                          
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                
    uintptr_t fv = (uintptr_t)IB_KFL("mov_m_r_q_base_sp", kk), fl = 0;                            
    __asm__ volatile(IB_SETF "movq" " %[a]," IB_M_SP "\n\t" "mov" "q" " " IB_M_SP ",%[x]" IB_GETF 
                    : [a] "+r"(a), [x] "=&r"(x), [fl] "=&r"(fl)                   
                    : [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv) : "cc", "memory");    
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;           
    g->o0 = (uint64_t)x;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- movabs_r_i_q: IB_K_MOVI ---- */
static uint64_t k_movabs_r_i_q(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)0x11;                                                              
    for (i = 0; i < it; i++)                                                      
        __asm__ volatile("movabsq" " " "$0x123456789abcdef" ",%[a]" : [a] "+r"(a));                     
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_movabs_r_i_q_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)0x11, c = (IB_UQ)0x22, e = (IB_UQ)0x33, g = (IB_UQ)0x44;                    
    for (i = 0; i < it; i++) {                                                    
        __asm__ volatile("movabsq" " " "$0x123456789abcdef" ",%[a]" : [a] "+r"(a));                     
        __asm__ volatile("movabsq" " " "$0x123456789abcdef" ",%[a]" : [a] "+r"(c));                     
        __asm__ volatile("movabsq" " " "$0x123456789abcdef" ",%[a]" : [a] "+r"(e));                     
        __asm__ volatile("movabsq" " " "$0x123456789abcdef" ",%[a]" : [a] "+r"(g));                     
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- movabs_r_i_q: IB_KT_MOV ---- */
static inline void k_movabs_r_i_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("movabs_r_i_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("movabs_r_i_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("movabs_r_i_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movabsq" " " "$0x123456789abcdef,%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- movsb_r_m_q_base: IB_K_CHASE ---- */
static uint64_t k_movsb_r_m_q_base(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p = (const void *)(b + (((uintptr_t)a << 3) & 448));          
        IB_PROT_X(i);                                                             
        __asm__("movsbq" " " IB_M_BASE ",%[a]" : [a] "=r"(a) : [p] "r"(p), [ix] "r"(ix)      
                 : "memory");                                                     
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_movsb_r_m_q_base_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p0 = (const void *)(b + (((uintptr_t)a << 3) & 448));         
        const void *p1 = (const void *)(b + (((uintptr_t)c << 3) & 448));         
        const void *p2 = (const void *)(b + (((uintptr_t)e << 3) & 448));         
        const void *p3 = (const void *)(b + (((uintptr_t)g << 3) & 448));         
        IB_PROT_X(i);                                                             
        __asm__("movsbq" " " IB_M_BASE ",%[a]" : [a] "=r"(a) : [p] "r"(p0), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movsbq" " " IB_M_BASE ",%[a]" : [a] "=r"(c) : [p] "r"(p1), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movsbq" " " IB_M_BASE ",%[a]" : [a] "=r"(e) : [p] "r"(p2), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movsbq" " " IB_M_BASE ",%[a]" : [a] "=r"(g) : [p] "r"(p3), [ix] "r"(ix)     
                 : "memory");                                                     
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- movsb_r_m_q_base: IB_KT_MOV ---- */
static inline void k_movsb_r_m_q_base_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("movsb_r_m_q_base", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("movsb_r_m_q_base", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("movsb_r_m_q_base", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movsbq" " " IB_M_BASE ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- movsb_r_m_q_index: IB_K_CHASE ---- */
static uint64_t k_movsb_r_m_q_index(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p = (const void *)(b + (((uintptr_t)a << 3) & 448));          
        IB_PROT_X(i);                                                             
        __asm__("movsbq" " " IB_M_IDX ",%[a]" : [a] "=r"(a) : [p] "r"(p), [ix] "r"(ix)      
                 : "memory");                                                     
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_movsb_r_m_q_index_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p0 = (const void *)(b + (((uintptr_t)a << 3) & 448));         
        const void *p1 = (const void *)(b + (((uintptr_t)c << 3) & 448));         
        const void *p2 = (const void *)(b + (((uintptr_t)e << 3) & 448));         
        const void *p3 = (const void *)(b + (((uintptr_t)g << 3) & 448));         
        IB_PROT_X(i);                                                             
        __asm__("movsbq" " " IB_M_IDX ",%[a]" : [a] "=r"(a) : [p] "r"(p0), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movsbq" " " IB_M_IDX ",%[a]" : [a] "=r"(c) : [p] "r"(p1), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movsbq" " " IB_M_IDX ",%[a]" : [a] "=r"(e) : [p] "r"(p2), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movsbq" " " IB_M_IDX ",%[a]" : [a] "=r"(g) : [p] "r"(p3), [ix] "r"(ix)     
                 : "memory");                                                     
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- movsb_r_m_q_index: IB_KT_MOV ---- */
static inline void k_movsb_r_m_q_index_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("movsb_r_m_q_index", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("movsb_r_m_q_index", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("movsb_r_m_q_index", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movsbq" " " IB_M_IDX ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- movsl_r_m_q_base: IB_K_CHASE ---- */
static uint64_t k_movsl_r_m_q_base(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p = (const void *)(b + (((uintptr_t)a << 3) & 448));          
        IB_PROT_X(i);                                                             
        __asm__("movslq" " " IB_M_BASE ",%[a]" : [a] "=r"(a) : [p] "r"(p), [ix] "r"(ix)      
                 : "memory");                                                     
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_movsl_r_m_q_base_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p0 = (const void *)(b + (((uintptr_t)a << 3) & 448));         
        const void *p1 = (const void *)(b + (((uintptr_t)c << 3) & 448));         
        const void *p2 = (const void *)(b + (((uintptr_t)e << 3) & 448));         
        const void *p3 = (const void *)(b + (((uintptr_t)g << 3) & 448));         
        IB_PROT_X(i);                                                             
        __asm__("movslq" " " IB_M_BASE ",%[a]" : [a] "=r"(a) : [p] "r"(p0), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movslq" " " IB_M_BASE ",%[a]" : [a] "=r"(c) : [p] "r"(p1), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movslq" " " IB_M_BASE ",%[a]" : [a] "=r"(e) : [p] "r"(p2), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movslq" " " IB_M_BASE ",%[a]" : [a] "=r"(g) : [p] "r"(p3), [ix] "r"(ix)     
                 : "memory");                                                     
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- movsl_r_m_q_base: IB_KT_MOV ---- */
static inline void k_movsl_r_m_q_base_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("movsl_r_m_q_base", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("movsl_r_m_q_base", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("movsl_r_m_q_base", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movslq" " " IB_M_BASE ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- movsl_r_m_q_index: IB_K_CHASE ---- */
static uint64_t k_movsl_r_m_q_index(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p = (const void *)(b + (((uintptr_t)a << 3) & 448));          
        IB_PROT_X(i);                                                             
        __asm__("movslq" " " IB_M_IDX ",%[a]" : [a] "=r"(a) : [p] "r"(p), [ix] "r"(ix)      
                 : "memory");                                                     
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_movsl_r_m_q_index_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p0 = (const void *)(b + (((uintptr_t)a << 3) & 448));         
        const void *p1 = (const void *)(b + (((uintptr_t)c << 3) & 448));         
        const void *p2 = (const void *)(b + (((uintptr_t)e << 3) & 448));         
        const void *p3 = (const void *)(b + (((uintptr_t)g << 3) & 448));         
        IB_PROT_X(i);                                                             
        __asm__("movslq" " " IB_M_IDX ",%[a]" : [a] "=r"(a) : [p] "r"(p0), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movslq" " " IB_M_IDX ",%[a]" : [a] "=r"(c) : [p] "r"(p1), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movslq" " " IB_M_IDX ",%[a]" : [a] "=r"(e) : [p] "r"(p2), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movslq" " " IB_M_IDX ",%[a]" : [a] "=r"(g) : [p] "r"(p3), [ix] "r"(ix)     
                 : "memory");                                                     
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- movsl_r_m_q_index: IB_KT_MOV ---- */
static inline void k_movsl_r_m_q_index_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("movsl_r_m_q_index", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("movsl_r_m_q_index", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("movsl_r_m_q_index", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movslq" " " IB_M_IDX ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- movsl_r_r_q: IB_K_ZX ---- */
static uint64_t k_movsl_r_r_q(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("movslq" " " "%%eax,%%rax" : [a] "+a"(a));                                        
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_movsl_r_r_q_tp(ib_uw it)                                
{                                                                                 
    return k_movsl_r_r_q(it);                                                            
}

/* ---- movsl_r_r_q: IB_KT_MOV ---- */
static inline void k_movsl_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("movsl_r_r_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("movsl_r_r_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("movsl_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movslq" " " "%%eax,%%rax" IB_GETF                                   
                    : [a] "+a"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- movsw_r_r_q: IB_K_ZX ---- */
static uint64_t k_movsw_r_r_q(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("movswq" " " "%%ax,%%rax" : [a] "+a"(a));                                        
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_movsw_r_r_q_tp(ib_uw it)                                
{                                                                                 
    return k_movsw_r_r_q(it);                                                            
}

/* ---- movsw_r_r_q: IB_KT_MOV ---- */
static inline void k_movsw_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("movsw_r_r_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("movsw_r_r_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("movsw_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movswq" " " "%%ax,%%rax" IB_GETF                                   
                    : [a] "+a"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- bswap_r__q: IB_K_R1 ---- */
static uint64_t k_bswap_r__q(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("bswap" " %[a]" : [a] "+r"(a) : : "cc");                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_bswap_r__q_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("bswap" " %[a]" : [a] "+r"(a) : : "cc");                             
        __asm__("bswap" " %[c]" : [c] "+r"(c) : : "cc");                             
        __asm__("bswap" " %[e]" : [e] "+r"(e) : : "cc");                             
        __asm__("bswap" " %[g]" : [g] "+r"(g) : : "cc");                             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- bswap_r__q: IB_KT_MOV ---- */
static inline void k_bswap_r__q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("bswap_r__q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("bswap_r__q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("bswap_r__q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "bswap" " " "%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- movbe_r_m_q_base: IB_K_CHASE ---- */
static uint64_t k_movbe_r_m_q_base(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p = (const void *)(b + (((uintptr_t)a << 3) & 448));          
        IB_PROT_X(i);                                                             
        __asm__("movbe" " " IB_M_BASE ",%[a]" : [a] "=r"(a) : [p] "r"(p), [ix] "r"(ix)      
                 : "memory");                                                     
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_movbe_r_m_q_base_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p0 = (const void *)(b + (((uintptr_t)a << 3) & 448));         
        const void *p1 = (const void *)(b + (((uintptr_t)c << 3) & 448));         
        const void *p2 = (const void *)(b + (((uintptr_t)e << 3) & 448));         
        const void *p3 = (const void *)(b + (((uintptr_t)g << 3) & 448));         
        IB_PROT_X(i);                                                             
        __asm__("movbe" " " IB_M_BASE ",%[a]" : [a] "=r"(a) : [p] "r"(p0), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movbe" " " IB_M_BASE ",%[a]" : [a] "=r"(c) : [p] "r"(p1), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movbe" " " IB_M_BASE ",%[a]" : [a] "=r"(e) : [p] "r"(p2), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movbe" " " IB_M_BASE ",%[a]" : [a] "=r"(g) : [p] "r"(p3), [ix] "r"(ix)     
                 : "memory");                                                     
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- movbe_r_m_q_base: IB_KT_MOV ---- */
static inline void k_movbe_r_m_q_base_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("movbe_r_m_q_base", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("movbe_r_m_q_base", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("movbe_r_m_q_base", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movbe" " " IB_M_BASE ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- cltq___: IB_K_WIDE ---- */
static uint64_t k_cltq___(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), d = (IB_UQ)0;                                             
    for (i = 0; i < it; i++)                                                      
        __asm__("cltq" : "+a"(a), "+d"(d) : : "cc");                                
    return IB_S2(a, d);                                                           
}                                                                                 
static uint64_t k_cltq____tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), d = (IB_UQ)0;                                             
    for (i = 0; i < it; i++)                                                      
        __asm__("cltq" : "+a"(a), "+d"(d) : : "cc");                                
    return IB_S2(a, d);                                                           
}

/* ---- cltq___: IB_KT_MOVW ---- */
static inline void k_cltq____kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UQ a = (IB_UQ)IB_KIN8("cltq___", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("cltq___", kk, 1, IB_UQ);          
    IB_UQ ain = a, bin = b;                                                          
    void *p = ib_kbuf_fill((uint64_t)b);                                          
    uintptr_t fv = (uintptr_t)IB_KFL("cltq___", kk), fl = 0;                            
    __asm__ volatile(IB_SETF "cltq" IB_GETF                                         
                    : [a] "+a"(a), [d] "+d"(b), [fl] "=&r"(fl)                    
                    : [p] "r"(p), [fv] "r"(fv) : "cc", "memory");                  
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)bin;  g->inf = (uint64_t)fv;          
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- cqto___: IB_K_WIDE ---- */
static uint64_t k_cqto___(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), d = (IB_UQ)0;                                             
    for (i = 0; i < it; i++)                                                      
        __asm__("cqto" : "+a"(a), "+d"(d) : : "cc");                                
    return IB_S2(a, d);                                                           
}                                                                                 
static uint64_t k_cqto____tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), d = (IB_UQ)0;                                             
    for (i = 0; i < it; i++)                                                      
        __asm__("cqto" : "+a"(a), "+d"(d) : : "cc");                                
    return IB_S2(a, d);                                                           
}

/* ---- cqto___: IB_KT_MOVW ---- */
static inline void k_cqto____kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UQ a = (IB_UQ)IB_KIN8("cqto___", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("cqto___", kk, 1, IB_UQ);          
    IB_UQ ain = a, bin = b;                                                          
    void *p = ib_kbuf_fill((uint64_t)b);                                          
    uintptr_t fv = (uintptr_t)IB_KFL("cqto___", kk), fl = 0;                            
    __asm__ volatile(IB_SETF "cqto" IB_GETF                                         
                    : [a] "+a"(a), [d] "+d"(b), [fl] "=&r"(fl)                    
                    : [p] "r"(p), [fv] "r"(fv) : "cc", "memory");                  
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)bin;  g->inf = (uint64_t)fv;          
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

#endif

/* ---------------- 两 ABI 共有形态(32 位为主) ---------------- */
/* ---- mov_r_m_l_base: IB_K_CHASE ---- */
static uint64_t k_mov_r_m_l_base(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p = (const void *)(b + (((uintptr_t)a << 3) & 448));          
        IB_PROT_X(i);                                                             
        __asm__("movl" " " IB_M_BASE ",%[a]" : [a] "=r"(a) : [p] "r"(p), [ix] "r"(ix)      
                 : "memory");                                                     
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_mov_r_m_l_base_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p0 = (const void *)(b + (((uintptr_t)a << 3) & 448));         
        const void *p1 = (const void *)(b + (((uintptr_t)c << 3) & 448));         
        const void *p2 = (const void *)(b + (((uintptr_t)e << 3) & 448));         
        const void *p3 = (const void *)(b + (((uintptr_t)g << 3) & 448));         
        IB_PROT_X(i);                                                             
        __asm__("movl" " " IB_M_BASE ",%[a]" : [a] "=r"(a) : [p] "r"(p0), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movl" " " IB_M_BASE ",%[a]" : [a] "=r"(c) : [p] "r"(p1), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movl" " " IB_M_BASE ",%[a]" : [a] "=r"(e) : [p] "r"(p2), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movl" " " IB_M_BASE ",%[a]" : [a] "=r"(g) : [p] "r"(p3), [ix] "r"(ix)     
                 : "memory");                                                     
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- mov_r_m_l_base: IB_KT_MOV ---- */
static inline void k_mov_r_m_l_base_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("mov_r_m_l_base", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("mov_r_m_l_base", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("mov_r_m_l_base", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movl" " " IB_M_BASE ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- mov_r_r_l: IB_K_MOVR ---- */
static uint64_t k_mov_r_r_l(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++)                                                      
        __asm__("movl" " %[a],%[b]\n\t" "movl" " %[b],%[a]"                            
                : [a] "+r"(a), [b] "+r"(b));                                      
    return IB_S2(a, b);                        /* a==b(见下注), 故不能异或 */      
}                                                                                 
static uint64_t k_mov_r_r_l_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    IB_UL c = (IB_UL)IB_SEED(2), d = (IB_UL)IB_SEED(3);                                    
    for (i = 0; i < it; i++) {                                                    
        __asm__("movl" " %[a],%[b]\n\t" "movl" " %[b],%[a]"                            
                : [a] "+r"(a), [b] "+r"(b));                                      
        __asm__("movl" " %[c],%[d]\n\t" "movl" " %[d],%[c]"                            
                : [c] "+r"(c), [d] "+r"(d));                                      
    }                                                                             
    return IB_S4(a, b, c, d);                                                     
}

/* ---- mov_r_r_l: IB_KT_MOV ---- */
static inline void k_mov_r_r_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("mov_r_r_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("mov_r_r_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("mov_r_r_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movl" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- mov_r_m_l_index: IB_K_CHASE ---- */
static uint64_t k_mov_r_m_l_index(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p = (const void *)(b + (((uintptr_t)a << 3) & 448));          
        IB_PROT_X(i);                                                             
        __asm__("movl" " " IB_M_IDX ",%[a]" : [a] "=r"(a) : [p] "r"(p), [ix] "r"(ix)      
                 : "memory");                                                     
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_mov_r_m_l_index_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p0 = (const void *)(b + (((uintptr_t)a << 3) & 448));         
        const void *p1 = (const void *)(b + (((uintptr_t)c << 3) & 448));         
        const void *p2 = (const void *)(b + (((uintptr_t)e << 3) & 448));         
        const void *p3 = (const void *)(b + (((uintptr_t)g << 3) & 448));         
        IB_PROT_X(i);                                                             
        __asm__("movl" " " IB_M_IDX ",%[a]" : [a] "=r"(a) : [p] "r"(p0), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movl" " " IB_M_IDX ",%[a]" : [a] "=r"(c) : [p] "r"(p1), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movl" " " IB_M_IDX ",%[a]" : [a] "=r"(e) : [p] "r"(p2), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movl" " " IB_M_IDX ",%[a]" : [a] "=r"(g) : [p] "r"(p3), [ix] "r"(ix)     
                 : "memory");                                                     
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- mov_r_m_l_index: IB_KT_MOV ---- */
static inline void k_mov_r_m_l_index_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("mov_r_m_l_index", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("mov_r_m_l_index", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("mov_r_m_l_index", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movl" " " IB_M_IDX ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- mov_r_m_l_base_sp: IB_K_LDP ---- */
static uint64_t k_mov_r_m_l_base_sp(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)0x11;                                                              
    __asm__ volatile("mov" "l" " $0x5a5a5a," IB_M_SP ::: "memory");                    
    for (i = 0; i < it; i++)                                                      
        __asm__ volatile("movl" " " IB_M_SP ",%[a]" : [a] "+r"(a) : : "memory");         
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_mov_r_m_l_base_sp_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)0x11, c = (IB_UL)0x22, e = (IB_UL)0x33, g = (IB_UL)0x44;                    
    __asm__ volatile("mov" "l" " $0x5a5a5a," IB_M_SP ::: "memory");                    
    for (i = 0; i < it; i++) {                                                    
        __asm__ volatile("movl" " " IB_M_SP ",%[a]" : [a] "+r"(a) : : "memory");         
        __asm__ volatile("movl" " " IB_M_SP ",%[a]" : [a] "+r"(c) : : "memory");         
        __asm__ volatile("movl" " " IB_M_SP ",%[a]" : [a] "+r"(e) : : "memory");         
        __asm__ volatile("movl" " " IB_M_SP ",%[a]" : [a] "+r"(g) : : "memory");         
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- mov_r_m_l_base_sp: IB_KT_MOVP ---- */
static inline void k_mov_r_m_l_base_sp_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("mov_r_m_l_base_sp", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("mov_r_m_l_base_sp", kk, 1, IB_UL);          
    IB_UL ain = a;                                                                   
    void *p = ib_kbuf_fill((uint64_t)b);                                          
    uintptr_t fv = (uintptr_t)IB_KFL("mov_r_m_l_base_sp", kk), fl = 0;                            
    __asm__ volatile(IB_SETF "mov" "l" " %[b]," IB_M_SP "\n\t" "movl" " " IB_M_SP ",%[a]" IB_GETF 
                    : [a] "+r"(a), [fl] "=&r"(fl)                                 
                    : [b] "r"(b), [p] "r"(p), [fv] "r"(fv) : "cc", "memory");       
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- mov_m_r_l_base: IB_K_DST ---- */
static uint64_t k_mov_m_r_l_base(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_W(i);                                                             
        IB_PROT_X(i);                                                             
        a = (IB_UL)((uint64_t)a + 1);                                                
        __asm__ volatile("movl" " %[a]," IB_W_BASE : [a] "+r"(a) : [w] "r"(w), [ix] "r"(ix)        
                         : "memory");                                             
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_mov_m_r_l_base_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_W(i);                                                             
        IB_PROT_X(i);                                                             
        a = (IB_UL)((uint64_t)a + 1);                                                
        __asm__ volatile("movl" " %[a]," IB_W_BASE : [a] "+r"(a) : [w] "r"(w), [ix] "r"(ix)        
                         : "memory");                                             
        __asm__ volatile("movl" " %[a]," IB_W_BASE : [a] "+r"(c) : [w] "r"(w), [ix] "r"(ix)        
                         : "memory");                                             
        __asm__ volatile("movl" " %[a]," IB_W_BASE : [a] "+r"(e) : [w] "r"(w), [ix] "r"(ix)        
                         : "memory");                                             
        __asm__ volatile("movl" " %[a]," IB_W_BASE : [a] "+r"(g) : [w] "r"(w), [ix] "r"(ix)        
                         : "memory");                                             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- mov_m_r_l_base: IB_KT_MOVM ---- */
static inline void k_mov_m_r_l_base_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("mov_m_r_l_base", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("mov_m_r_l_base", kk, 1, IB_UL);          
    IB_UL x = (IB_UL)0;                                                                 
    void *p = ib_kbuf_fill((uint64_t)b);                                          
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                
    uintptr_t fv = (uintptr_t)IB_KFL("mov_m_r_l_base", kk), fl = 0;                            
    __asm__ volatile(IB_SETF "movl" " %[a]," "8(%[p])" "\n\t" "mov" "l" " " "8(%[p])" ",%[x]" IB_GETF 
                    : [a] "+r"(a), [x] "=&r"(x), [fl] "=&r"(fl)                   
                    : [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv) : "cc", "memory");    
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;           
    g->o0 = (uint64_t)x;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- mov_r_i_l: IB_K_MOVI ---- */
static uint64_t k_mov_r_i_l(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)0x11;                                                              
    for (i = 0; i < it; i++)                                                      
        __asm__ volatile("movl" " " "$0x12345678" ",%[a]" : [a] "+r"(a));                     
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_mov_r_i_l_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)0x11, c = (IB_UL)0x22, e = (IB_UL)0x33, g = (IB_UL)0x44;                    
    for (i = 0; i < it; i++) {                                                    
        __asm__ volatile("movl" " " "$0x12345678" ",%[a]" : [a] "+r"(a));                     
        __asm__ volatile("movl" " " "$0x12345678" ",%[a]" : [a] "+r"(c));                     
        __asm__ volatile("movl" " " "$0x12345678" ",%[a]" : [a] "+r"(e));                     
        __asm__ volatile("movl" " " "$0x12345678" ",%[a]" : [a] "+r"(g));                     
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- mov_r_i_l: IB_KT_MOV ---- */
static inline void k_mov_r_i_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("mov_r_i_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("mov_r_i_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("mov_r_i_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movl" " " "$0x12345678,%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- movzb_r_m_l_base: IB_K_CHASE ---- */
static uint64_t k_movzb_r_m_l_base(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p = (const void *)(b + (((uintptr_t)a << 3) & 448));          
        IB_PROT_X(i);                                                             
        __asm__("movzbl" " " IB_M_BASE ",%[a]" : [a] "=r"(a) : [p] "r"(p), [ix] "r"(ix)      
                 : "memory");                                                     
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_movzb_r_m_l_base_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p0 = (const void *)(b + (((uintptr_t)a << 3) & 448));         
        const void *p1 = (const void *)(b + (((uintptr_t)c << 3) & 448));         
        const void *p2 = (const void *)(b + (((uintptr_t)e << 3) & 448));         
        const void *p3 = (const void *)(b + (((uintptr_t)g << 3) & 448));         
        IB_PROT_X(i);                                                             
        __asm__("movzbl" " " IB_M_BASE ",%[a]" : [a] "=r"(a) : [p] "r"(p0), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movzbl" " " IB_M_BASE ",%[a]" : [a] "=r"(c) : [p] "r"(p1), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movzbl" " " IB_M_BASE ",%[a]" : [a] "=r"(e) : [p] "r"(p2), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movzbl" " " IB_M_BASE ",%[a]" : [a] "=r"(g) : [p] "r"(p3), [ix] "r"(ix)     
                 : "memory");                                                     
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- movzb_r_m_l_base: IB_KT_MOV ---- */
static inline void k_movzb_r_m_l_base_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("movzb_r_m_l_base", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("movzb_r_m_l_base", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("movzb_r_m_l_base", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movzbl" " " IB_M_BASE ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- movzb_r_m_l_index: IB_K_CHASE ---- */
static uint64_t k_movzb_r_m_l_index(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p = (const void *)(b + (((uintptr_t)a << 3) & 448));          
        IB_PROT_X(i);                                                             
        __asm__("movzbl" " " IB_M_IDX ",%[a]" : [a] "=r"(a) : [p] "r"(p), [ix] "r"(ix)      
                 : "memory");                                                     
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_movzb_r_m_l_index_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p0 = (const void *)(b + (((uintptr_t)a << 3) & 448));         
        const void *p1 = (const void *)(b + (((uintptr_t)c << 3) & 448));         
        const void *p2 = (const void *)(b + (((uintptr_t)e << 3) & 448));         
        const void *p3 = (const void *)(b + (((uintptr_t)g << 3) & 448));         
        IB_PROT_X(i);                                                             
        __asm__("movzbl" " " IB_M_IDX ",%[a]" : [a] "=r"(a) : [p] "r"(p0), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movzbl" " " IB_M_IDX ",%[a]" : [a] "=r"(c) : [p] "r"(p1), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movzbl" " " IB_M_IDX ",%[a]" : [a] "=r"(e) : [p] "r"(p2), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movzbl" " " IB_M_IDX ",%[a]" : [a] "=r"(g) : [p] "r"(p3), [ix] "r"(ix)     
                 : "memory");                                                     
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- movzb_r_m_l_index: IB_KT_MOV ---- */
static inline void k_movzb_r_m_l_index_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("movzb_r_m_l_index", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("movzb_r_m_l_index", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("movzb_r_m_l_index", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movzbl" " " IB_M_IDX ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- movzb_r_r_l: IB_K_ZX ---- */
static uint64_t k_movzb_r_r_l(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("movzbl" " " "%%al,%%eax" : [a] "+a"(a));                                        
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_movzb_r_r_l_tp(ib_uw it)                                
{                                                                                 
    return k_movzb_r_r_l(it);                                                            
}

/* ---- movzb_r_r_l: IB_KT_MOV ---- */
static inline void k_movzb_r_r_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("movzb_r_r_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("movzb_r_r_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("movzb_r_r_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movzbl" " " "%%al,%%eax" IB_GETF                                   
                    : [a] "+a"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- movzw_r_m_l_base: IB_K_CHASE ---- */
static uint64_t k_movzw_r_m_l_base(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p = (const void *)(b + (((uintptr_t)a << 3) & 448));          
        IB_PROT_X(i);                                                             
        __asm__("movzwl" " " IB_M_BASE ",%[a]" : [a] "=r"(a) : [p] "r"(p), [ix] "r"(ix)      
                 : "memory");                                                     
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_movzw_r_m_l_base_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p0 = (const void *)(b + (((uintptr_t)a << 3) & 448));         
        const void *p1 = (const void *)(b + (((uintptr_t)c << 3) & 448));         
        const void *p2 = (const void *)(b + (((uintptr_t)e << 3) & 448));         
        const void *p3 = (const void *)(b + (((uintptr_t)g << 3) & 448));         
        IB_PROT_X(i);                                                             
        __asm__("movzwl" " " IB_M_BASE ",%[a]" : [a] "=r"(a) : [p] "r"(p0), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movzwl" " " IB_M_BASE ",%[a]" : [a] "=r"(c) : [p] "r"(p1), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movzwl" " " IB_M_BASE ",%[a]" : [a] "=r"(e) : [p] "r"(p2), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movzwl" " " IB_M_BASE ",%[a]" : [a] "=r"(g) : [p] "r"(p3), [ix] "r"(ix)     
                 : "memory");                                                     
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- movzw_r_m_l_base: IB_KT_MOV ---- */
static inline void k_movzw_r_m_l_base_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("movzw_r_m_l_base", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("movzw_r_m_l_base", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("movzw_r_m_l_base", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movzwl" " " IB_M_BASE ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- movzw_r_m_l_index: IB_K_CHASE ---- */
static uint64_t k_movzw_r_m_l_index(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p = (const void *)(b + (((uintptr_t)a << 3) & 448));          
        IB_PROT_X(i);                                                             
        __asm__("movzwl" " " IB_M_IDX ",%[a]" : [a] "=r"(a) : [p] "r"(p), [ix] "r"(ix)      
                 : "memory");                                                     
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_movzw_r_m_l_index_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p0 = (const void *)(b + (((uintptr_t)a << 3) & 448));         
        const void *p1 = (const void *)(b + (((uintptr_t)c << 3) & 448));         
        const void *p2 = (const void *)(b + (((uintptr_t)e << 3) & 448));         
        const void *p3 = (const void *)(b + (((uintptr_t)g << 3) & 448));         
        IB_PROT_X(i);                                                             
        __asm__("movzwl" " " IB_M_IDX ",%[a]" : [a] "=r"(a) : [p] "r"(p0), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movzwl" " " IB_M_IDX ",%[a]" : [a] "=r"(c) : [p] "r"(p1), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movzwl" " " IB_M_IDX ",%[a]" : [a] "=r"(e) : [p] "r"(p2), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movzwl" " " IB_M_IDX ",%[a]" : [a] "=r"(g) : [p] "r"(p3), [ix] "r"(ix)     
                 : "memory");                                                     
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- movzw_r_m_l_index: IB_KT_MOV ---- */
static inline void k_movzw_r_m_l_index_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("movzw_r_m_l_index", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("movzw_r_m_l_index", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("movzw_r_m_l_index", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movzwl" " " IB_M_IDX ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- movzw_r_r_l: IB_K_ZX ---- */
static uint64_t k_movzw_r_r_l(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("movzwl" " " "%%ax,%%eax" : [a] "+a"(a));                                        
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_movzw_r_r_l_tp(ib_uw it)                                
{                                                                                 
    return k_movzw_r_r_l(it);                                                            
}

/* ---- movzw_r_r_l: IB_KT_MOV ---- */
static inline void k_movzw_r_r_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("movzw_r_r_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("movzw_r_r_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("movzw_r_r_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movzwl" " " "%%ax,%%eax" IB_GETF                                   
                    : [a] "+a"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- movsw_r_r_l: IB_K_ZX ---- */
static uint64_t k_movsw_r_r_l(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("movswl" " " "%%ax,%%eax" : [a] "+a"(a));                                        
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_movsw_r_r_l_tp(ib_uw it)                                
{                                                                                 
    return k_movsw_r_r_l(it);                                                            
}

/* ---- movsw_r_r_l: IB_KT_MOV ---- */
static inline void k_movsw_r_r_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("movsw_r_r_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("movsw_r_r_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("movsw_r_r_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movswl" " " "%%ax,%%eax" IB_GETF                                   
                    : [a] "+a"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- movsw_r_m_l_index: IB_K_CHASE ---- */
static uint64_t k_movsw_r_m_l_index(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p = (const void *)(b + (((uintptr_t)a << 3) & 448));          
        IB_PROT_X(i);                                                             
        __asm__("movswl" " " IB_M_IDX ",%[a]" : [a] "=r"(a) : [p] "r"(p), [ix] "r"(ix)      
                 : "memory");                                                     
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_movsw_r_m_l_index_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    uintptr_t b = (uintptr_t)IB_RBASE();                                          
    for (i = 0; i < it; i++) {                                                    
        const void *p0 = (const void *)(b + (((uintptr_t)a << 3) & 448));         
        const void *p1 = (const void *)(b + (((uintptr_t)c << 3) & 448));         
        const void *p2 = (const void *)(b + (((uintptr_t)e << 3) & 448));         
        const void *p3 = (const void *)(b + (((uintptr_t)g << 3) & 448));         
        IB_PROT_X(i);                                                             
        __asm__("movswl" " " IB_M_IDX ",%[a]" : [a] "=r"(a) : [p] "r"(p0), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movswl" " " IB_M_IDX ",%[a]" : [a] "=r"(c) : [p] "r"(p1), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movswl" " " IB_M_IDX ",%[a]" : [a] "=r"(e) : [p] "r"(p2), [ix] "r"(ix)     
                 : "memory");                                                     
        __asm__("movswl" " " IB_M_IDX ",%[a]" : [a] "=r"(g) : [p] "r"(p3), [ix] "r"(ix)     
                 : "memory");                                                     
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- movsw_r_m_l_index: IB_KT_MOV ---- */
static inline void k_movsw_r_m_l_index_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("movsw_r_m_l_index", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("movsw_r_m_l_index", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("movsw_r_m_l_index", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "movswl" " " IB_M_IDX ",%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- bswap_r__l: IB_K_R1 ---- */
static uint64_t k_bswap_r__l(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0);                                                        
    for (i = 0; i < it; i++)                                                      
        __asm__("bswap" " %[a]" : [a] "+r"(a) : : "cc");                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_bswap_r__l_tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6);                                                        
    for (i = 0; i < it; i++) {                                                    
        __asm__("bswap" " %[a]" : [a] "+r"(a) : : "cc");                             
        __asm__("bswap" " %[c]" : [c] "+r"(c) : : "cc");                             
        __asm__("bswap" " %[e]" : [e] "+r"(e) : : "cc");                             
        __asm__("bswap" " %[g]" : [g] "+r"(g) : : "cc");                             
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- bswap_r__l: IB_KT_MOV ---- */
static inline void k_bswap_r__l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("bswap_r__l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("bswap_r__l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("bswap_r__l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "bswap" " " "%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- cwtl___: IB_K_WIDE ---- */
static uint64_t k_cwtl___(ib_uw it)                                     
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), d = (IB_UL)0;                                             
    for (i = 0; i < it; i++)                                                      
        __asm__("cwtl" : "+a"(a), "+d"(d) : : "cc");                                
    return IB_S2(a, d);                                                           
}                                                                                 
static uint64_t k_cwtl____tp(ib_uw it)                                
{                                                                                 
    ib_uw i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), d = (IB_UL)0;                                             
    for (i = 0; i < it; i++)                                                      
        __asm__("cwtl" : "+a"(a), "+d"(d) : : "cc");                                
    return IB_S2(a, d);                                                           
}

/* ---- cwtl___: IB_KT_MOVW ---- */
static inline void k_cwtl____kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("cwtl___", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("cwtl___", kk, 1, IB_UL);          
    IB_UL ain = a, bin = b;                                                          
    void *p = ib_kbuf_fill((uint64_t)b);                                          
    uintptr_t fv = (uintptr_t)IB_KFL("cwtl___", kk), fl = 0;                            
    __asm__ volatile(IB_SETF "cwtl" IB_GETF                                         
                    : [a] "+a"(a), [d] "+d"(b), [fl] "=&r"(fl)                    
                    : [p] "r"(p), [fv] "r"(fv) : "cc", "memory");                  
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)bin;  g->inf = (uint64_t)fv;          
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}


/* ---------------- 用例表(bpop = 每 op 处理字节数, 供 tput 折 MB/s) ---------------- */
static const ib_case g_cases[] = {
    /* 两 ABI 共有 */
    IB_ROW_K("x86_mov__r_m_l_base",   NULL, mov_r_m_l_base,    4),
    IB_ROW_K("x86_mov__r_r_l",        NULL, mov_r_r_l,         4),
    IB_ROW_K("x86_mov__r_m_l_index",  NULL, mov_r_m_l_index,   4),
    IB_ROW_K("x86_mov__r_m_l_base_sp", NULL, mov_r_m_l_base_sp, 4),
    IB_ROW_K("x86_mov__m_r_l_base",   NULL, mov_m_r_l_base,    4),
    IB_ROW_K("x86_mov__r_i_l",        NULL, mov_r_i_l,         4),
    IB_ROW_K("x86_movzb__r_m_l_base", NULL, movzb_r_m_l_base,  1),
    IB_ROW_K("x86_movzb__r_m_l_index", NULL, movzb_r_m_l_index, 1),
    IB_ROW_K("x86_movzb__r_r_l",      NULL, movzb_r_r_l,       1),
    IB_ROW_K("x86_movzw__r_m_l_base", NULL, movzw_r_m_l_base,  2),
    IB_ROW_K("x86_movzw__r_m_l_index", NULL, movzw_r_m_l_index, 2),
    IB_ROW_K("x86_movzw__r_r_l",      NULL, movzw_r_r_l,       2),
    IB_ROW_K("x86_movsw__r_r_l",      NULL, movsw_r_r_l,       2),
    IB_ROW_K("x86_movsw__r_m_l_index", NULL, movsw_r_m_l_index, 2),
    IB_ROW_K("x86_bswap__r__l",       NULL, bswap_r__l,       0),
    IB_ROW_K("x86_cwtl___",           NULL, cwtl___,          0),
#ifdef __x86_64__
    /* 64 位专有形态 */
    IB_ROW_K("x86_mov__r_m_q_base",   NULL, mov_r_m_q_base,    8),
    IB_ROW_K("x86_mov__r_r_q",        NULL, mov_r_r_q,         8),
    IB_ROW_K("x86_mov__r_m_q_index",  NULL, mov_r_m_q_index,   8),
    IB_ROW_K("x86_mov__r_m_q_rip",    NULL, mov_r_m_q_rip,     8),
    IB_ROW_K("x86_mov__r_m_q_base_sp", NULL, mov_r_m_q_base_sp, 8),
    IB_ROW_K("x86_mov__m_r_q_base",   NULL, mov_m_r_q_base,    8),
    IB_ROW_K("x86_mov__m_r_q_base_sp", NULL, mov_m_r_q_base_sp, 8),
    IB_ROW_K("x86_movabs__r_i_q",     NULL, movabs_r_i_q,      8),
    IB_ROW_K("x86_movsb__r_m_q_base", NULL, movsb_r_m_q_base,  1),
    IB_ROW_K("x86_movsb__r_m_q_index", NULL, movsb_r_m_q_index, 1),
    IB_ROW_K("x86_movsl__r_m_q_base", NULL, movsl_r_m_q_base,  4),
    IB_ROW_K("x86_movsl__r_m_q_index", NULL, movsl_r_m_q_index, 4),
    IB_ROW_K("x86_movsl__r_r_q",      NULL, movsl_r_r_q,       4),
    IB_ROW_K("x86_movsw__r_r_q",      NULL, movsw_r_r_q,       2),
    IB_ROW_K("x86_bswap__r__q",       NULL, bswap_r__q,       0),
    IB_ROW_K("x86_movbe__r_m_q_base", "movbe", movbe_r_m_q_base, 8),
    IB_ROW_K("x86_cltq___",           NULL, cltq___,          0),
    IB_ROW_K("x86_cqto___",           NULL, cqto___,          0),
#endif
};
#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

int main(int argc, char **argv)
{
    ib_init(argc, argv);
    ib_abuf_init();                 /* 只读/写区确定性预置(签名跨机可复现的前提) */
    ib_hdr("mov", NCASES);
    ib_run_cases("mov", g_cases, NCASES);
    return 0;
}
