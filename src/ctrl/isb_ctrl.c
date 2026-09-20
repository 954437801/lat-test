/* isb_ctrl.c —— 栈/上下文家族形态组(grp=ctrl): push/pop/leave/retf/pushf
 *
 * 用例来源 = xperf 三层映射 round5_form_weights.csv 里栈类的实测 k90 形态 +
 * 两个计划锚点, 共 8 条。与计划表的差异(全部以实测为准, 逐条列明):
 *   - 计划写 `push r.r.q`(1.60%) / `pop`(1.60%) / `leave`(0.69%) / `retf`
 *     (0.48%) / `pushf r.f.q`(0.07%) / `pusha all.w` / `popa all.w` / `_BOUND`;
 *     此表里 push 的真实 form_key 是 `push m.r.q/rsp`(6.9960%, 组内第 1 权重),
 *     pop 是 `pop r.m.q/rsp`(0.9464%) —— 首字母 m/r 表示「目的」, "/rsp" 是
 *     push/pop 隐式栈目的数的基址, 故 `push m.r.q/rsp` 就是 `pushq %reg`。
 *   - retf / pushf / pusha / popa / _BOUND 在本表 nf=0(采样窗内没抓到), 按
 *     「计划锚点不可丢」保留 retf + pushf 两条(CSV 无 -> 权重列标 nf=0)。
 *   - pusha/popa/_BOUND 本轮不登记: 三者在 64 位长模式下是**无效操作码**
 *     (pusha/popa 的 0F60/0F61 与 BOUND 的 0FB2 都被 AMD64 移除), 只能 i386
 *     注册; 而 pusha/popa 一次改写全部 8 个 GPR、_BOUND 越界即 #BR(SIGSEGV)
 *     与「链主/循环变量不被污染」冲突。计划把它们列进 ctrl 是按旧权重表的
 *     i386 视角, 本轮以实测 k90 为准, 需要时可另开 i386 专有组。
 *
 * 为什么单独立组(风险隔离): leave/retf 直接改写 rsp/rbp(retf 还改 RIP), 混在
 * 别的组里一旦某条形态算错, 崩的是整组的调用帧; 独立成组则一条崩不拖全族。
 *
 * 机制(细节见 ib_gen.h 第 23 节头注):
 *   - push/pop 族: 每轮 push 与 pop 成对 => 净栈深 0, 用真实栈测(与真码一致)。
 *     被测的落点值取进 %[f] 再 `lea (a,f,2),a` 回灌链主(乘子 3 为奇, 签名不归零)。
 *   - leave/retf 族: 整个循环包在一段 asm 里, 入口把 rsp(及 rbp)切到函数内
 *     static 私有栈, 出口按保存值还原; 崩溃由外层 ib_case_* 的 siglongjmp 兜住
 *     (恢复点与执行体同帧, rsp 一并复原)。签名取「相对私有栈基址的偏移」——
 *     绝对地址跨机不可比, 偏移可。
 *   - 因此 leave/retf 的签名是与 iters 无关的常数: 它的意义是「私有栈没跑飞 +
 *     指令确实执行到了」, 不能像算术族那样证伪折叠; 这两条以 lat/tput 为主。
 *
 * 64 位形态只存在于 x86_64: 内核实例与表项一起 #ifdef(i386 侧只剩 leave/retf)。
 *
 * KAT(与其余 7 组同一机制, 但本组只有 6 条上表):
 *   - push/pop/pushf 六条走 IB_KT_PUSH 与 IB_KT_POPR/POPM/PUSHF(见 ib_gen.h 15Ko):
 *     这一族的输出在栈上 -> 探针从 (%rsp) 回读当 o0, 这一次回读同时验了 rsp
 *     的位移(位移错就读到另一个槽)。标志全掩码上表(push/pop/pushf 都不改标志
 *     -> outf == inf)。
 *   - pop 族造栈帧压的那个已知值不是一条, 而是分两支(写成同一值会让判据
 *     不可证伪): pop <reg>(POPR) 的源槽就是 g_kbuf(整窗广播 = i1) -> o0 = i1;
 *     而 pop <mem>(POPM) 的目的槽也已被广播成 i1, 若再压 i1, 「pop 真写了内
 *     存」与「pop 什么都没写」回读同值 -> 压的是 %[a] = i0, 于是 o0 只能是
 *     i0(理由也写在 IB_KT_POPM 头注里)。
 *   - 本组实测结论(2026-09-06, 四重证据齐): 6 条 kat_st=OK 8/8(四形态零告警)
 *     + kat_audit.py 审=6 通过=6(栈族规则在那个独立第二实现里单独写) + kat_neg.sh 9
 *     处注入全检出 + box31 真机 x86_64 6 行 OK、零 KATFAIL、零 SIGILL。
 *   - 计时签名撞车(本轮改判: 不当缺陷, 口径见 docs/设计/功能测试与KAT.md):
 *     q_dup.sh 实测 push m.r.q-rsp / pop r.m.q-rsp / pop m.m.q-rsp 三条 lat_sig
 *     与 tput_sig 全同值 —— 骨架本就是「每轮 push+pop 成对 => 净栈 0, 回读同一
 *     个值再 lea 回灌」, 三条的值流逐位相同不是译错, 而是骨架使然; 它们的
 *     lat_ns/tput_ops 仍各自一行可对照, 语义则由上面那 6 条 KAT 分别兜住。
 *     (leave/retf 两条的签名是与输入无关的常数, 见上面机制段, 同一口径。)
 *   - leave / retf 两条**不接** KAT, 理由不是没时间做, 是上表没有意义: 它俩的
 *     可观测效果只有 rsp/rbp/rip 的**地址**变化, 绝对地址跨机不可比, 而相对
 *     私有栈基址的偏移又与输入无关(计时签名已经是「私有栈没跑飞 + 指令确实
 *     执行到」的常数断言) -> 拿一次采到的地址写进表要求另一台机器复现, 只会
 *     造成假 KATFAIL。这两条以 lat/tput 为主(与本文件开头的机制说明一致)。
 *   - push 的内存侧(m.m)在探针里改成读 g_kbuf(整窗广播 = i1), 与 logic/mov 组
 *     同一处理: 计时骨架读的是 g_rbuf 里那个与表无关的预置值 -> 不可审。
 *   - 推论(真机实测已确认): 本组 i386 侧接 KAT 的行数是 **0**(六条全在
 *     #ifdef __x86_64__ 里) -> 别把「i386 二进制全 OK」当成本组的跨 ABI 证据,
 *     它只说明 leave/retf 两行未接表。拿 i386 注入真值表时报的是
 *     「本 ABI 无接 KAT 的行」而不是 KATFAIL(见 _tmp/box31_neg_run.sh)。
 */
#include "ib_core.h"
#include "ib_buf.h"
#include "isb_ctrl_kat.h"   /* KAT 真值表(采集后生成; 未取数时全 UNSET) */

/* ---------------- 64 位形态(仅 x86_64) ---------------- */
#ifdef __x86_64__
/* ---- push_m_r_q_rsp: IB_K_PUSH ---- */
static uint64_t k_push_m_r_q_rsp(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)((IB_SEED(0) & 0xffff) | 1), f = (IB_UQ)0;                            
    const void *p = (const void *)IB_RBASE();                                     
    uintptr_t ix = 0;                                                             
    for (i = 0; i < it; i++)                                                      
        __asm__("pushq" " " "%[a]" "\n\t"                                               
                "pop" "q" " %[f]\n\t"                                             
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(a), [f] "=&r"(f)                                       
                : [p] "r"(p), [ix] "r"(ix) : "memory");                           
    return IB_S1(a);                                                              
}                                                                                 
static uint64_t k_push_m_r_q_rsp_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)((IB_SEED(0) & 0xffff) | 1), f = (IB_UQ)0;                            
    IB_UQ c = (IB_UQ)((IB_SEED(2) & 0xffff) | 1), g = (IB_UQ)0;                            
    IB_UQ e = (IB_UQ)((IB_SEED(4) & 0xffff) | 1), h = (IB_UQ)0;                            
    IB_UQ k = (IB_UQ)((IB_SEED(6) & 0xffff) | 1), m = (IB_UQ)0;                            
    const void *p = (const void *)IB_RBASE();                                     
    uintptr_t ix = 0;                                                             
    for (i = 0; i < it; i++) {                                                    
        __asm__("pushq" " " "%[a]" "\n\t" "pop" "q" " %[f]\n\t"                         
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(a), [f] "=&r"(f)                                       
                : [p] "r"(p), [ix] "r"(ix) : "memory");                           
        __asm__("pushq" " " "%[a]" "\n\t" "pop" "q" " %[f]\n\t"                         
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(c), [f] "=&r"(g)                                       
                : [p] "r"(p), [ix] "r"(ix) : "memory");                           
        __asm__("pushq" " " "%[a]" "\n\t" "pop" "q" " %[f]\n\t"                         
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(e), [f] "=&r"(h)                                       
                : [p] "r"(p), [ix] "r"(ix) : "memory");                           
        __asm__("pushq" " " "%[a]" "\n\t" "pop" "q" " %[f]\n\t"                         
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(k), [f] "=&r"(m)                                       
                : [p] "r"(p), [ix] "r"(ix) : "memory");                           
    }                                                                             
    return IB_S4(a, c, e, k);                                                     
}

/* ---- push_m_r_q_rsp: IB_KT_PUSH ---- */
static inline void k_push_m_r_q_rsp_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UQ a = (IB_UQ)IB_KIN8("push_m_r_q_rsp", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("push_m_r_q_rsp", kk, 1, IB_UQ);          
    IB_UQ x = (IB_UQ)0, y = (IB_UQ)0;                                                      
    void *p = ib_kbuf_fill((uint64_t)b);                                          
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                
    uintptr_t fv = (uintptr_t)IB_KFL("push_m_r_q_rsp", kk), fl = 0;                            
    __asm__ volatile(IB_SETF "pushq" " " "%[a]" "\n\t"                                     
                     "mov" "q" " (%%" IB_REG_SP "),%[x]\n\t" "pop" "q" " %[y]" IB_GETF 
                    : [x] "=&r"(x), [y] "=&r"(y), [fl] "=&r"(fl)                   
                    : [a] "r"(a), [b] "r"(b), [p] "r"(p), [ix] "r"(ix),             
                      [fv] "r"(fv) : "cc", "memory");                             
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;           
    g->o0 = (uint64_t)x;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- push_m_i_q_rsp: IB_K_PUSH ---- */
static uint64_t k_push_m_i_q_rsp(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)((IB_SEED(0) & 0xffff) | 1), f = (IB_UQ)0;                            
    const void *p = (const void *)IB_RBASE();                                     
    uintptr_t ix = 0;                                                             
    for (i = 0; i < it; i++)                                                      
        __asm__("pushq" " " "$5" "\n\t"                                               
                "pop" "q" " %[f]\n\t"                                             
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(a), [f] "=&r"(f)                                       
                : [p] "r"(p), [ix] "r"(ix) : "memory");                           
    return IB_S1(a);                                                              
}                                                                                 
static uint64_t k_push_m_i_q_rsp_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)((IB_SEED(0) & 0xffff) | 1), f = (IB_UQ)0;                            
    IB_UQ c = (IB_UQ)((IB_SEED(2) & 0xffff) | 1), g = (IB_UQ)0;                            
    IB_UQ e = (IB_UQ)((IB_SEED(4) & 0xffff) | 1), h = (IB_UQ)0;                            
    IB_UQ k = (IB_UQ)((IB_SEED(6) & 0xffff) | 1), m = (IB_UQ)0;                            
    const void *p = (const void *)IB_RBASE();                                     
    uintptr_t ix = 0;                                                             
    for (i = 0; i < it; i++) {                                                    
        __asm__("pushq" " " "$5" "\n\t" "pop" "q" " %[f]\n\t"                         
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(a), [f] "=&r"(f)                                       
                : [p] "r"(p), [ix] "r"(ix) : "memory");                           
        __asm__("pushq" " " "$5" "\n\t" "pop" "q" " %[f]\n\t"                         
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(c), [f] "=&r"(g)                                       
                : [p] "r"(p), [ix] "r"(ix) : "memory");                           
        __asm__("pushq" " " "$5" "\n\t" "pop" "q" " %[f]\n\t"                         
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(e), [f] "=&r"(h)                                       
                : [p] "r"(p), [ix] "r"(ix) : "memory");                           
        __asm__("pushq" " " "$5" "\n\t" "pop" "q" " %[f]\n\t"                         
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(k), [f] "=&r"(m)                                       
                : [p] "r"(p), [ix] "r"(ix) : "memory");                           
    }                                                                             
    return IB_S4(a, c, e, k);                                                     
}

/* ---- push_m_i_q_rsp: IB_KT_PUSH ---- */
static inline void k_push_m_i_q_rsp_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UQ a = (IB_UQ)IB_KIN8("push_m_i_q_rsp", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("push_m_i_q_rsp", kk, 1, IB_UQ);          
    IB_UQ x = (IB_UQ)0, y = (IB_UQ)0;                                                      
    void *p = ib_kbuf_fill((uint64_t)b);                                          
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                
    uintptr_t fv = (uintptr_t)IB_KFL("push_m_i_q_rsp", kk), fl = 0;                            
    __asm__ volatile(IB_SETF "pushq" " " "$5" "\n\t"                                     
                     "mov" "q" " (%%" IB_REG_SP "),%[x]\n\t" "pop" "q" " %[y]" IB_GETF 
                    : [x] "=&r"(x), [y] "=&r"(y), [fl] "=&r"(fl)                   
                    : [a] "r"(a), [b] "r"(b), [p] "r"(p), [ix] "r"(ix),             
                      [fv] "r"(fv) : "cc", "memory");                             
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;           
    g->o0 = (uint64_t)x;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- push_m_m_q_rsp: IB_K_PUSH ---- */
static uint64_t k_push_m_m_q_rsp(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)((IB_SEED(0) & 0xffff) | 1), f = (IB_UQ)0;                            
    const void *p = (const void *)IB_RBASE();                                     
    uintptr_t ix = 0;                                                             
    for (i = 0; i < it; i++)                                                      
        __asm__("pushq" " " IB_M_BASE "\n\t"                                               
                "pop" "q" " %[f]\n\t"                                             
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(a), [f] "=&r"(f)                                       
                : [p] "r"(p), [ix] "r"(ix) : "memory");                           
    return IB_S1(a);                                                              
}                                                                                 
static uint64_t k_push_m_m_q_rsp_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)((IB_SEED(0) & 0xffff) | 1), f = (IB_UQ)0;                            
    IB_UQ c = (IB_UQ)((IB_SEED(2) & 0xffff) | 1), g = (IB_UQ)0;                            
    IB_UQ e = (IB_UQ)((IB_SEED(4) & 0xffff) | 1), h = (IB_UQ)0;                            
    IB_UQ k = (IB_UQ)((IB_SEED(6) & 0xffff) | 1), m = (IB_UQ)0;                            
    const void *p = (const void *)IB_RBASE();                                     
    uintptr_t ix = 0;                                                             
    for (i = 0; i < it; i++) {                                                    
        __asm__("pushq" " " IB_M_BASE "\n\t" "pop" "q" " %[f]\n\t"                         
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(a), [f] "=&r"(f)                                       
                : [p] "r"(p), [ix] "r"(ix) : "memory");                           
        __asm__("pushq" " " IB_M_BASE "\n\t" "pop" "q" " %[f]\n\t"                         
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(c), [f] "=&r"(g)                                       
                : [p] "r"(p), [ix] "r"(ix) : "memory");                           
        __asm__("pushq" " " IB_M_BASE "\n\t" "pop" "q" " %[f]\n\t"                         
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(e), [f] "=&r"(h)                                       
                : [p] "r"(p), [ix] "r"(ix) : "memory");                           
        __asm__("pushq" " " IB_M_BASE "\n\t" "pop" "q" " %[f]\n\t"                         
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(k), [f] "=&r"(m)                                       
                : [p] "r"(p), [ix] "r"(ix) : "memory");                           
    }                                                                             
    return IB_S4(a, c, e, k);                                                     
}

/* ---- push_m_m_q_rsp: IB_KT_PUSH ---- */
static inline void k_push_m_m_q_rsp_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UQ a = (IB_UQ)IB_KIN8("push_m_m_q_rsp", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("push_m_m_q_rsp", kk, 1, IB_UQ);          
    IB_UQ x = (IB_UQ)0, y = (IB_UQ)0;                                                      
    void *p = ib_kbuf_fill((uint64_t)b);                                          
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                
    uintptr_t fv = (uintptr_t)IB_KFL("push_m_m_q_rsp", kk), fl = 0;                            
    __asm__ volatile(IB_SETF "pushq" " " IB_M_BASE "\n\t"                                     
                     "mov" "q" " (%%" IB_REG_SP "),%[x]\n\t" "pop" "q" " %[y]" IB_GETF 
                    : [x] "=&r"(x), [y] "=&r"(y), [fl] "=&r"(fl)                   
                    : [a] "r"(a), [b] "r"(b), [p] "r"(p), [ix] "r"(ix),             
                      [fv] "r"(fv) : "cc", "memory");                             
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;           
    g->o0 = (uint64_t)x;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- pop_r_m_q_rsp: IB_K_POPR ---- */
static uint64_t k_pop_r_m_q_rsp(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)((IB_SEED(0) & 0xffff) | 1), f = (IB_UQ)0;                            
    for (i = 0; i < it; i++)                                                      
        __asm__("push" "q" " %[a]\n\t"                                            
                "popq" " %[f]\n\t"                                                  
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(a), [f] "=&r"(f) : : "memory");                        
    return IB_S1(a);                                                              
}                                                                                 
static uint64_t k_pop_r_m_q_rsp_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)((IB_SEED(0) & 0xffff) | 1), f = (IB_UQ)0;                            
    IB_UQ c = (IB_UQ)((IB_SEED(2) & 0xffff) | 1), g = (IB_UQ)0;                            
    IB_UQ e = (IB_UQ)((IB_SEED(4) & 0xffff) | 1), h = (IB_UQ)0;                            
    IB_UQ k = (IB_UQ)((IB_SEED(6) & 0xffff) | 1), m = (IB_UQ)0;                            
    for (i = 0; i < it; i++) {                                                    
        __asm__("push" "q" " %[a]\n\t" "popq" " %[f]\n\t"                           
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(a), [f] "=&r"(f) : : "memory");                        
        __asm__("push" "q" " %[a]\n\t" "popq" " %[f]\n\t"                           
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(c), [f] "=&r"(g) : : "memory");                        
        __asm__("push" "q" " %[a]\n\t" "popq" " %[f]\n\t"                           
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(e), [f] "=&r"(h) : : "memory");                        
        __asm__("push" "q" " %[a]\n\t" "popq" " %[f]\n\t"                           
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(k), [f] "=&r"(m) : : "memory");                        
    }                                                                             
    return IB_S4(a, c, e, k);                                                     
}

/* ---- pop_r_m_q_rsp: IB_KT_POPR ---- */
static inline void k_pop_r_m_q_rsp_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UQ a = (IB_UQ)IB_KIN8("pop_r_m_q_rsp", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("pop_r_m_q_rsp", kk, 1, IB_UQ);          
    IB_UQ ain = a;                                                                   
    void *p = ib_kbuf_fill((uint64_t)b);                                          
    uintptr_t fv = (uintptr_t)IB_KFL("pop_r_m_q_rsp", kk), fl = 0;                            
    __asm__ volatile(IB_SETF "push" "q" " %[b]\n\t" "popq" " %[a]" IB_GETF             
                    : [a] "+r"(a), [fl] "=&r"(fl)                                 
                    : [b] "r"(b), [p] "r"(p), [fv] "r"(fv) : "cc", "memory");       
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- pop_m_m_q_rsp: IB_K_POPM ---- */
static uint64_t k_pop_m_m_q_rsp(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)((IB_SEED(0) & 0xffff) | 1), f = (IB_UQ)0;                            
    void *w = (void *)IB_WBASE();                                                 
    for (i = 0; i < it; i++)                                                      
        __asm__("push" "q" " %[a]\n\t"                                            
                "popq" " " IB_W_BASE "\n\t"                                               
                "mov" "q" " " IB_W_BASE ",%[f]\n\t"                                     
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(a), [f] "=&r"(f) : [w] "r"(w) : "memory");             
    return IB_S1(a);                                                              
}                                                                                 
static uint64_t k_pop_m_m_q_rsp_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)((IB_SEED(0) & 0xffff) | 1), f = (IB_UQ)0;                            
    IB_UQ c = (IB_UQ)((IB_SEED(2) & 0xffff) | 1), g = (IB_UQ)0;                            
    IB_UQ e = (IB_UQ)((IB_SEED(4) & 0xffff) | 1), h = (IB_UQ)0;                            
    IB_UQ k = (IB_UQ)((IB_SEED(6) & 0xffff) | 1), m = (IB_UQ)0;                            
    void *w = (void *)IB_WBASE();                                                 
    for (i = 0; i < it; i++) {                                                    
        __asm__("push" "q" " %[a]\n\t" "popq" " " IB_W_BASE "\n\t"                        
                "mov" "q" " " IB_W_BASE ",%[f]\n\t"                                     
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(a), [f] "=&r"(f) : [w] "r"(w) : "memory");             
        __asm__("push" "q" " %[a]\n\t" "popq" " " IB_W_BASE "\n\t"                        
                "mov" "q" " " IB_W_BASE ",%[f]\n\t"                                     
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(c), [f] "=&r"(g) : [w] "r"(w) : "memory");             
        __asm__("push" "q" " %[a]\n\t" "popq" " " IB_W_BASE "\n\t"                        
                "mov" "q" " " IB_W_BASE ",%[f]\n\t"                                     
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(e), [f] "=&r"(h) : [w] "r"(w) : "memory");             
        __asm__("push" "q" " %[a]\n\t" "popq" " " IB_W_BASE "\n\t"                        
                "mov" "q" " " IB_W_BASE ",%[f]\n\t"                                     
                "lea" "q" " (%[a],%[f],2),%[a]"                                   
                : [a] "+r"(k), [f] "=&r"(m) : [w] "r"(w) : "memory");             
    }                                                                             
    return IB_S4(a, c, e, k);                                                     
}

/* ---- pop_m_m_q_rsp: IB_KT_POPM ---- */
static inline void k_pop_m_m_q_rsp_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UQ b = (IB_UQ)IB_KIN8("pop_m_m_q_rsp", kk, 1, IB_UQ), x = (IB_UQ)0;                                
    IB_UQ a = (IB_UQ)IB_KIN8("pop_m_m_q_rsp", kk, 0, IB_UQ);                                           
    void *p = ib_kbuf_fill((uint64_t)b);                                          
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                
    uintptr_t fv = (uintptr_t)IB_KFL("pop_m_m_q_rsp", kk), fl = 0;                            
    __asm__ volatile(IB_SETF "push" "q" " %[a]\n\t" "popq" " " "8(%[p])" "\n\t"                
                     "mov" "q" " " "8(%[p])" ",%[x]" IB_GETF                                
                    : [x] "=&r"(x), [fl] "=&r"(fl)                                 
                    : [a] "r"(a), [b] "r"(b), [p] "r"(p), [ix] "r"(ix),             
                      [fv] "r"(fv) : "cc", "memory");                             
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;           
    g->o0 = (uint64_t)x;   g->o1 = (uint64_t)b;   /* o0 预期 = i0(见上方注释) */      
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- pushf_r_f_q: IB_K_PUSHF ---- */
static uint64_t k_pushf_r_f_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)0, f = (IB_UQ)0;                                                      
    for (i = 0; i < it; i++)                                                      
        __asm__("pushfq" "\n\t"                                                       
                "pop" "q" " %[f]\n\t"                                             
                "add" "q" " %[f],%[a]"                                            
                : [a] "+r"(a), [f] "=&r"(f) : : "memory");                        
    return IB_S1(a);                                                              
}                                                                                 
static uint64_t k_pushf_r_f_q_tp(unsigned long long it)                                
{                                                                                 
    return k_pushf_r_f_q(it);                                                            
}

/* ---- pushf_r_f_q: IB_KT_PUSHF ---- */
static inline void k_pushf_r_f_q_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UQ b = (IB_UQ)IB_KIN8("pushf_r_f_q", kk, 1, IB_UQ), x = (IB_UQ)0;                                
    IB_UQ a = (IB_UQ)IB_KIN8("pushf_r_f_q", kk, 0, IB_UQ);                                           
    void *p = ib_kbuf_fill((uint64_t)b);                                          
    uintptr_t fv = (uintptr_t)IB_KFL("pushf_r_f_q", kk), fl = 0;                            
    __asm__ volatile(IB_SETF "pushfq" "\n\t"                                              
                     "mov" "q" " (%%" IB_REG_SP "),%[x]\n\t" "popf" "q" IB_GETF     
                    : [x] "=&r"(x), [fl] "=&r"(fl)                                 
                    : [a] "r"(a), [b] "r"(b), [p] "r"(p), [fv] "r"(fv)                
                    : "cc", "memory");                                            
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;           
    g->o0 = (uint64_t)x & IB_FLG_MASK;  g->o1 = (uint64_t)b;                        
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

#endif

/* ---------------- 两 ABI 共有形态(无操作数, 尺寸由 ABI 定) ---------------- */
/* ---- leave__: IB_K_LEAVE ---- */
static uint64_t k_leave__(unsigned long long it)                                     
{                                                                                 
    static unsigned char sb[4096] __attribute__((aligned(64)));                   
    volatile uint64_t *slot = (volatile uint64_t *)sb + 128;                      
    uintptr_t base = (uintptr_t)sb, obp = 0, ors = 0;                             
    register uintptr_t vsp __asm__(IB_RG_A);                                      
    register uintptr_t vbp __asm__(IB_RG_B);                                      
    register uintptr_t vlk __asm__(IB_RG_C) = (uintptr_t)slot;                    
    register uintptr_t vcn __asm__(IB_RG_E) = (uintptr_t)it;                      
    if (!it)                                                                      
        return IB_S1(0);                                                          
    *slot = (uint64_t)(uintptr_t)slot;                                            
    __asm__ volatile(                                                             
        "mov" IB_SSTK " %%" IB_REG_SP ",%[vsp]\n\t"                               
        "mov" IB_SSTK " %%" IB_REG_BP ",%[vbp]\n\t"                               
        "mov" IB_SSTK " %[vlk],%%" IB_REG_BP "\n\t"                               
        "mov" IB_SSTK " %[vlk],%%" IB_REG_SP "\n\t"                               
        "2:\n\t"                                                                  
        "dec" IB_SSTK " %[vcn]\n\t"                                               
        "leave" "\n\t"                                                               
        "jnz 2b\n\t"                                                              
        "mov" IB_SSTK " %%" IB_REG_BP ",%[obp]\n\t"                               
        "mov" IB_SSTK " %%" IB_REG_SP ",%[ors]\n\t"                               
        "mov" IB_SSTK " %[vsp],%%" IB_REG_SP "\n\t"                               
        "mov" IB_SSTK " %[vbp],%%" IB_REG_BP "\n\t"                               
        : [vsp] "=&r"(vsp), [vbp] "=&r"(vbp), [obp] "=&r"(obp),                   
          [ors] "=&r"(ors), [vcn] "+r"(vcn)                                       
        : [vlk] "r"(vlk) : "memory", "cc");                                       
    return IB_S2((uint64_t)(obp - base), (uint64_t)(ors - base));                 
}                                                                                 
static uint64_t k_leave___tp(unsigned long long it)                                
{                                                                                 
    return k_leave__(it);                                                            
}

#ifdef __x86_64__
/* ---- retf__: IB_K_RETF ---- */
static uint64_t k_retf__(unsigned long long it)
{
    static unsigned char sb[4096] __attribute__((aligned(64)));
    uintptr_t base = (uintptr_t)sb;
    uintptr_t vsp = 0, ors = 0, rfr = 0;
    uintptr_t vtop = (uintptr_t)sb + 2048;
    uintptr_t vrb = 0;
    uintptr_t vrd = 0;
    uintptr_t vcn = (uintptr_t)it;
    if (!it)
        return IB_S1(0);
    __asm__ volatile(
        "mov" IB_SSTK " %%" IB_REG_SP ",%[vsp]\n\t"
        "mov" IB_SSTK " %[vtop],%%" IB_REG_SP "\n\t"
        "lea" IB_SSTK " " IB_LBL_ADDR ",%[vrb]\n\t"
        "xor" IB_SSTK " %[vrd],%[vrd]\n\t"
        "movw %%cs,%%" IB_RG_D16 "\n\t"
        "push" IB_SSTK " %[vrd]\n\t"
        "push" IB_SSTK " %[vrb]\n\t"
        "mov" IB_SSTK " %%" IB_REG_SP ",%[rfr]\n\t"
        "3:\n\t"
        "dec" IB_SSTK " %[vcn]\n\t"
        "mov" IB_SSTK " %[rfr],%%" IB_REG_SP "\n\t"
        "retfq" "\n\t"
        "8:\n\t"
        "jnz 3b\n\t"
        "mov" IB_SSTK " %%" IB_REG_SP ",%[ors]\n\t"
        "mov" IB_SSTK " %[vsp],%%" IB_REG_SP "\n\t"
        : [vsp] "=&r"(vsp), [ors] "=&r"(ors), [rfr] "=&r"(rfr),
          [vrb] "=&r"(vrb), [vrd] "=&r"(vrd), [vcn] "+r"(vcn)
        : [vtop] "r"(vtop) : "memory", "cc");
    return IB_S2((uint64_t)(ors - base), (uint64_t)(rfr - base));
}
static uint64_t k_retf___tp(unsigned long long it)
{
    return k_retf__(it);
}

#else
/* ---- retf__: IB_K_RETF ---- */
static uint64_t k_retf__(unsigned long long it)                                     
{                                                                                 
    static unsigned char sb[4096] __attribute__((aligned(64)));                   
    uintptr_t base = (uintptr_t)sb;                                               
    uintptr_t vsp = 0, ors = 0, rfr = 0;                                          
    uintptr_t vtop = (uintptr_t)sb + 2048;
    uintptr_t vrb = 0;
    uintptr_t vrd = 0;
    uintptr_t vcn = (uintptr_t)it;
    if (!it)                                                                      
        return IB_S1(0);                                                          
    __asm__ volatile(                                                             
        "mov" IB_SSTK " %%" IB_REG_SP ",%[vsp]\n\t"                               
        "mov" IB_SSTK " %[vtop],%%" IB_REG_SP "\n\t"                              
        "lea" IB_SSTK " " IB_LBL_ADDR ",%[vrb]\n\t"                               
        "xor" IB_SSTK " %[vrd],%[vrd]\n\t"                                        
        "movw %%cs,%%" IB_RG_D16 "\n\t"                                           
        "push" IB_SSTK " %[vrd]\n\t"                                              
        "push" IB_SSTK " %[vrb]\n\t"                                              
        "mov" IB_SSTK " %%" IB_REG_SP ",%[rfr]\n\t"                               
        "3:\n\t"                                                                  
        "dec" IB_SSTK " %[vcn]\n\t"                                               
        "mov" IB_SSTK " %[rfr],%%" IB_REG_SP "\n\t"                               
        "retf" "\n\t"                                                               
        "8:\n\t"                                                                  
        "jnz 3b\n\t"                                                              
        "mov" IB_SSTK " %%" IB_REG_SP ",%[ors]\n\t"                               
        "mov" IB_SSTK " %[vsp],%%" IB_REG_SP "\n\t"                               
        : [vsp] "=&r"(vsp), [ors] "=&r"(ors), [rfr] "=&r"(rfr),                   
          [vrb] "=&r"(vrb), [vrd] "=&r"(vrd), [vcn] "+r"(vcn)                       
        : [vtop] "r"(vtop) : "memory", "cc");                                     
    return IB_S2((uint64_t)(ors - base), (uint64_t)(rfr - base));                 
}                                                                                 
static uint64_t k_retf___tp(unsigned long long it)                                
{                                                                                 
    return k_retf__(it);                                                            
}

#endif

/* ---------------- 用例表(bpop = 每 op 处理字节数, 供 tput 折 MB/s) ------------ */
static const ib_case g_cases[] = {
    /* 两 ABI 共有 */
    IB_ROW  ("x86_leave___",            NULL, leave__),
    IB_ROW  ("x86_retf___",             NULL, retf__),
#ifdef __x86_64__
    /* 64 位专有形态 */
    IB_ROW_K("x86_push__m_r_q_rsp",     NULL, push_m_r_q_rsp,  8),
    IB_ROW_K("x86_push__m_i_q_rsp",     NULL, push_m_i_q_rsp,  8),
    IB_ROW_K("x86_push__m_m_q_rsp",     NULL, push_m_m_q_rsp,  8),
    IB_ROW_K("x86_pop__r_m_q_rsp",      NULL, pop_r_m_q_rsp,   8),
    IB_ROW_K("x86_pop__m_m_q_rsp",      NULL, pop_m_m_q_rsp,   8),
    IB_ROW_K("x86_pushf__r_f_q",        NULL, pushf_r_f_q,     8),
#endif
};
#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

int main(int argc, char **argv)
{
    ib_init(argc, argv);
    ib_abuf_init();                 /* 只读/写区确定性预置(签名跨机可复现的前提) */
    ib_hdr("ctrl", NCASES);
    ib_run_cases("ctrl", g_cases, NCASES);
    return 0;
}
