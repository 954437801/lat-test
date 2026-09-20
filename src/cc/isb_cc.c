/* isb_cc.c —— 标志消费家族形态组(grp=cc): jcc / setcc / cmovcc
 *
 * 用例来源 = xperf 三层映射 round5_form_weights.csv 的实测 k90 形态, 共 44 条
 * (jcc 16 + setcc 13 + cmovcc 15), 计数口径与计划表一致: 「每个助记符取其权重
 * 最高的那条形态」。与计划的字面差异(以实测为准):
 *   - jcc 的真实 form_key 是 `je .` / `jne .` —— 点号表示「无显式操作数」, 即
 *     rel8/rel32 由链接器决定; 计划示意的 `jcc rel32` 在表里不存在 -> case 名
 *     是 x86_je___ 而不是 x86_jne__rel32(isbench.py 的 WARM_SENT 必须按前者登记)。
 *   - setcc 一律是 `setcc r.f.b/flags`(f.b = 8 位目的寄存器, /flags = 隐式标志
 *     源), cmovcc 一律是 `cmovcc r.rc.q|l/flags`。
 *   - 实测 16 条 jcc 形态 = 采样里出现的 15 种 cc + jno(nf=0, 计划锚点保留);
 *     setp/seto/setno/cmovnp 在表里 nf=0 且计划也未点名 -> 本轮不登记。
 *   - cmovcc 的 .q 形态只在 x86_64 存在(REX.W 是 64 位模式专属) -> 9 条 .q 随
 *     内核实例一起 #ifdef, i386 侧本组只剩 35 条。
 *
 * 为什么独立成组(成本结构, 不是权重): jcc 是全家唯一「被测不写任何寄存器」的
 * 形态 —— 它的 lat 反映的是分支/TB 边界开销, 与 setcc/cmovcc 的值链延迟不是同
 * 一种量; 混进 alu/logic 会把那两组的组内横比拉歪。三者同组的理由是它们**共享
 * 同一个被测面**(flags 的语义译错在这里最显形), 且 jcc 的骨架与另两条同构。
 *
 * 机制(细节见 ib_gen.h 第 24 节头注): 骨架 `lea ×5 / addb $1,%[n] / cmpb %[n],%b[a]`
 * 造出五个都不塌陷的条件码(标志源 = 链主低字节 vs 256 周期计数器, 两边都在变,
 * 所以 ZF 真会翻、CF/SF/OF/PF 互不退化), 再由各族放大器把「这一轮的判断」永久
 * 折回链主。
 *
 * 交付口径(本轮改判, 下面那段 v1->v5 不是门槛而是记账):
 *   正确性 = 下面的 KAT 逐字段比对(单发执行、错在哪个操作数/标志直接点名);
 *   计时列只要求跨 run/跨机可复现, 「两条 case 同签名」不再当缺陷处理。
 *   链形仍一路改到 v5 的理由不是“撞签名不好看”, 而是“静默塌缩”会让整族
 *   从计时列里拿不出任何信息: v1 只有 7/44 唯一(and 把链主压到 2 bit、
 *   比的是常数 -> CF/OF/ZF 恒 0), v2 20/44(宽 vs 宽 -> ZF 永不出现, jb≡jbe 等 4 对),
 *   v3 被否(判断不依赖链主, 被测掉出关键路径), v4 23/44 且 11/15 条 cmov 的 lat_sig
 *   全等于 IB_S1(1) —— 链主被 `cmov→a=2a` 的偶数乘推进了 a=0 吸收态, 等于整族没测。
 *   v5 起用三条不变量(判断同时依赖链主与自变量 / 折叠步必奇数可逆 / 折叠点不覆写
 *   已判过的位), 实测 **x86_64-linux 侧 44/44 条 lat_sig 与 tput_sig 均唯一**。
 *   两 ABI 侧条数不同(i386 35), 唯一性审计在 x86_64 上做。
 *
 * KAT(与 flag/alu/logic/shift/bits 组同一机制): 每个计时内核下面紧跟一行
 * IB_KT_* 探针, 只执行 1 次、不进循环(模板见第 15Km 节)。本组与其他组最大的
 * 区别是「条件不注入」: jcc/setcc/cmovcc 自己都不产生标志, 输入条件得由探针里
 * 一次真 cmp 现生成 -> inf 就是那次比较的实测产物, 于是三条断言同时成立:
 *   inf == cmp(i0,i1) 的架构定义(SUBTRACT 六位) —— 连采到的标志本身也被复核
 *   outf == inf —— 三条指令都不得改标志(比只验判断更严)
 *   o0 == 判断结果 —— setcc 目的字节 0/1、cmov 选通后的 dest、jcc 走的路径 0/1
 * cmov 的 dest/src 直接复用比较的那两个操作数(o0 = cc ? i1 : i0), 两个输入槽
 * 就够用, 不必再开第三个入值。
 * 探针骨架固定 32 位(不跟 IB_WSUF): 计时内核按 ABI 选宽是对的(i386 没有 64 位
 * 寄存器), 但校验内核跟着选宽就会让 i386 拿到另一套输入(输入由值类型截断),
 * 一张表两 ABI 共用就变成假不匹配。cmov 的 .q 形态本身只在 x86_64 存在,
 * 内核/探针/表行同在一段 #ifdef 里, 不受这一条约束。
 *
 * 本组实测结论(2026-09-06, 四重证据齐): 44 条 kat_st=OK 8/8(四形态零告警)
 * + kat_audit.py 审=44 通过=44 + kat_neg.sh 9 处注入全检出 + box31 真机 x86_64
 * 44 行 OK / i386 35 行 OK、零 KATFAIL、零 SIGILL。表是在「SETCC/JCC 探针里让
 * k%4==0 那两组输入故意相等(b = a, 为了把 ZF=1 那一支补上: 两个随机数不相等
 * 是近乎必然 -> ZF 恒 0 -> je/sete 的 true 分支一次也走不到, 实测首版 44 条里
 * jcc/setcc 的 o0 各 8 组全同值)」之后 FORCE=1 重采的: 旧表随这条改动立即失效
 * (实测 jcc/setcc 全族 KATFAIL k=0 i1.l, cmov 未打此补丁所以不动)。教训记死:
 * 改探针的输入生成规则 = 改真值表, 必须整组重采, 不能只改源码。
 */
#include "ib_core.h"
#include "ib_buf.h"
#include "isb_cc_kat.h"      /* KAT 真值表(采集后生成; 未取数时全 UNSET) */

/* ---------------- jcc(16: 实测 15 + jno 锚点) ---------------- */
/* ---- je__: IB_K_JCC ---- */
static uint64_t k_je__(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "e" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_je___tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "e" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "e" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+b"(e), [n] "+q"(m) : : "memory");                   
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- je__: IB_KT_JCC ---- */
static inline void k_je___kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("je__", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("je__", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "j" "e" " 9f\n\tmovl $1,%[s]\n\t9:" IB_GETF2("fl")            
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- jne__: IB_K_JCC ---- */
static uint64_t k_jne__(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "ne" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_jne___tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "ne" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "ne" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+b"(e), [n] "+q"(m) : : "memory");                   
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- jne__: IB_KT_JCC ---- */
static inline void k_jne___kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("jne__", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("jne__", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "j" "ne" " 9f\n\tmovl $1,%[s]\n\t9:" IB_GETF2("fl")            
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- jl__: IB_K_JCC ---- */
static uint64_t k_jl__(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "l" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_jl___tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "l" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "l" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+b"(e), [n] "+q"(m) : : "memory");                   
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- jl__: IB_KT_JCC ---- */
static inline void k_jl___kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("jl__", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("jl__", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "j" "l" " 9f\n\tmovl $1,%[s]\n\t9:" IB_GETF2("fl")            
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- jge__: IB_K_JCC ---- */
static uint64_t k_jge__(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "ge" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_jge___tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "ge" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "ge" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+b"(e), [n] "+q"(m) : : "memory");                   
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- jge__: IB_KT_JCC ---- */
static inline void k_jge___kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("jge__", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("jge__", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "j" "ge" " 9f\n\tmovl $1,%[s]\n\t9:" IB_GETF2("fl")            
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- jle__: IB_K_JCC ---- */
static uint64_t k_jle__(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "le" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_jle___tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "le" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "le" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+b"(e), [n] "+q"(m) : : "memory");                   
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- jle__: IB_KT_JCC ---- */
static inline void k_jle___kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("jle__", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("jle__", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "j" "le" " 9f\n\tmovl $1,%[s]\n\t9:" IB_GETF2("fl")            
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- jg__: IB_K_JCC ---- */
static uint64_t k_jg__(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "g" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_jg___tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "g" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "g" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+b"(e), [n] "+q"(m) : : "memory");                   
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- jg__: IB_KT_JCC ---- */
static inline void k_jg___kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("jg__", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("jg__", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "j" "g" " 9f\n\tmovl $1,%[s]\n\t9:" IB_GETF2("fl")            
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- jb__: IB_K_JCC ---- */
static uint64_t k_jb__(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "b" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_jb___tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "b" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "b" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+b"(e), [n] "+q"(m) : : "memory");                   
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- jb__: IB_KT_JCC ---- */
static inline void k_jb___kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("jb__", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("jb__", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "j" "b" " 9f\n\tmovl $1,%[s]\n\t9:" IB_GETF2("fl")            
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- jae__: IB_K_JCC ---- */
static uint64_t k_jae__(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "ae" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_jae___tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "ae" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "ae" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+b"(e), [n] "+q"(m) : : "memory");                   
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- jae__: IB_KT_JCC ---- */
static inline void k_jae___kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("jae__", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("jae__", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "j" "ae" " 9f\n\tmovl $1,%[s]\n\t9:" IB_GETF2("fl")            
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- jbe__: IB_K_JCC ---- */
static uint64_t k_jbe__(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "be" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_jbe___tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "be" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "be" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+b"(e), [n] "+q"(m) : : "memory");                   
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- jbe__: IB_KT_JCC ---- */
static inline void k_jbe___kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("jbe__", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("jbe__", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "j" "be" " 9f\n\tmovl $1,%[s]\n\t9:" IB_GETF2("fl")            
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- ja__: IB_K_JCC ---- */
static uint64_t k_ja__(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "a" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_ja___tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "a" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "a" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+b"(e), [n] "+q"(m) : : "memory");                   
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- ja__: IB_KT_JCC ---- */
static inline void k_ja___kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("ja__", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("ja__", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "j" "a" " 9f\n\tmovl $1,%[s]\n\t9:" IB_GETF2("fl")            
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- js__: IB_K_JCC ---- */
static uint64_t k_js__(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "s" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_js___tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "s" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "s" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+b"(e), [n] "+q"(m) : : "memory");                   
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- js__: IB_KT_JCC ---- */
static inline void k_js___kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("js__", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("js__", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "j" "s" " 9f\n\tmovl $1,%[s]\n\t9:" IB_GETF2("fl")            
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- jns__: IB_K_JCC ---- */
static uint64_t k_jns__(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "ns" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_jns___tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "ns" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "ns" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+b"(e), [n] "+q"(m) : : "memory");                   
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- jns__: IB_KT_JCC ---- */
static inline void k_jns___kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("jns__", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("jns__", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "j" "ns" " 9f\n\tmovl $1,%[s]\n\t9:" IB_GETF2("fl")            
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- jp__: IB_K_JCC ---- */
static uint64_t k_jp__(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "p" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_jp___tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "p" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "p" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+b"(e), [n] "+q"(m) : : "memory");                   
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- jp__: IB_KT_JCC ---- */
static inline void k_jp___kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("jp__", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("jp__", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "j" "p" " 9f\n\tmovl $1,%[s]\n\t9:" IB_GETF2("fl")            
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- jnp__: IB_K_JCC ---- */
static uint64_t k_jnp__(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "np" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_jnp___tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "np" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "np" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+b"(e), [n] "+q"(m) : : "memory");                   
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- jnp__: IB_KT_JCC ---- */
static inline void k_jnp___kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("jnp__", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("jnp__", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "j" "np" " 9f\n\tmovl $1,%[s]\n\t9:" IB_GETF2("fl")            
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- jo__: IB_K_JCC ---- */
static uint64_t k_jo__(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "o" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_jo___tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "o" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "o" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+b"(e), [n] "+q"(m) : : "memory");                   
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- jo__: IB_KT_JCC ---- */
static inline void k_jo___kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("jo__", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("jo__", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "j" "o" " 9f\n\tmovl $1,%[s]\n\t9:" IB_GETF2("fl")            
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- jno__: IB_K_JCC ---- */
static uint64_t k_jno__(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "no" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_jno___tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "no" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+a"(a), [n] "+q"(n) : : "memory");                   
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tj" "no" " 9f\n\tadd" IB_WSUF " $3,%[a]\n\t9:"       
                : [a] "+b"(e), [n] "+q"(m) : : "memory");                   
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- jno__: IB_KT_JCC ---- */
static inline void k_jno___kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("jno__", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("jno__", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "j" "no" " 9f\n\tmovl $1,%[s]\n\t9:" IB_GETF2("fl")            
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}


/* ---------------- setcc(13, 全部 r.f.b/flags) ---------------- */
/* ---- sete_r_f_b_flags: IB_K_SETCC ---- */
static uint64_t k_sete_r_f_b_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    IB_WTY s = (IB_WTY)0;                                                                 
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "e" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_sete_r_f_b_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    IB_WTY s = (IB_WTY)0, u = (IB_WTY)0;                                                      
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "e" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "e" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+b"(e), [s] "+q"(u), [n] "+q"(m) : : "memory");      
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- sete_r_f_b_flags: IB_KT_SETCC ---- */
static inline void k_sete_r_f_b_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("sete_r_f_b_flags", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("sete_r_f_b_flags", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "set" "e" " %b[s]" IB_GETF2("fl")                             
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- setne_r_f_b_flags: IB_K_SETCC ---- */
static uint64_t k_setne_r_f_b_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    IB_WTY s = (IB_WTY)0;                                                                 
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "ne" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_setne_r_f_b_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    IB_WTY s = (IB_WTY)0, u = (IB_WTY)0;                                                      
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "ne" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "ne" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+b"(e), [s] "+q"(u), [n] "+q"(m) : : "memory");      
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- setne_r_f_b_flags: IB_KT_SETCC ---- */
static inline void k_setne_r_f_b_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("setne_r_f_b_flags", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("setne_r_f_b_flags", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "set" "ne" " %b[s]" IB_GETF2("fl")                             
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- setl_r_f_b_flags: IB_K_SETCC ---- */
static uint64_t k_setl_r_f_b_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    IB_WTY s = (IB_WTY)0;                                                                 
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "l" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_setl_r_f_b_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    IB_WTY s = (IB_WTY)0, u = (IB_WTY)0;                                                      
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "l" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "l" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+b"(e), [s] "+q"(u), [n] "+q"(m) : : "memory");      
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- setl_r_f_b_flags: IB_KT_SETCC ---- */
static inline void k_setl_r_f_b_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("setl_r_f_b_flags", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("setl_r_f_b_flags", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "set" "l" " %b[s]" IB_GETF2("fl")                             
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- setge_r_f_b_flags: IB_K_SETCC ---- */
static uint64_t k_setge_r_f_b_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    IB_WTY s = (IB_WTY)0;                                                                 
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "ge" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_setge_r_f_b_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    IB_WTY s = (IB_WTY)0, u = (IB_WTY)0;                                                      
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "ge" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "ge" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+b"(e), [s] "+q"(u), [n] "+q"(m) : : "memory");      
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- setge_r_f_b_flags: IB_KT_SETCC ---- */
static inline void k_setge_r_f_b_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("setge_r_f_b_flags", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("setge_r_f_b_flags", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "set" "ge" " %b[s]" IB_GETF2("fl")                             
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- setle_r_f_b_flags: IB_K_SETCC ---- */
static uint64_t k_setle_r_f_b_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    IB_WTY s = (IB_WTY)0;                                                                 
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "le" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_setle_r_f_b_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    IB_WTY s = (IB_WTY)0, u = (IB_WTY)0;                                                      
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "le" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "le" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+b"(e), [s] "+q"(u), [n] "+q"(m) : : "memory");      
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- setle_r_f_b_flags: IB_KT_SETCC ---- */
static inline void k_setle_r_f_b_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("setle_r_f_b_flags", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("setle_r_f_b_flags", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "set" "le" " %b[s]" IB_GETF2("fl")                             
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- setg_r_f_b_flags: IB_K_SETCC ---- */
static uint64_t k_setg_r_f_b_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    IB_WTY s = (IB_WTY)0;                                                                 
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "g" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_setg_r_f_b_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    IB_WTY s = (IB_WTY)0, u = (IB_WTY)0;                                                      
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "g" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "g" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+b"(e), [s] "+q"(u), [n] "+q"(m) : : "memory");      
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- setg_r_f_b_flags: IB_KT_SETCC ---- */
static inline void k_setg_r_f_b_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("setg_r_f_b_flags", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("setg_r_f_b_flags", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "set" "g" " %b[s]" IB_GETF2("fl")                             
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- setb_r_f_b_flags: IB_K_SETCC ---- */
static uint64_t k_setb_r_f_b_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    IB_WTY s = (IB_WTY)0;                                                                 
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "b" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_setb_r_f_b_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    IB_WTY s = (IB_WTY)0, u = (IB_WTY)0;                                                      
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "b" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "b" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+b"(e), [s] "+q"(u), [n] "+q"(m) : : "memory");      
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- setb_r_f_b_flags: IB_KT_SETCC ---- */
static inline void k_setb_r_f_b_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("setb_r_f_b_flags", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("setb_r_f_b_flags", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "set" "b" " %b[s]" IB_GETF2("fl")                             
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- setae_r_f_b_flags: IB_K_SETCC ---- */
static uint64_t k_setae_r_f_b_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    IB_WTY s = (IB_WTY)0;                                                                 
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "ae" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_setae_r_f_b_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    IB_WTY s = (IB_WTY)0, u = (IB_WTY)0;                                                      
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "ae" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "ae" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+b"(e), [s] "+q"(u), [n] "+q"(m) : : "memory");      
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- setae_r_f_b_flags: IB_KT_SETCC ---- */
static inline void k_setae_r_f_b_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("setae_r_f_b_flags", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("setae_r_f_b_flags", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "set" "ae" " %b[s]" IB_GETF2("fl")                             
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- setbe_r_f_b_flags: IB_K_SETCC ---- */
static uint64_t k_setbe_r_f_b_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    IB_WTY s = (IB_WTY)0;                                                                 
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "be" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_setbe_r_f_b_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    IB_WTY s = (IB_WTY)0, u = (IB_WTY)0;                                                      
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "be" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "be" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+b"(e), [s] "+q"(u), [n] "+q"(m) : : "memory");      
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- setbe_r_f_b_flags: IB_KT_SETCC ---- */
static inline void k_setbe_r_f_b_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("setbe_r_f_b_flags", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("setbe_r_f_b_flags", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "set" "be" " %b[s]" IB_GETF2("fl")                             
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- seta_r_f_b_flags: IB_K_SETCC ---- */
static uint64_t k_seta_r_f_b_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    IB_WTY s = (IB_WTY)0;                                                                 
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "a" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_seta_r_f_b_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    IB_WTY s = (IB_WTY)0, u = (IB_WTY)0;                                                      
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "a" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "a" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+b"(e), [s] "+q"(u), [n] "+q"(m) : : "memory");      
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- seta_r_f_b_flags: IB_KT_SETCC ---- */
static inline void k_seta_r_f_b_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("seta_r_f_b_flags", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("seta_r_f_b_flags", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "set" "a" " %b[s]" IB_GETF2("fl")                             
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- sets_r_f_b_flags: IB_K_SETCC ---- */
static uint64_t k_sets_r_f_b_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    IB_WTY s = (IB_WTY)0;                                                                 
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "s" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_sets_r_f_b_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    IB_WTY s = (IB_WTY)0, u = (IB_WTY)0;                                                      
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "s" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "s" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+b"(e), [s] "+q"(u), [n] "+q"(m) : : "memory");      
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- sets_r_f_b_flags: IB_KT_SETCC ---- */
static inline void k_sets_r_f_b_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("sets_r_f_b_flags", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("sets_r_f_b_flags", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "set" "s" " %b[s]" IB_GETF2("fl")                             
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- setns_r_f_b_flags: IB_K_SETCC ---- */
static uint64_t k_setns_r_f_b_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    IB_WTY s = (IB_WTY)0;                                                                 
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "ns" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_setns_r_f_b_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    IB_WTY s = (IB_WTY)0, u = (IB_WTY)0;                                                      
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "ns" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "ns" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+b"(e), [s] "+q"(u), [n] "+q"(m) : : "memory");      
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- setns_r_f_b_flags: IB_KT_SETCC ---- */
static inline void k_setns_r_f_b_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("setns_r_f_b_flags", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("setns_r_f_b_flags", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "set" "ns" " %b[s]" IB_GETF2("fl")                             
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- setnp_r_f_b_flags: IB_K_SETCC ---- */
static uint64_t k_setnp_r_f_b_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1);                                                  
    IB_WTY s = (IB_WTY)0;                                                                 
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "np" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_setnp_r_f_b_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_WTY a = (IB_WTY)(IB_SEED(0) | 1), e = (IB_WTY)(IB_SEED(2) | 1);                        
    IB_WTY s = (IB_WTY)0, u = (IB_WTY)0;                                                      
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "np" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+a"(a), [s] "+q"(s), [n] "+q"(n) : : "memory");      
        __asm__("lea" IB_WSUF " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tset" "np" " %b[s]\n\t"                          
                "movzb" IB_WSUF " %b[s],%[s]\n\tadd %[s],%[a]"                        
                : [a] "+b"(e), [s] "+q"(u), [n] "+q"(m) : : "memory");      
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- setnp_r_f_b_flags: IB_KT_SETCC ---- */
static inline void k_setnp_r_f_b_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("setnp_r_f_b_flags", kk, 0, IB_UL);                                  
    IB_UL b = (IB_UL)IB_KIN8("setnp_r_f_b_flags", kk, 1, IB_UL);                                  
    IB_UL s = (IB_UL)0;                                                           
    uintptr_t f1 = 0, fl = 0;                                                     
    if ((kk & 3) == 0) b = a;                                                     
    __asm__ volatile("movl $0,%[s]\n\t" "cmpl %[b],%[a]" IB_GETF2("f1") "\n\t"    
                     "set" "np" " %b[s]" IB_GETF2("fl")                             
                     : [s] "=q"(s), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [a] "r"(a), [b] "r"(b) : "memory");                  
    g->i0 = (uint64_t)a;   g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)s;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}


/* ---------------- cmovcc 32 位形态(两 ABI 皆有) ---------------- */
/* ---- cmovl_r_rc_l_flags: IB_K_CMOV ---- */
static uint64_t k_cmovl_r_rc_l_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 1), w = (IB_UL)(IB_SEED(2) | 1);                        
    IB_UL b = (IB_UL)(IB_SEED(4) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" "l" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "l" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "l" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_cmovl_r_rc_l_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 1), e = (IB_UL)(IB_SEED(2) | 1);                        
    IB_UL w = (IB_UL)(IB_SEED(4) | 1), x = (IB_UL)(IB_SEED(6) | 1);                        
    IB_UL b = (IB_UL)(IB_SEED(8) | 1), c = (IB_UL)(IB_SEED(10) | 1);                       
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" "l" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "l" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "l" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
        __asm__("lea" "l" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "l" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "l" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+b"(e), [w] "+r"(x), [b] "+r"(c), [n] "+q"(m)              
                : : "memory");                                              
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- cmovl_r_rc_l_flags: IB_KT_CMOV ---- */
static inline void k_cmovl_r_rc_l_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("cmovl_r_rc_l_flags", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("cmovl_r_rc_l_flags", kk, 1, IB_UL);          
    IB_UL ain = a;                                                                   
    uintptr_t f1 = 0, fl = 0;                                                     
    __asm__ volatile("cmp" "l" " %[b],%[a]" IB_GETF2("f1") "\n\t"                 
                     "cmov" "l" " %[b],%[a]" IB_GETF2("fl")                        
                     : [a] "+r"(a), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [b] "r"(b) : "memory");                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- cmovg_r_rc_l_flags: IB_K_CMOV ---- */
static uint64_t k_cmovg_r_rc_l_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 1), w = (IB_UL)(IB_SEED(2) | 1);                        
    IB_UL b = (IB_UL)(IB_SEED(4) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" "l" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "l" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "g" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_cmovg_r_rc_l_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 1), e = (IB_UL)(IB_SEED(2) | 1);                        
    IB_UL w = (IB_UL)(IB_SEED(4) | 1), x = (IB_UL)(IB_SEED(6) | 1);                        
    IB_UL b = (IB_UL)(IB_SEED(8) | 1), c = (IB_UL)(IB_SEED(10) | 1);                       
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" "l" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "l" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "g" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
        __asm__("lea" "l" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "l" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "g" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+b"(e), [w] "+r"(x), [b] "+r"(c), [n] "+q"(m)              
                : : "memory");                                              
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- cmovg_r_rc_l_flags: IB_KT_CMOV ---- */
static inline void k_cmovg_r_rc_l_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("cmovg_r_rc_l_flags", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("cmovg_r_rc_l_flags", kk, 1, IB_UL);          
    IB_UL ain = a;                                                                   
    uintptr_t f1 = 0, fl = 0;                                                     
    __asm__ volatile("cmp" "l" " %[b],%[a]" IB_GETF2("f1") "\n\t"                 
                     "cmov" "g" " %[b],%[a]" IB_GETF2("fl")                        
                     : [a] "+r"(a), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [b] "r"(b) : "memory");                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- cmovb_r_rc_l_flags: IB_K_CMOV ---- */
static uint64_t k_cmovb_r_rc_l_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 1), w = (IB_UL)(IB_SEED(2) | 1);                        
    IB_UL b = (IB_UL)(IB_SEED(4) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" "l" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "l" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "b" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_cmovb_r_rc_l_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 1), e = (IB_UL)(IB_SEED(2) | 1);                        
    IB_UL w = (IB_UL)(IB_SEED(4) | 1), x = (IB_UL)(IB_SEED(6) | 1);                        
    IB_UL b = (IB_UL)(IB_SEED(8) | 1), c = (IB_UL)(IB_SEED(10) | 1);                       
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" "l" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "l" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "b" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
        __asm__("lea" "l" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "l" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "b" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+b"(e), [w] "+r"(x), [b] "+r"(c), [n] "+q"(m)              
                : : "memory");                                              
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- cmovb_r_rc_l_flags: IB_KT_CMOV ---- */
static inline void k_cmovb_r_rc_l_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("cmovb_r_rc_l_flags", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("cmovb_r_rc_l_flags", kk, 1, IB_UL);          
    IB_UL ain = a;                                                                   
    uintptr_t f1 = 0, fl = 0;                                                     
    __asm__ volatile("cmp" "l" " %[b],%[a]" IB_GETF2("f1") "\n\t"                 
                     "cmov" "b" " %[b],%[a]" IB_GETF2("fl")                        
                     : [a] "+r"(a), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [b] "r"(b) : "memory");                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- cmovs_r_rc_l_flags: IB_K_CMOV ---- */
static uint64_t k_cmovs_r_rc_l_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 1), w = (IB_UL)(IB_SEED(2) | 1);                        
    IB_UL b = (IB_UL)(IB_SEED(4) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" "l" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "l" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "s" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_cmovs_r_rc_l_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 1), e = (IB_UL)(IB_SEED(2) | 1);                        
    IB_UL w = (IB_UL)(IB_SEED(4) | 1), x = (IB_UL)(IB_SEED(6) | 1);                        
    IB_UL b = (IB_UL)(IB_SEED(8) | 1), c = (IB_UL)(IB_SEED(10) | 1);                       
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" "l" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "l" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "s" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
        __asm__("lea" "l" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "l" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "s" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+b"(e), [w] "+r"(x), [b] "+r"(c), [n] "+q"(m)              
                : : "memory");                                              
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- cmovs_r_rc_l_flags: IB_KT_CMOV ---- */
static inline void k_cmovs_r_rc_l_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("cmovs_r_rc_l_flags", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("cmovs_r_rc_l_flags", kk, 1, IB_UL);          
    IB_UL ain = a;                                                                   
    uintptr_t f1 = 0, fl = 0;                                                     
    __asm__ volatile("cmp" "l" " %[b],%[a]" IB_GETF2("f1") "\n\t"                 
                     "cmov" "s" " %[b],%[a]" IB_GETF2("fl")                        
                     : [a] "+r"(a), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [b] "r"(b) : "memory");                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- cmovo_r_rc_l_flags: IB_K_CMOV ---- */
static uint64_t k_cmovo_r_rc_l_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 1), w = (IB_UL)(IB_SEED(2) | 1);                        
    IB_UL b = (IB_UL)(IB_SEED(4) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" "l" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "l" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "o" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_cmovo_r_rc_l_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 1), e = (IB_UL)(IB_SEED(2) | 1);                        
    IB_UL w = (IB_UL)(IB_SEED(4) | 1), x = (IB_UL)(IB_SEED(6) | 1);                        
    IB_UL b = (IB_UL)(IB_SEED(8) | 1), c = (IB_UL)(IB_SEED(10) | 1);                       
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" "l" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "l" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "o" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
        __asm__("lea" "l" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "l" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "o" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+b"(e), [w] "+r"(x), [b] "+r"(c), [n] "+q"(m)              
                : : "memory");                                              
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- cmovo_r_rc_l_flags: IB_KT_CMOV ---- */
static inline void k_cmovo_r_rc_l_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("cmovo_r_rc_l_flags", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("cmovo_r_rc_l_flags", kk, 1, IB_UL);          
    IB_UL ain = a;                                                                   
    uintptr_t f1 = 0, fl = 0;                                                     
    __asm__ volatile("cmp" "l" " %[b],%[a]" IB_GETF2("f1") "\n\t"                 
                     "cmov" "o" " %[b],%[a]" IB_GETF2("fl")                        
                     : [a] "+r"(a), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [b] "r"(b) : "memory");                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- cmovno_r_rc_l_flags: IB_K_CMOV ---- */
static uint64_t k_cmovno_r_rc_l_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 1), w = (IB_UL)(IB_SEED(2) | 1);                        
    IB_UL b = (IB_UL)(IB_SEED(4) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" "l" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "l" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "no" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_cmovno_r_rc_l_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 1), e = (IB_UL)(IB_SEED(2) | 1);                        
    IB_UL w = (IB_UL)(IB_SEED(4) | 1), x = (IB_UL)(IB_SEED(6) | 1);                        
    IB_UL b = (IB_UL)(IB_SEED(8) | 1), c = (IB_UL)(IB_SEED(10) | 1);                       
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" "l" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "l" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "no" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
        __asm__("lea" "l" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "l" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "no" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+b"(e), [w] "+r"(x), [b] "+r"(c), [n] "+q"(m)              
                : : "memory");                                              
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- cmovno_r_rc_l_flags: IB_KT_CMOV ---- */
static inline void k_cmovno_r_rc_l_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UL a = (IB_UL)IB_KIN8("cmovno_r_rc_l_flags", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("cmovno_r_rc_l_flags", kk, 1, IB_UL);          
    IB_UL ain = a;                                                                   
    uintptr_t f1 = 0, fl = 0;                                                     
    __asm__ volatile("cmp" "l" " %[b],%[a]" IB_GETF2("f1") "\n\t"                 
                     "cmov" "no" " %[b],%[a]" IB_GETF2("fl")                        
                     : [a] "+r"(a), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [b] "r"(b) : "memory");                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}


/* ---------------- cmovcc 64 位形态(仅 x86_64) ---------------- */
#ifdef __x86_64__
/* ---- cmove_r_rc_q_flags: IB_K_CMOV ---- */
static uint64_t k_cmove_r_rc_q_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), w = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ b = (IB_UQ)(IB_SEED(4) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "e" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_cmove_r_rc_q_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), e = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ w = (IB_UQ)(IB_SEED(4) | 1), x = (IB_UQ)(IB_SEED(6) | 1);                        
    IB_UQ b = (IB_UQ)(IB_SEED(8) | 1), c = (IB_UQ)(IB_SEED(10) | 1);                       
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "e" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "e" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+b"(e), [w] "+r"(x), [b] "+r"(c), [n] "+q"(m)              
                : : "memory");                                              
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- cmove_r_rc_q_flags: IB_KT_CMOV ---- */
static inline void k_cmove_r_rc_q_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UQ a = (IB_UQ)IB_KIN8("cmove_r_rc_q_flags", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("cmove_r_rc_q_flags", kk, 1, IB_UQ);          
    IB_UQ ain = a;                                                                   
    uintptr_t f1 = 0, fl = 0;                                                     
    __asm__ volatile("cmp" "q" " %[b],%[a]" IB_GETF2("f1") "\n\t"                 
                     "cmov" "e" " %[b],%[a]" IB_GETF2("fl")                        
                     : [a] "+r"(a), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [b] "r"(b) : "memory");                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- cmovne_r_rc_q_flags: IB_K_CMOV ---- */
static uint64_t k_cmovne_r_rc_q_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), w = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ b = (IB_UQ)(IB_SEED(4) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "ne" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_cmovne_r_rc_q_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), e = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ w = (IB_UQ)(IB_SEED(4) | 1), x = (IB_UQ)(IB_SEED(6) | 1);                        
    IB_UQ b = (IB_UQ)(IB_SEED(8) | 1), c = (IB_UQ)(IB_SEED(10) | 1);                       
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "ne" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "ne" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+b"(e), [w] "+r"(x), [b] "+r"(c), [n] "+q"(m)              
                : : "memory");                                              
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- cmovne_r_rc_q_flags: IB_KT_CMOV ---- */
static inline void k_cmovne_r_rc_q_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UQ a = (IB_UQ)IB_KIN8("cmovne_r_rc_q_flags", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("cmovne_r_rc_q_flags", kk, 1, IB_UQ);          
    IB_UQ ain = a;                                                                   
    uintptr_t f1 = 0, fl = 0;                                                     
    __asm__ volatile("cmp" "q" " %[b],%[a]" IB_GETF2("f1") "\n\t"                 
                     "cmov" "ne" " %[b],%[a]" IB_GETF2("fl")                        
                     : [a] "+r"(a), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [b] "r"(b) : "memory");                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- cmovge_r_rc_q_flags: IB_K_CMOV ---- */
static uint64_t k_cmovge_r_rc_q_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), w = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ b = (IB_UQ)(IB_SEED(4) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "ge" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_cmovge_r_rc_q_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), e = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ w = (IB_UQ)(IB_SEED(4) | 1), x = (IB_UQ)(IB_SEED(6) | 1);                        
    IB_UQ b = (IB_UQ)(IB_SEED(8) | 1), c = (IB_UQ)(IB_SEED(10) | 1);                       
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "ge" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "ge" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+b"(e), [w] "+r"(x), [b] "+r"(c), [n] "+q"(m)              
                : : "memory");                                              
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- cmovge_r_rc_q_flags: IB_KT_CMOV ---- */
static inline void k_cmovge_r_rc_q_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UQ a = (IB_UQ)IB_KIN8("cmovge_r_rc_q_flags", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("cmovge_r_rc_q_flags", kk, 1, IB_UQ);          
    IB_UQ ain = a;                                                                   
    uintptr_t f1 = 0, fl = 0;                                                     
    __asm__ volatile("cmp" "q" " %[b],%[a]" IB_GETF2("f1") "\n\t"                 
                     "cmov" "ge" " %[b],%[a]" IB_GETF2("fl")                        
                     : [a] "+r"(a), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [b] "r"(b) : "memory");                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- cmovle_r_rc_q_flags: IB_K_CMOV ---- */
static uint64_t k_cmovle_r_rc_q_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), w = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ b = (IB_UQ)(IB_SEED(4) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "le" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_cmovle_r_rc_q_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), e = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ w = (IB_UQ)(IB_SEED(4) | 1), x = (IB_UQ)(IB_SEED(6) | 1);                        
    IB_UQ b = (IB_UQ)(IB_SEED(8) | 1), c = (IB_UQ)(IB_SEED(10) | 1);                       
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "le" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "le" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+b"(e), [w] "+r"(x), [b] "+r"(c), [n] "+q"(m)              
                : : "memory");                                              
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- cmovle_r_rc_q_flags: IB_KT_CMOV ---- */
static inline void k_cmovle_r_rc_q_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UQ a = (IB_UQ)IB_KIN8("cmovle_r_rc_q_flags", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("cmovle_r_rc_q_flags", kk, 1, IB_UQ);          
    IB_UQ ain = a;                                                                   
    uintptr_t f1 = 0, fl = 0;                                                     
    __asm__ volatile("cmp" "q" " %[b],%[a]" IB_GETF2("f1") "\n\t"                 
                     "cmov" "le" " %[b],%[a]" IB_GETF2("fl")                        
                     : [a] "+r"(a), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [b] "r"(b) : "memory");                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- cmovae_r_rc_q_flags: IB_K_CMOV ---- */
static uint64_t k_cmovae_r_rc_q_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), w = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ b = (IB_UQ)(IB_SEED(4) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "ae" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_cmovae_r_rc_q_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), e = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ w = (IB_UQ)(IB_SEED(4) | 1), x = (IB_UQ)(IB_SEED(6) | 1);                        
    IB_UQ b = (IB_UQ)(IB_SEED(8) | 1), c = (IB_UQ)(IB_SEED(10) | 1);                       
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "ae" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "ae" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+b"(e), [w] "+r"(x), [b] "+r"(c), [n] "+q"(m)              
                : : "memory");                                              
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- cmovae_r_rc_q_flags: IB_KT_CMOV ---- */
static inline void k_cmovae_r_rc_q_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UQ a = (IB_UQ)IB_KIN8("cmovae_r_rc_q_flags", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("cmovae_r_rc_q_flags", kk, 1, IB_UQ);          
    IB_UQ ain = a;                                                                   
    uintptr_t f1 = 0, fl = 0;                                                     
    __asm__ volatile("cmp" "q" " %[b],%[a]" IB_GETF2("f1") "\n\t"                 
                     "cmov" "ae" " %[b],%[a]" IB_GETF2("fl")                        
                     : [a] "+r"(a), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [b] "r"(b) : "memory");                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- cmovbe_r_rc_q_flags: IB_K_CMOV ---- */
static uint64_t k_cmovbe_r_rc_q_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), w = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ b = (IB_UQ)(IB_SEED(4) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "be" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_cmovbe_r_rc_q_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), e = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ w = (IB_UQ)(IB_SEED(4) | 1), x = (IB_UQ)(IB_SEED(6) | 1);                        
    IB_UQ b = (IB_UQ)(IB_SEED(8) | 1), c = (IB_UQ)(IB_SEED(10) | 1);                       
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "be" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "be" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+b"(e), [w] "+r"(x), [b] "+r"(c), [n] "+q"(m)              
                : : "memory");                                              
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- cmovbe_r_rc_q_flags: IB_KT_CMOV ---- */
static inline void k_cmovbe_r_rc_q_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UQ a = (IB_UQ)IB_KIN8("cmovbe_r_rc_q_flags", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("cmovbe_r_rc_q_flags", kk, 1, IB_UQ);          
    IB_UQ ain = a;                                                                   
    uintptr_t f1 = 0, fl = 0;                                                     
    __asm__ volatile("cmp" "q" " %[b],%[a]" IB_GETF2("f1") "\n\t"                 
                     "cmov" "be" " %[b],%[a]" IB_GETF2("fl")                        
                     : [a] "+r"(a), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [b] "r"(b) : "memory");                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- cmova_r_rc_q_flags: IB_K_CMOV ---- */
static uint64_t k_cmova_r_rc_q_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), w = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ b = (IB_UQ)(IB_SEED(4) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "a" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_cmova_r_rc_q_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), e = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ w = (IB_UQ)(IB_SEED(4) | 1), x = (IB_UQ)(IB_SEED(6) | 1);                        
    IB_UQ b = (IB_UQ)(IB_SEED(8) | 1), c = (IB_UQ)(IB_SEED(10) | 1);                       
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "a" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "a" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+b"(e), [w] "+r"(x), [b] "+r"(c), [n] "+q"(m)              
                : : "memory");                                              
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- cmova_r_rc_q_flags: IB_KT_CMOV ---- */
static inline void k_cmova_r_rc_q_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UQ a = (IB_UQ)IB_KIN8("cmova_r_rc_q_flags", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("cmova_r_rc_q_flags", kk, 1, IB_UQ);          
    IB_UQ ain = a;                                                                   
    uintptr_t f1 = 0, fl = 0;                                                     
    __asm__ volatile("cmp" "q" " %[b],%[a]" IB_GETF2("f1") "\n\t"                 
                     "cmov" "a" " %[b],%[a]" IB_GETF2("fl")                        
                     : [a] "+r"(a), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [b] "r"(b) : "memory");                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- cmovns_r_rc_q_flags: IB_K_CMOV ---- */
static uint64_t k_cmovns_r_rc_q_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), w = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ b = (IB_UQ)(IB_SEED(4) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "ns" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_cmovns_r_rc_q_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), e = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ w = (IB_UQ)(IB_SEED(4) | 1), x = (IB_UQ)(IB_SEED(6) | 1);                        
    IB_UQ b = (IB_UQ)(IB_SEED(8) | 1), c = (IB_UQ)(IB_SEED(10) | 1);                       
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "ns" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "ns" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+b"(e), [w] "+r"(x), [b] "+r"(c), [n] "+q"(m)              
                : : "memory");                                              
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- cmovns_r_rc_q_flags: IB_KT_CMOV ---- */
static inline void k_cmovns_r_rc_q_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UQ a = (IB_UQ)IB_KIN8("cmovns_r_rc_q_flags", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("cmovns_r_rc_q_flags", kk, 1, IB_UQ);          
    IB_UQ ain = a;                                                                   
    uintptr_t f1 = 0, fl = 0;                                                     
    __asm__ volatile("cmp" "q" " %[b],%[a]" IB_GETF2("f1") "\n\t"                 
                     "cmov" "ns" " %[b],%[a]" IB_GETF2("fl")                        
                     : [a] "+r"(a), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [b] "r"(b) : "memory");                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

/* ---- cmovp_r_rc_q_flags: IB_K_CMOV ---- */
static uint64_t k_cmovp_r_rc_q_flags(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), w = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ b = (IB_UQ)(IB_SEED(4) | 1);                                                  
    uint8_t n = 0;                                                                
    for (i = 0; i < it; i++)                                                      
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "p" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
    return IB_S1((uint64_t)a + 1);                                                
}                                                                                 
static uint64_t k_cmovp_r_rc_q_flags_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 1), e = (IB_UQ)(IB_SEED(2) | 1);                        
    IB_UQ w = (IB_UQ)(IB_SEED(4) | 1), x = (IB_UQ)(IB_SEED(6) | 1);                        
    IB_UQ b = (IB_UQ)(IB_SEED(8) | 1), c = (IB_UQ)(IB_SEED(10) | 1);                       
    uint8_t n = 0, m = 0;                                                         
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "p" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+a"(a), [w] "+r"(w), [b] "+r"(b), [n] "+q"(n)              
                : : "memory");                                              
        __asm__("lea" "q" " (%[a],%[a],4),%[a]\n\taddb $1,%[n]\n\t"               
                "cmpb %[n],%b[a]\n\tlea" "q" " (%[b],%[b],4),%[b]\n\t"            
                "cmov" "p" " %[b],%[w]\n\tadd %[w],%[a]"                           
                : [a] "+b"(e), [w] "+r"(x), [b] "+r"(c), [n] "+q"(m)              
                : : "memory");                                              
    }                                                                             
    return IB_S2((uint64_t)a + 1, (uint64_t)e + 1);                               
}

/* ---- cmovp_r_rc_q_flags: IB_KT_CMOV ---- */
static inline void k_cmovp_r_rc_q_flags_kat(int kk, ib_kv *g)                                 
{                                                                                 
    IB_UQ a = (IB_UQ)IB_KIN8("cmovp_r_rc_q_flags", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("cmovp_r_rc_q_flags", kk, 1, IB_UQ);          
    IB_UQ ain = a;                                                                   
    uintptr_t f1 = 0, fl = 0;                                                     
    __asm__ volatile("cmp" "q" " %[b],%[a]" IB_GETF2("f1") "\n\t"                 
                     "cmov" "p" " %[b],%[a]" IB_GETF2("fl")                        
                     : [a] "+r"(a), [f1] "=&r"(f1), [fl] "=&r"(fl)                
                     : [b] "r"(b) : "memory");                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;                                    
    g->inf = (uint64_t)f1 & IB_FLG_MASK;                                           
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                          
}

#endif

/* ---------------- 用例表(bpop = 每 op 处理字节数, 供 tput 折 MB/s) ------------ */
static const ib_case g_cases[] = {
    /* jcc: 被测不写结果 -> 无数据宽度, bpop 留空(0) */
    IB_ROW_K("x86_jne___",                NULL, jne__,        0),
    IB_ROW_K("x86_je___",                 NULL, je__,         0),
    IB_ROW_K("x86_jae___",                NULL, jae__,        0),
    IB_ROW_K("x86_ja___",                 NULL, ja__,         0),
    IB_ROW_K("x86_jb___",                 NULL, jb__,         0),
    IB_ROW_K("x86_js___",                 NULL, js__,         0),
    IB_ROW_K("x86_jge___",                NULL, jge__,        0),
    IB_ROW_K("x86_jle___",                NULL, jle__,        0),
    IB_ROW_K("x86_jbe___",                NULL, jbe__,        0),
    IB_ROW_K("x86_jg___",                 NULL, jg__,         0),
    IB_ROW_K("x86_jns___",                NULL, jns__,        0),
    IB_ROW_K("x86_jl___",                 NULL, jl__,         0),
    IB_ROW_K("x86_jo___",                 NULL, jo__,         0),
    IB_ROW_K("x86_jp___",                 NULL, jp__,         0),
    IB_ROW_K("x86_jnp___",                NULL, jnp__,        0),
    IB_ROW_K("x86_jno___",                NULL, jno__,        0),
    /* setcc: 目的数是 8 位 */
    IB_ROW_K("x86_setb__r_f_b_flags",     NULL, setb_r_f_b_flags,   1),
    IB_ROW_K("x86_sete__r_f_b_flags",     NULL, sete_r_f_b_flags,   1),
    IB_ROW_K("x86_setne__r_f_b_flags",    NULL, setne_r_f_b_flags,  1),
    IB_ROW_K("x86_setl__r_f_b_flags",     NULL, setl_r_f_b_flags,   1),
    IB_ROW_K("x86_setae__r_f_b_flags",    NULL, setae_r_f_b_flags,  1),
    IB_ROW_K("x86_setns__r_f_b_flags",    NULL, setns_r_f_b_flags,  1),
    IB_ROW_K("x86_setbe__r_f_b_flags",    NULL, setbe_r_f_b_flags,  1),
    IB_ROW_K("x86_setg__r_f_b_flags",     NULL, setg_r_f_b_flags,   1),
    IB_ROW_K("x86_seta__r_f_b_flags",     NULL, seta_r_f_b_flags,   1),
    IB_ROW_K("x86_sets__r_f_b_flags",     NULL, sets_r_f_b_flags,   1),
    IB_ROW_K("x86_setge__r_f_b_flags",    NULL, setge_r_f_b_flags,  1),
    IB_ROW_K("x86_setle__r_f_b_flags",    NULL, setle_r_f_b_flags,  1),
    IB_ROW_K("x86_setnp__r_f_b_flags",    NULL, setnp_r_f_b_flags,  1),
    /* cmovcc 32 位 */
    IB_ROW_K("x86_cmovb__r_rc_l_flags",   NULL, cmovb_r_rc_l_flags,  4),
    IB_ROW_K("x86_cmovl__r_rc_l_flags",   NULL, cmovl_r_rc_l_flags,  4),
    IB_ROW_K("x86_cmovg__r_rc_l_flags",   NULL, cmovg_r_rc_l_flags,  4),
    IB_ROW_K("x86_cmovs__r_rc_l_flags",   NULL, cmovs_r_rc_l_flags,  4),
    IB_ROW_K("x86_cmovo__r_rc_l_flags",   NULL, cmovo_r_rc_l_flags,  4),
    IB_ROW_K("x86_cmovno__r_rc_l_flags",  NULL, cmovno_r_rc_l_flags, 4),
#ifdef __x86_64__
    /* cmovcc 64 位专有形态 */
    IB_ROW_K("x86_cmova__r_rc_q_flags",   NULL, cmova_r_rc_q_flags,  8),
    IB_ROW_K("x86_cmovne__r_rc_q_flags",  NULL, cmovne_r_rc_q_flags, 8),
    IB_ROW_K("x86_cmove__r_rc_q_flags",   NULL, cmove_r_rc_q_flags,  8),
    IB_ROW_K("x86_cmovge__r_rc_q_flags",  NULL, cmovge_r_rc_q_flags, 8),
    IB_ROW_K("x86_cmovae__r_rc_q_flags",  NULL, cmovae_r_rc_q_flags, 8),
    IB_ROW_K("x86_cmovbe__r_rc_q_flags",  NULL, cmovbe_r_rc_q_flags, 8),
    IB_ROW_K("x86_cmovns__r_rc_q_flags",  NULL, cmovns_r_rc_q_flags, 8),
    IB_ROW_K("x86_cmovle__r_rc_q_flags",  NULL, cmovle_r_rc_q_flags, 8),
    IB_ROW_K("x86_cmovp__r_rc_q_flags",   NULL, cmovp_r_rc_q_flags,  8),
#endif
};
#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

int main(int argc, char **argv)
{
    ib_init(argc, argv);
    ib_abuf_init();                 /* 只读/写区确定性预置(签名跨机可复现的前提) */
    ib_hdr("cc", NCASES);
    ib_run_cases("cc", g_cases, NCASES);
    return 0;
}
