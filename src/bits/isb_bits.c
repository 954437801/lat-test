/* isb_bits.c —— 位测试/位扫描/位操纵形态组(grp=bits): bt bts btc btq bsr bsf
 * popcnt lzcnt tzcnt + BMI1(andn bzhi blsr bextr) + BMI2(pdep pext)
 *
 * 用例来源 = 实测 三层映射 round5_form_weights.csv 的实测 k90 形态, 共 17 条,
 * 与计划表同数(bt 3 + bts 1 + btc 1 + btq 1 + bsr 1 + bsf 1 + popcnt 1 + lzcnt 1
 * + tzcnt 1 + BMI 6)。实测有货的只有 7 条:
 *   bt r.r.l 0.0822 / bt r.i.l 0.0571 / bt r.r.q 0.0265 / bsr r.r.q 0.0183
 *   btc r.i.q 0.0034 / bts r.r.l 0.0020 / btq m.i/base_sp 0.0007
 * 其余 10 条(bsf popcnt lzcnt tzcnt andn bzhi blsr bextr pdep pext)CSV 里 nf=0
 * (采样窗内没抓到), 按计划「贵形态锚点不可丢」保留, 名字按同一机械变换从
 * `bsf r.r.l` 这类 form_key 合成, 权重列一律标 nf=0。
 * 注意计划里的 `btq 1` 不是一条「q 尺寸的 bt」: 实测 form_key 是
 * `btq m.i/base_sp`(内存位数组 + 立即数位号, base_sp 寻址, 1 个样本), 与
 * `bt r.r.q` 是两种完全不同的形状(一个读栈、一个纯寄存器), 各占一条。
 *
 * 为什么独立成组: 这一族在 ISA 上分两半, 内核结构也不同 ——
 *   a) bt/bts/btc/btq 的「结果」在 CF 里(bt 连位数组操作数都不写回), 与
 *      cmp/test 同构 -> 直接复用 15 节 IB_K_FLG(add -> 被测 -> adc 回灌)/
 *      IB_K_FLG8P(base_sp 形态, 栈槽入口预置定值), bits 组不新增模板;
 *   b) bsr/bsf/popcnt/lzcnt/tzcnt 与 BMI 六条把结果写回目的寄存器 -> 新模板
 *      IB_K_BIT(第 26 节): 被测写进独立的 %[s], 骨架为 lea(乘 5)/add/or 三条。
 *      不写成 dst==src、也不只用 `add+or $1`: 这一族多是压缩型运算(输出很小),
 *      两种写法都实测过 —— 链主会收敛到不动点, 不同助记符撞同一签名(详见第 26
 *      节头注的 v1/v2/v3 记录); 乘 5 使任何一点测算差永久留在链主里。
 *   c) base_sp 那一条(btq m.i/base_sp)额外需要栈槽入口预置定值, 走 IB_K_FLG8P。
 *   两半混在一个组里是因为目标端(LATX)对它们的处理代价同量级(都是「一条标量
 *   位操作 -> 若干条带标志补齐的翻译」), 拆开只会让每组的 case 数少于统计意义。
 *
 * tzcnt 与 bsf 同编码族(F3 0F BC vs 0F BC), 区别只在 0 输入: tzcnt 给位宽、
 * bsf 的 dest 未定义 —— 第 26 节末尾那条 `or %[t],%[a]`(钳位落在位 5, 不是位 0
 * 也不是最高位)就是为 bsf 加的, 同时不把 bsf/lzcnt 的返回值钉成常数。
 *
 * 签名列可检出性自检(签名重复自检实测): 本组 17 条最后只剩 1 对同签名 —— bsf 与
 * tzcnt(非 0 输入下二者逐位相同, 见上一段), 其余 15 条 lat/tput 签名全离散。
 * 中途实测撞过而必须改掉的三对也都排掉了: popcnt/bsr、pdep/pext、
 * bsf/lzcnt/tzcnt —— 后两组不是语义相同, 而是链形退化(第 26 节头注的 v1/v2/v3)。
 * 跨组可解释的撞车只剩 shift 组的 2 对(shl、shr 的 $3 与 %%cl=3 是同一条运算
 * 的两种编码, 值流必然逐位相同)。
 * 这些不影响对拍: 每条 case 的参考值是按 case 名逐条登记的, 不是组内互比。
 *
 * 64 位形态只存在于 x86_64: 内核实例与表项一起 #ifdef(i386 侧 17->13 条,
 * 掉的是 bt r.r.q / btc r.i.q / btq m.i/base_sp / bsr r.r.q —— 32 位码里不存
 * 在 64 位操作数尺寸的位操作, 不是漏收)。
 *
 * KAT(与 flag/alu/logic/shift 组同一机制): 每个计时内核下面紧跟一行 IB_KT_*
 * 探针, 只执行 1 次、不进循环。本组的口径全在「哪些位架构上真有定义」上:
 *   - bt/bts/btc/btq: 只写 CF, 其余五个不受影响 -> 拿全掩码 IB_FLG_MASK
 *     (比只比 CF 更严: 翻译器不得动剩下五个); btq 那条是内存位数组,
 *     位数组在表里就是 i1(栈槽预置值), %[a] 只是形式上的旁路寄存器;
 *   - bsr/bsf: 源为 0 时 dest 未定义 -> 探针 |1 钳非 0, 且只上 CF/ZF
 *     (IB_FLG_MASK_SCAN); 寄存器位号形态的偏移按架构对操作数宽度取模, 审计
 *     端按同一规则算(i1 & (宽度-1));
 *   - popcnt/lzcnt/tzcnt 与 BMI 六条: 只上结果、不上标志(IB_KT_BITF, MASK=0)。
 *     初版按「标志全不受影响」上了全掩码, 独立复算(kat_audit.py)当场判出 7 处
 *     不符: 采到的 outf 里 blsr=0x80、tzcnt=0x40、bzhi 的 PF 跟结果而 andn 的不跟
 *     —— 既不是「保持注入值」也没有统一的「按结果算」规则, 因为 SDM 给这几条的
 *     标志本来就是逐条描述(且带一堆 undefined)。这类位上了表等于要求 LATX 复现
 *     架构没承诺的东西, 跨机报假不匹配的概率远大于抓到真 bug -> 撤下;
 *     正确性仍由 o0(结果) + i0/i1 两侧入值保证, 对「算错了什么」的覆盖没缩水;
 *   - BMI 三操作数的计数/索引类先钳进安全区间: bzhi 的 index 落在 [0,宽度)、
 *     bextr 的控制字 start+len <= 11 —— 否则要拿「越宽那一支」的行为上表,
 *     而那一段 SDM 描述含糊, 正是 LATX 最可能出现合法差异的地方。
 */
#include "ib_core.h"
#include "ib_buf.h"
#include "isb_bits_kat.h"     /* KAT 真值表(采集后生成; 未取数时全 UNSET) */

/* ---------------- 64 位形态(仅 x86_64) ---------------- */
#ifdef __x86_64__
/* ---- bt_r_r_q: IB_K_FLG ---- */
static uint64_t k_bt_r_r_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "q" " $1,%[a]\n\t" "btq" " " "%[b],%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_bt_r_r_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "q" " $1,%[a]\n\t" "btq" " " "%[b],%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "btq" " " "%[b],%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(c) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "btq" " " "%[b],%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(e) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "btq" " " "%[b],%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(g) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- bt_r_r_q: IB_KT_FLG ---- */
static inline void k_bt_r_r_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("bt_r_r_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("bt_r_r_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("bt_r_r_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "btq" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- btc_r_i_q: IB_K_FLG ---- */
static uint64_t k_btc_r_i_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "q" " $1,%[a]\n\t" "btcq" " " "$5,%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_btc_r_i_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0), c = (IB_UQ)IB_SEED(2), e = (IB_UQ)IB_SEED(4),                
       g = (IB_UQ)IB_SEED(6), b = (IB_UQ)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "q" " $1,%[a]\n\t" "btcq" " " "$5,%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "btcq" " " "$5,%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(c) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "btcq" " " "$5,%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(e) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "q" " $1,%[a]\n\t" "btcq" " " "$5,%[a]" "\n\t"                      
                "adc" "q" " $0,%[a]"                                              
                : [a] "+r"(g) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- btc_r_i_q: IB_KT_FLG ---- */
static inline void k_btc_r_i_q_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("btc_r_i_q", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("btc_r_i_q", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("btc_r_i_q", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "btcq" " " "$5,%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- btq_m_i_base_sp: IB_K_FLG8P ---- */
static uint64_t k_btq_m_i_base_sp(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)IB_SEED(0);                                                        
    __asm__ volatile("mov" "q" " $0x3c," IB_M_SP ::: "memory");                        
    for (i = 0; i < it; i++)                                                      
        __asm__("add" "q" " $1,%[a]\n\t" "btq" " " "$5," IB_M_SP "\n\t"                       
                "adc" "q" " $0,%[a]"                                              
                : [a] "+a"(a) : : "cc", "memory");                                
    return IB_S1(a);                                                              
}                                                                                 
static uint64_t k_btq_m_i_base_sp_tp(unsigned long long it)                                
{                                                                                 
    return k_btq_m_i_base_sp(it);                                                            
}

/* ---- btq_m_i_base_sp: IB_KT_FLG8P ---- */
static inline void k_btq_m_i_base_sp_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UQ a = (IB_UQ)IB_KIN8("btq_m_i_base_sp", kk, 0, IB_UQ), b = (IB_UQ)IB_KIN8("btq_m_i_base_sp", kk, 1, IB_UQ);            
    IB_UQ ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t fv = (uintptr_t)IB_KFL("btq_m_i_base_sp", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "mov" "q" " %[b], " IB_M_SP "\n\t" "btq" " " "$5," IB_M_SP IB_GETF      
                    : [a] "+a"(a), [fl] "=&r"(fl)                                   
                    : [b] "q"(b), [p] "r"(p), [fv] "r"(fv) : "cc", "memory");         
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & IB_FLG_MASK;                                           
}

/* ---- bsr_r_r_q: IB_K_BIT ---- */
static uint64_t k_bsr_r_r_q(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 0x20), s = (IB_UQ)0;                                    
    IB_UQ b = (IB_UQ)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UQ c = (IB_UQ)0x0807, t = (IB_UQ)0x20;                                              
    for (i = 0; i < it; i++)                                                      
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "bsrq" " " "%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    return IB_S2((uint64_t)a, (uint64_t)s);                                       
}                                                                                 
static uint64_t k_bsr_r_r_q_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UQ a = (IB_UQ)(IB_SEED(0) | 0x20), e = (IB_UQ)(IB_SEED(2) | 0x20);                  
    IB_UQ s = (IB_UQ)0, f = (IB_UQ)0;                                                      
    IB_UQ b = (IB_UQ)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UQ c = (IB_UQ)0x0807, t = (IB_UQ)0x20;                                              
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "bsrq" " " "%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
        /* 第二链: 操作数**名**必须仍是 [a]/[s](只换绑定的变量), 见 25 节 ⚠ */                        
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "bsrq" " " "%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(e), [s] "=&r"(f)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    }                                                                             
    return IB_S2(a, e) + IB_S2(s, f);                                             
}

/* ---- bsr_r_r_q: IB_KT_BITNZ ---- */
/* ---- bsr_r_r_q: IB_KT_BITA (manually expanded) ---- */
static inline void k_bsr_r_r_q_kat(int kk, ib_kv *g)
{
    IB_UQ a = (IB_UQ)((IB_UQ)(IB_KIN8("bsr_r_r_q", kk, 0, IB_UQ) | 1)), s = (IB_UQ)(IB_KIN8("bsr_r_r_q", kk, 1, IB_UQ));
    IB_UQ ain = a;
    void *p = ib_kbuf_fill((uint64_t)a);
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);
    __asm__ volatile("bsrq " "%[a],%[s]"
            : [a] "+r"(a), [s] "=&r"(s)
            : [p] "r"(p), [ix] "r"(ix) : "cc", "memory");
    g->i0 = (uint64_t)ain; g->i1 = 0; g->inf = 0;
    g->o0 = (uint64_t)a; g->o1 = (uint64_t)s; g->outf = (uint64_t)0 & (IB_FLG_MASK_SCAN);
}

#endif

/* ---------------- 两 ABI 共有形态 ---------------- */
/* ---- bt_r_r_l: IB_K_FLG ---- */
static uint64_t k_bt_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "l" " $1,%[a]\n\t" "btl" " " "%[b],%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_bt_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "l" " $1,%[a]\n\t" "btl" " " "%[b],%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "btl" " " "%[b],%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(c) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "btl" " " "%[b],%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(e) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "btl" " " "%[b],%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(g) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- bt_r_r_l: IB_KT_FLG ---- */
static inline void k_bt_r_r_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("bt_r_r_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("bt_r_r_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("bt_r_r_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "btl" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- bt_r_i_l: IB_K_FLG ---- */
static uint64_t k_bt_r_i_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "l" " $1,%[a]\n\t" "btl" " " "$5,%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_bt_r_i_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "l" " $1,%[a]\n\t" "btl" " " "$5,%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "btl" " " "$5,%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(c) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "btl" " " "$5,%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(e) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "btl" " " "$5,%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(g) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- bt_r_i_l: IB_KT_FLG ---- */
static inline void k_bt_r_i_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("bt_r_i_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("bt_r_i_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("bt_r_i_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "btl" " " "$5,%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- bts_r_r_l: IB_K_FLG ---- */
static uint64_t k_bts_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "l" " $1,%[a]\n\t" "btsl" " " "%[b],%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return (uint64_t)a;                                                           
}                                                                                 
static uint64_t k_bts_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)IB_SEED(0), c = (IB_UL)IB_SEED(2), e = (IB_UL)IB_SEED(4),                
       g = (IB_UL)IB_SEED(6), b = (IB_UL)IB_SEED(1);                                    
    for (i = 0; i < it; i++) {                                                    
        IB_PROT_P(i);                                                             
        IB_PROT_X(i);                                                             
        __asm__("add" "l" " $1,%[a]\n\t" "btsl" " " "%[b],%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(a) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "btsl" " " "%[b],%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(c) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "btsl" " " "%[b],%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(e) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
        __asm__("add" "l" " $1,%[a]\n\t" "btsl" " " "%[b],%[a]" "\n\t"                      
                "adc" "l" " $0,%[a]"                                              
                : [a] "+r"(g) : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");      
    }                                                                             
    return IB_S4(a, c, e, g);                                                     
}

/* ---- bts_r_r_l: IB_KT_FLG ---- */
static inline void k_bts_r_r_l_kat(int kk, ib_kv *g)                                   
{                                                                                   
    IB_UL a = (IB_UL)IB_KIN8("bts_r_r_l", kk, 0, IB_UL), b = (IB_UL)IB_KIN8("bts_r_r_l", kk, 1, IB_UL);            
    IB_UL ain = a;                                                                    
    void *p = ib_kbuf_fill((uint64_t)b);                                            
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);                                  
    uintptr_t fv = (uintptr_t)IB_KFL("bts_r_r_l", kk), fl = 0;                              
    __asm__ volatile(IB_SETF "btsl" " " "%[b],%[a]" IB_GETF                                   
                    : [a] "+r"(a), [fl] "=&r"(fl)                                     
                    : [b] "q"(b), [p] "r"(p), [ix] "r"(ix), [fv] "r"(fv)             
                    : "cc", "memory");                                              
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b;   g->inf = (uint64_t)fv;             
    g->o0 = (uint64_t)a;   g->o1 = (uint64_t)b;                                    
    g->outf = (uint64_t)fl & (IB_FLG_MASK);                                                
}

/* ---- bsf_r_r_l: IB_K_BIT ---- */
static uint64_t k_bsf_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 0x20), s = (IB_UL)0;                                    
    IB_UL b = (IB_UL)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UL c = (IB_UL)0x0807, t = (IB_UL)0x20;                                              
    for (i = 0; i < it; i++)                                                      
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "bsfl" " " "%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    return IB_S2((uint64_t)a, (uint64_t)s);                                       
}                                                                                 
static uint64_t k_bsf_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 0x20), e = (IB_UL)(IB_SEED(2) | 0x20);                  
    IB_UL s = (IB_UL)0, f = (IB_UL)0;                                                      
    IB_UL b = (IB_UL)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UL c = (IB_UL)0x0807, t = (IB_UL)0x20;                                              
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "bsfl" " " "%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
        /* 第二链: 操作数**名**必须仍是 [a]/[s](只换绑定的变量), 见 25 节 ⚠ */                        
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "bsfl" " " "%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(e), [s] "=&r"(f)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    }                                                                             
    return IB_S2(a, e) + IB_S2(s, f);                                             
}

/* ---- bsf_r_r_l: IB_KT_BITNZ ---- */
/* ---- bsf_r_r_l: IB_KT_BITA (manually expanded) ---- */
static inline void k_bsf_r_r_l_kat(int kk, ib_kv *g)
{
    IB_UL a = (IB_UL)((IB_UL)(IB_KIN8("bsf_r_r_l", kk, 0, IB_UL) | 1)), s = (IB_UL)(IB_KIN8("bsf_r_r_l", kk, 1, IB_UL));
    IB_UL ain = a;
    void *p = ib_kbuf_fill((uint64_t)a);
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);
    __asm__ volatile("bsfl " "%[a],%[s]"
            : [a] "+r"(a), [s] "=&r"(s)
            : [p] "r"(p), [ix] "r"(ix) : "cc", "memory");
    g->i0 = (uint64_t)ain; g->i1 = 0; g->inf = 0;
    g->o0 = (uint64_t)a; g->o1 = (uint64_t)s; g->outf = (uint64_t)0 & (IB_FLG_MASK_SCAN);
}

/* ---- popcnt_r_r_l: IB_K_BIT ---- */
static uint64_t k_popcnt_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 0x20), s = (IB_UL)0;                                    
    IB_UL b = (IB_UL)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UL c = (IB_UL)0x0807, t = (IB_UL)0x20;                                              
    for (i = 0; i < it; i++)                                                      
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "popcntl" " " "%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    return IB_S2((uint64_t)a, (uint64_t)s);                                       
}                                                                                 
static uint64_t k_popcnt_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 0x20), e = (IB_UL)(IB_SEED(2) | 0x20);                  
    IB_UL s = (IB_UL)0, f = (IB_UL)0;                                                      
    IB_UL b = (IB_UL)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UL c = (IB_UL)0x0807, t = (IB_UL)0x20;                                              
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "popcntl" " " "%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
        /* 第二链: 操作数**名**必须仍是 [a]/[s](只换绑定的变量), 见 25 节 ⚠ */                        
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "popcntl" " " "%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(e), [s] "=&r"(f)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    }                                                                             
    return IB_S2(a, e) + IB_S2(s, f);                                             
}

/* ---- popcnt_r_r_l: IB_KT_BITF ---- */
/* ---- popcnt_r_r_l: IB_KT_BITA (manually expanded) ---- */
static inline void k_popcnt_r_r_l_kat(int kk, ib_kv *g)
{
    IB_UL a = (IB_UL)(IB_KIN8("popcnt_r_r_l", kk, 0, IB_UL)), s = (IB_UL)(0);
    IB_UL ain = a;
    void *p = ib_kbuf_fill((uint64_t)a);
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);
    __asm__ volatile("popcntl " "%[a],%[s]"
            : [a] "+r"(a), [s] "=&r"(s)
            : [p] "r"(p), [ix] "r"(ix) : "cc", "memory");
    g->i0 = (uint64_t)ain; g->i1 = 0; g->inf = 0;
    g->o0 = (uint64_t)a; g->o1 = (uint64_t)s; g->outf = (uint64_t)0 & (0);
}

/* ---- lzcnt_r_r_l: IB_K_BIT ---- */
static uint64_t k_lzcnt_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 0x20), s = (IB_UL)0;                                    
    IB_UL b = (IB_UL)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UL c = (IB_UL)0x0807, t = (IB_UL)0x20;                                              
    for (i = 0; i < it; i++)                                                      
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "lzcntl" " " "%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    return IB_S2((uint64_t)a, (uint64_t)s);                                       
}                                                                                 
static uint64_t k_lzcnt_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 0x20), e = (IB_UL)(IB_SEED(2) | 0x20);                  
    IB_UL s = (IB_UL)0, f = (IB_UL)0;                                                      
    IB_UL b = (IB_UL)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UL c = (IB_UL)0x0807, t = (IB_UL)0x20;                                              
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "lzcntl" " " "%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
        /* 第二链: 操作数**名**必须仍是 [a]/[s](只换绑定的变量), 见 25 节 ⚠ */                        
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "lzcntl" " " "%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(e), [s] "=&r"(f)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    }                                                                             
    return IB_S2(a, e) + IB_S2(s, f);                                             
}

/* ---- lzcnt_r_r_l: IB_KT_BITF ---- */
/* ---- lzcnt_r_r_l: IB_KT_BITA (manually expanded) ---- */
static inline void k_lzcnt_r_r_l_kat(int kk, ib_kv *g)
{
    IB_UL a = (IB_UL)(IB_KIN8("lzcnt_r_r_l", kk, 0, IB_UL)), s = (IB_UL)(0);
    IB_UL ain = a;
    void *p = ib_kbuf_fill((uint64_t)a);
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);
    __asm__ volatile("lzcntl " "%[a],%[s]"
            : [a] "+r"(a), [s] "=&r"(s)
            : [p] "r"(p), [ix] "r"(ix) : "cc", "memory");
    g->i0 = (uint64_t)ain; g->i1 = 0; g->inf = 0;
    g->o0 = (uint64_t)a; g->o1 = (uint64_t)s; g->outf = (uint64_t)0 & (0);
}

/* ---- tzcnt_r_r_l: IB_K_BIT ---- */
static uint64_t k_tzcnt_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 0x20), s = (IB_UL)0;                                    
    IB_UL b = (IB_UL)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UL c = (IB_UL)0x0807, t = (IB_UL)0x20;                                              
    for (i = 0; i < it; i++)                                                      
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "tzcntl" " " "%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    return IB_S2((uint64_t)a, (uint64_t)s);                                       
}                                                                                 
static uint64_t k_tzcnt_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 0x20), e = (IB_UL)(IB_SEED(2) | 0x20);                  
    IB_UL s = (IB_UL)0, f = (IB_UL)0;                                                      
    IB_UL b = (IB_UL)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UL c = (IB_UL)0x0807, t = (IB_UL)0x20;                                              
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "tzcntl" " " "%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
        /* 第二链: 操作数**名**必须仍是 [a]/[s](只换绑定的变量), 见 25 节 ⚠ */                        
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "tzcntl" " " "%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(e), [s] "=&r"(f)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    }                                                                             
    return IB_S2(a, e) + IB_S2(s, f);                                             
}

/* ---- tzcnt_r_r_l: IB_KT_BITF ---- */
/* ---- tzcnt_r_r_l: IB_KT_BITA (manually expanded) ---- */
static inline void k_tzcnt_r_r_l_kat(int kk, ib_kv *g)
{
    IB_UL a = (IB_UL)(IB_KIN8("tzcnt_r_r_l", kk, 0, IB_UL)), s = (IB_UL)(0);
    IB_UL ain = a;
    void *p = ib_kbuf_fill((uint64_t)a);
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);
    __asm__ volatile("tzcntl " "%[a],%[s]"
            : [a] "+r"(a), [s] "=&r"(s)
            : [p] "r"(p), [ix] "r"(ix) : "cc", "memory");
    g->i0 = (uint64_t)ain; g->i1 = 0; g->inf = 0;
    g->o0 = (uint64_t)a; g->o1 = (uint64_t)s; g->outf = (uint64_t)0 & (0);
}

/* ---- andn_r_r_l: IB_K_BIT ---- */
static uint64_t k_andn_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 0x20), s = (IB_UL)0;                                    
    IB_UL b = (IB_UL)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UL c = (IB_UL)0x0807, t = (IB_UL)0x20;                                              
    for (i = 0; i < it; i++)                                                      
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "andnl" " " "%[b],%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    return IB_S2((uint64_t)a, (uint64_t)s);                                       
}                                                                                 
static uint64_t k_andn_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 0x20), e = (IB_UL)(IB_SEED(2) | 0x20);                  
    IB_UL s = (IB_UL)0, f = (IB_UL)0;                                                      
    IB_UL b = (IB_UL)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UL c = (IB_UL)0x0807, t = (IB_UL)0x20;                                              
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "andnl" " " "%[b],%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
        /* 第二链: 操作数**名**必须仍是 [a]/[s](只换绑定的变量), 见 25 节 ⚠ */                        
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "andnl" " " "%[b],%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(e), [s] "=&r"(f)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    }                                                                             
    return IB_S2(a, e) + IB_S2(s, f);                                             
}

/* ---- andn_r_r_l: IB_KT_BITF ---- */
/* ---- andn_r_r_l: IB_KT_BITA (manually expanded) ---- */
static inline void k_andn_r_r_l_kat(int kk, ib_kv *g)
{
    IB_UL a = (IB_UL)(IB_KIN8("andn_r_r_l", kk, 0, IB_UL)), s = (IB_UL)(0);
    IB_UL b = (IB_UL)(IB_KIN8("andn_r_r_l", kk, 1, IB_UL));
    IB_UL ain = a;
    void *p = ib_kbuf_fill((uint64_t)a);
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);
    __asm__ volatile("andnl " "%[b],%[a],%[s]"
            : [a] "+r"(a), [s] "=&r"(s)
            : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b; g->inf = 0;
    g->o0 = (uint64_t)a; g->o1 = (uint64_t)s; g->outf = (uint64_t)0 & (0);
}

/* ---- bzhi_r_r_l: IB_K_BIT ---- */
static uint64_t k_bzhi_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 0x20), s = (IB_UL)0;                                    
    IB_UL b = (IB_UL)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UL c = (IB_UL)0x0807, t = (IB_UL)0x20;                                              
    for (i = 0; i < it; i++)                                                      
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "bzhil" " " "%[c],%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    return IB_S2((uint64_t)a, (uint64_t)s);                                       
}                                                                                 
static uint64_t k_bzhi_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 0x20), e = (IB_UL)(IB_SEED(2) | 0x20);                  
    IB_UL s = (IB_UL)0, f = (IB_UL)0;                                                      
    IB_UL b = (IB_UL)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UL c = (IB_UL)0x0807, t = (IB_UL)0x20;                                              
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "bzhil" " " "%[c],%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
        /* 第二链: 操作数**名**必须仍是 [a]/[s](只换绑定的变量), 见 25 节 ⚠ */                        
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "bzhil" " " "%[c],%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(e), [s] "=&r"(f)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    }                                                                             
    return IB_S2(a, e) + IB_S2(s, f);                                             
}

/* ---- bzhi_r_r_l: IB_KT_BITZ ---- */
/* ---- bzhi_r_r_l: IB_KT_BITA (manually expanded) ---- */
static inline void k_bzhi_r_r_l_kat(int kk, ib_kv *g)
{
    IB_UL a = (IB_UL)(IB_KIN8("bzhi_r_r_l", kk, 0, IB_UL)), s = (IB_UL)0;
    IB_UL ain = a;
    IB_UL b = (IB_UL)(IB_KIN8("bzhi_r_r_l", kk, 1, IB_UL) & (8 * (int)sizeof(IB_UL) - 1));
    void *p = ib_kbuf_fill((uint64_t)ain);
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);
    __asm__ volatile("bzhil " "%[b],%[a],%[s]"
            : [a] "+r"(a), [s] "=&r"(s)
            : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b; g->inf = 0;
    g->o0 = (uint64_t)a; g->o1 = (uint64_t)s; g->outf = (uint64_t)0 & (0);
}/* ---- blsr_r_r_l: IB_K_BIT ---- */
static uint64_t k_blsr_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 0x20), s = (IB_UL)0;                                    
    IB_UL b = (IB_UL)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UL c = (IB_UL)0x0807, t = (IB_UL)0x20;                                              
    for (i = 0; i < it; i++)                                                      
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "blsrl" " " "%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    return IB_S2((uint64_t)a, (uint64_t)s);                                       
}                                                                                 
static uint64_t k_blsr_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 0x20), e = (IB_UL)(IB_SEED(2) | 0x20);                  
    IB_UL s = (IB_UL)0, f = (IB_UL)0;                                                      
    IB_UL b = (IB_UL)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UL c = (IB_UL)0x0807, t = (IB_UL)0x20;                                              
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "blsrl" " " "%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
        /* 第二链: 操作数**名**必须仍是 [a]/[s](只换绑定的变量), 见 25 节 ⚠ */                        
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "blsrl" " " "%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(e), [s] "=&r"(f)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    }                                                                             
    return IB_S2(a, e) + IB_S2(s, f);                                             
}

/* ---- blsr_r_r_l: IB_KT_BITF ---- */
/* ---- blsr_r_r_l: IB_KT_BITA (manually expanded) ---- */
static inline void k_blsr_r_r_l_kat(int kk, ib_kv *g)
{
    IB_UL a = (IB_UL)(IB_KIN8("blsr_r_r_l", kk, 0, IB_UL)), s = (IB_UL)(0);
    IB_UL ain = a;
    void *p = ib_kbuf_fill((uint64_t)a);
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);
    __asm__ volatile("blsrl " "%[a],%[s]"
            : [a] "+r"(a), [s] "=&r"(s)
            : [p] "r"(p), [ix] "r"(ix) : "cc", "memory");
    g->i0 = (uint64_t)ain; g->i1 = 0; g->inf = 0;
    g->o0 = (uint64_t)a; g->o1 = (uint64_t)s; g->outf = (uint64_t)0 & (0);
}

/* ---- bextr_r_r_l: IB_K_BIT ---- */
static uint64_t k_bextr_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 0x20), s = (IB_UL)0;                                    
    IB_UL b = (IB_UL)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UL c = (IB_UL)0x0807, t = (IB_UL)0x20;                                              
    for (i = 0; i < it; i++)                                                      
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "bextrl" " " "%[c],%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    return IB_S2((uint64_t)a, (uint64_t)s);                                       
}                                                                                 
static uint64_t k_bextr_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 0x20), e = (IB_UL)(IB_SEED(2) | 0x20);                  
    IB_UL s = (IB_UL)0, f = (IB_UL)0;                                                      
    IB_UL b = (IB_UL)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UL c = (IB_UL)0x0807, t = (IB_UL)0x20;                                              
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "bextrl" " " "%[c],%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
        /* 第二链: 操作数**名**必须仍是 [a]/[s](只换绑定的变量), 见 25 节 ⚠ */                        
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "bextrl" " " "%[c],%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(e), [s] "=&r"(f)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    }                                                                             
    return IB_S2(a, e) + IB_S2(s, f);                                             
}

/* ---- bextr_r_r_l: IB_KT_BITX ---- */
/* ---- bextr_r_r_l: IB_KT_BITA (manually expanded) ---- */
static inline void k_bextr_r_r_l_kat(int kk, ib_kv *g)
{
    IB_UL a = (IB_UL)(IB_KIN8("bextr_r_r_l", kk, 0, IB_UL)), s = (IB_UL)0;
    IB_UL ain = a;
    IB_UL b = (IB_UL)((IB_KIN("bextr_r_r_l", kk, 1) & 7ULL) | ((((IB_KIN("bextr_r_r_l", kk, 1) >> 3) & 3ULL) + 1ULL) << 8));
    void *p = ib_kbuf_fill((uint64_t)ain);
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);
    __asm__ volatile("bextrl " "%[b],%[a],%[s]"
            : [a] "+r"(a), [s] "=&r"(s)
            : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b; g->inf = 0;
    g->o0 = (uint64_t)a; g->o1 = (uint64_t)s; g->outf = (uint64_t)0 & (0);
}/* ---- pdep_r_r_l: IB_K_BIT ---- */
static uint64_t k_pdep_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 0x20), s = (IB_UL)0;                                    
    IB_UL b = (IB_UL)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UL c = (IB_UL)0x0807, t = (IB_UL)0x20;                                              
    for (i = 0; i < it; i++)                                                      
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "pdepl" " " "%[b],%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    return IB_S2((uint64_t)a, (uint64_t)s);                                       
}                                                                                 
static uint64_t k_pdep_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 0x20), e = (IB_UL)(IB_SEED(2) | 0x20);                  
    IB_UL s = (IB_UL)0, f = (IB_UL)0;                                                      
    IB_UL b = (IB_UL)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UL c = (IB_UL)0x0807, t = (IB_UL)0x20;                                              
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "pdepl" " " "%[b],%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
        /* 第二链: 操作数**名**必须仍是 [a]/[s](只换绑定的变量), 见 25 节 ⚠ */                        
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "pdepl" " " "%[b],%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(e), [s] "=&r"(f)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    }                                                                             
    return IB_S2(a, e) + IB_S2(s, f);                                             
}

/* ---- pdep_r_r_l: IB_KT_BITF ---- */
/* ---- pdep_r_r_l: IB_KT_BITA (manually expanded) ---- */
static inline void k_pdep_r_r_l_kat(int kk, ib_kv *g)
{
    IB_UL a = (IB_UL)(IB_KIN8("pdep_r_r_l", kk, 0, IB_UL)), s = (IB_UL)(0);
    IB_UL b = (IB_UL)(IB_KIN8("pdep_r_r_l", kk, 1, IB_UL));
    IB_UL ain = a;
    void *p = ib_kbuf_fill((uint64_t)a);
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);
    __asm__ volatile("pdepl " "%[b],%[a],%[s]"
            : [a] "+r"(a), [s] "=&r"(s)
            : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b; g->inf = 0;
    g->o0 = (uint64_t)a; g->o1 = (uint64_t)s; g->outf = (uint64_t)0 & (0);
}

/* ---- pext_r_r_l: IB_K_BIT ---- */
static uint64_t k_pext_r_r_l(unsigned long long it)                                     
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 0x20), s = (IB_UL)0;                                    
    IB_UL b = (IB_UL)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UL c = (IB_UL)0x0807, t = (IB_UL)0x20;                                              
    for (i = 0; i < it; i++)                                                      
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "pextl" " " "%[b],%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    return IB_S2((uint64_t)a, (uint64_t)s);                                       
}                                                                                 
static uint64_t k_pext_r_r_l_tp(unsigned long long it)                                
{                                                                                 
    unsigned long long i;                                                         
    IB_UL a = (IB_UL)(IB_SEED(0) | 0x20), e = (IB_UL)(IB_SEED(2) | 0x20);                  
    IB_UL s = (IB_UL)0, f = (IB_UL)0;                                                      
    IB_UL b = (IB_UL)((IB_SEED(1) & 0x0f0f0f0f) | 0x01010101);                          
    IB_UL c = (IB_UL)0x0807, t = (IB_UL)0x20;                                              
    for (i = 0; i < it; i++) {                                                    
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "pextl" " " "%[b],%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(a), [s] "=&r"(s)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
        /* 第二链: 操作数**名**必须仍是 [a]/[s](只换绑定的变量), 见 25 节 ⚠ */                        
        __asm__("lea (%[a],%[a],4),%[a]\n\t" "pextl" " " "%[b],%[a],%[s]"                         
                "\n\tadd %[s],%[a]\n\tor %[t],%[a]"                               
                : [a] "+r"(e), [s] "=&r"(f)                                       
                : [b] "r"(b), [c] "r"(c), [t] "r"(t) : "cc");                     
    }                                                                             
    return IB_S2(a, e) + IB_S2(s, f);                                             
}

/* ---- pext_r_r_l: IB_KT_BITF ---- */
/* ---- pext_r_r_l: IB_KT_BITA (manually expanded) ---- */
static inline void k_pext_r_r_l_kat(int kk, ib_kv *g)
{
    IB_UL a = (IB_UL)(IB_KIN8("pext_r_r_l", kk, 0, IB_UL)), s = (IB_UL)(0);
    IB_UL b = (IB_UL)(IB_KIN8("pext_r_r_l", kk, 1, IB_UL));
    IB_UL ain = a;
    void *p = ib_kbuf_fill((uint64_t)a);
    uintptr_t ix = (uintptr_t)((unsigned)kk & 7u);
    __asm__ volatile("pextl " "%[b],%[a],%[s]"
            : [a] "+r"(a), [s] "=&r"(s)
            : [b] "r"(b), [p] "r"(p), [ix] "r"(ix) : "cc", "memory");
    g->i0 = (uint64_t)ain; g->i1 = (uint64_t)b; g->inf = 0;
    g->o0 = (uint64_t)a; g->o1 = (uint64_t)s; g->outf = (uint64_t)0 & (0);
}

/* ---------------- 用例表(bpop = 每 op 处理字节数, 供 tput 折 MB/s) -------- */
static const ib_case g_cases[] = {
    /* 两 ABI 共有 */
    IB_ROW_K("x86_bt__r_r_l",         NULL, bt_r_r_l,         4),
    IB_ROW_K("x86_bt__r_i_l",          NULL, bt_r_i_l,         4),
    IB_ROW_K("x86_bts__r_r_l",         NULL, bts_r_r_l,        4),
    IB_ROW_K("x86_bsf__r_r_l",         NULL, bsf_r_r_l,        4),
    IB_ROW_K("x86_popcnt__r_r_l",      NULL, popcnt_r_r_l,     4),
    IB_ROW_K("x86_lzcnt__r_r_l",       NULL, lzcnt_r_r_l,      4),
    IB_ROW_K("x86_tzcnt__r_r_l",       NULL, tzcnt_r_r_l,      4),
    IB_ROW_K("x86_andn__r_r_l",        NULL, andn_r_r_l,       4),
    IB_ROW_K("x86_bzhi__r_r_l",        NULL, bzhi_r_r_l,       4),
    IB_ROW_K("x86_blsr__r_r_l",        NULL, blsr_r_r_l,       4),
    IB_ROW_K("x86_bextr__r_r_l",       NULL, bextr_r_r_l,      4),
    IB_ROW_K("x86_pdep__r_r_l",        NULL, pdep_r_r_l,       4),
    IB_ROW_K("x86_pext__r_r_l",        NULL, pext_r_r_l,       4),
#ifdef __x86_64__
    /* 64 位专有形态 */
    IB_ROW_K("x86_bt__r_r_q",          NULL, bt_r_r_q,         8),
    IB_ROW_K("x86_bsr__r_r_q",         NULL, bsr_r_r_q,        8),
    IB_ROW_K("x86_btc__r_i_q",         NULL, btc_r_i_q,        8),
    IB_ROW_K("x86_btq__m_i_base_sp",   NULL, btq_m_i_base_sp,  8),
#endif
};
#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

int main(int argc, char **argv)
{
    ib_init(argc, argv);
    ib_abuf_init();                 /* 只读/写区确定性预置(签名跨机可复现的前提) */
    ib_hdr("bits", NCASES);
    ib_run_cases("bits", g_cases, NCASES);
    return 0;
}
