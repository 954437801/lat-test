/* isb_x87.c —— isbench「x87 定点数搬运」组(i386 专属): FILD / FIST / FISTP /
 *              FISTTP / FBLD / FLD m80real / FST m80real 的整型往返精度。
 *
 * 为什么要单独立一组(缺陷本体, 见 docs/设计/分组与命名.md「x87 定点数搬运组」一节与
 * 设计文档第 4 章): LATX 翻译 i386 的 x87 整型搬运时, 把 FILD m64int 按
 * double(53 位尾数)取整装载, 把 FISTP m64int 按 double 中转, 于是 |值| >= 2^53
 * 时**往返丢位**。上层症状: OpenSSL 3.x 的 namemap 用 FNV-1a 64 位哈希做键,
 * 键值失真 -> 每一次 EVP_*_fetch 返回空 -> 全部算法取不到, 且**不崩不报**,
 * 只在功能层表现为"没有这个算法"。special 组原有的 x87 用例入值口径是 n/4
 * (<= 24 位整数, 刻意保证 double 也能精确表示), 结构上不可能撞上这个缺陷 ——
 * 本组的存在理由就是把入值挪到**高有效位**(>= 2^53, 覆盖 2^63 边界与负侧)。
 *
 * 为什么只在 i386 注册(下面第 1 条是**唯一站得住的理由**, 第 2 条已被实测推翻):
 *   1) 编译器事实: 只有 -m32 的 GCC 默认 -mfpmath=387 才发射 x87 整型搬运;
 *      x86_64 的 psABI 强制 SSE2 做浮点, 整型<->浮点转换走 cvtsi2sd/cvttsd2si。
 *      真实负载(32 位 x86 应用等)在 64 位下根本不会执行到 fildll/fistpll, 给 x86_64 造
 *      一份 x87 探针 = 测一条不存在的路径, 且会把"i386 才有"的缺陷读数摊薄成
 *      两 ABI 各半的假覆盖。
 *   2) 原先写在这里的"ISA 事实"(SDM: FLD/FST/FSTP m80real 在 64-Bit Mode 为
 *      Invalid)**不能拿来当护栏** —— 实测(实测, 探针 ABI 对比脚本):
 *      同一份源用 gcc 不带 -m32 编出 x86_64 ELF, 在本机 构建机 上 fldt/fstpt 照旧
 *      执行(不 #UD、rc=0、164 行齐全), 自报 ok=18/18, 且 144 块 K 行与 参考机 的
 *      **i386 ELF** 逐字相同。=> 误登记成 x87_x86_64_* 之后, 运行期与比对期都
 *      看不出任何异常, 只有"这一组的数从哪台机器哪种模式采的"记在 abi 列里。
 *      故本文件底部有 #error 硬拦非 i386 编译, build.sh 的白名单只是第二道。
 *   3) FIST m64int 在 ISA 里**不存在**(只有 m16/m32 的 FIST 不弹栈形), gas 亦
 *      拒 `fistll`; 64 位宽只有弹栈形 `fistpll` = DF/7。AT&T 的 m16int 装载形
 *      助记符是 `filds` = DF/0(被拒的是 `fildw`)。全套编码见下面「实测编码表」。
 *
 * 判据三分界(每条用例注明它属于哪一类, 决定它能不能进真值表):
 *   [解析] 期望值可由 SDM 文本 + 纯整数算式推导, 不需要任何参考机采集也能断言;
 *   [采集] 期望值只能从 x86 参考机实测得到(本组里几乎不存在, 见各条注);
 *   [档间] 只断言"换档前后自位形一致", 不断言绝对值。**本组没有一条按这一类定期望**
 *     —— 实测 g 重做(见下 g0)证明 PC 被硬件 honor, 于是 P2/P3 每一档都能给绝对值
 *     期望; 这一类只剩"第二道判据"的位置(P3 的 pc24/pc53 共用同一入值向量, 档间
 *     对照仍核, 但不再当唯一判据, 见 3) 节末与 kat_audit.py 的 pc_arm_relation)。
 *   P1 全 12 条都是 [解析]: FILD/FISTP/FBLD 对整数的精确往返、FST m80 的左规
 *   位形、超出 int64 时的 integer-indefinite, 全都是架构承诺, 所以**这一组的
 *   真值表本身就是断言**, 参考机只负责确认"我的推导没抄错 SDM"。
 *
 * 双物理机实测事实(实测; 探针 校验探针, 两份输出
 *   实测记录 / 实测记录 由 校验脚本 逐行
 *   比对 = 104 行完全一致; 顺序按门禁: 先 Windows 本机 PE
 *   (i686-w64-mingw32-gcc -O2 -static), 后 参考机 native ELF(gcc -m32 -O2 -static)):
 *   a) 状态字位序: IE/DE/ZE/OE/UE/PE/SF/ES = bit0..7, C0=8 C1=9 C2=10,
 *      **TOP = bits 11-13(LSB=bit11)**, C3=14, B=15。三条独立证据: fincstp 每步
 *      +0x0800 且 8 步回环; fnstsw m2byte 与 fnstsw ax 两路同字; fcompp 位形自洽
 *      (相等 0x4000 / ST0<ST1 0x0100 / ST0>ST1 0x0000 / 无序 0x4500)。
 *      —— 凡按"TOP=bits 8-10"写的解析一律读成恒 0, 那是抄错的 SDM, 不是硬件差异。
 *   b) masked 异常**不置 ES**: 1/0 -> 0x3804(ZE=1, ES=0); sqrt(-1) -> 0x3801;
 *      9 次 fld1 溢出 -> 0x3a41(TOP=7 C1=1 SF=1 IE=1 ES=0); 弹空下溢 -> 0x0841。
 *      => 任何拿 ES 当断言的判据都是错的, P6 按 unmasked 路径另做。
 *   c) FISTP 越界是 #IA/IE 而**不是 OE**: fistpll(2^63) 与 fistpll(+Inf) 都写回
 *      0x8000000000000000 且 SW=0x0001。本组 fistp_q_indef 就钉这一对。
 *   d) PE 不轻置: 1.0+2^-60 在 80 位下精确(SW=0x3800, PE=0); 两个最小 denormal
 *      相加只置 DE(0x3802)。
 *   e) native 的 FILD m64int 真按 80 位精确装载: 8/8 入值左规尾数 == 期望
 *      (含 0x7fffffffffffffff -> 403d.fffffffffffffffe、-2^63 -> 403e.8000...)。
 *      m32int/m16int 侧同口径 8/8 无损。
 *   f) FBLD 量程 = 18 位十进制(9 字节 packed BCD, 低位在前, 第 10 字节 bit7 为
 *      负号): 0x0de0b6b3a763ffff(=999999999999999999)无损且符号正确; 19 位入值
 *      必被截 => 本组 BVEC 全部 < 1e18。
 *   g) PC(精度控制)**被硬件 honor**, 且 RC 在位 10-11(不在 2-3)。这一条原先写的是
 *      "PC 被硬件忽略 => P3 只能走[档间]", 那个结论是**伪实测**得到的, 重做过程与
 *      教训全在下面 g0): 现按实测订正。
 *      g0) 为什么重做: 旧探针 校验探针 的 pc_probe() 里 `andl $0xffffc3ff`
 *          清的是**位 10-11**(0xc3ff 那两个 0 在 10/11), PC 所在的位 8-9 从没被清过 ——
 *          finit 后 0x037f 的位 8-9 本就是 11, `orl` 只能置 1 不能清 0 => 所谓"三档"
 *          写进去的是同一个 0x037f, "三档位形逐位相同"是必然结果、不是硬件事实。
 *          旧日志 实测记录 自己就写着这件事(三行全 `(cw 037f->037f)`),
 *          但它打印的是**我们写进内存的数**、不是 fnstcw 的硬件读回, 所以当场没被
 *          发现。重做探针 = 校验探针(三节: RC 定位 / PC 三档 / 可写位档),
 *          两份输出 实测记录(本机 PE) 与 实测记录(native ELF)
 *          去掉 CR 后**逐字节相同**(PE 侧每行带 \r 是 mingw 文本模式的 stdout, 属通道
 *          不是数据差); 且两边各数出 38 条 x87 指令、次序一致(反汇编记录) ——
 *          先核"发出去的是什么", 再读"硬件回了什么", 这两步缺一步就会重演旧错。
 *      g1) **RC = 位 10-11**: 把位 2-3 改遍 4 档, 四个入值的 fistpl 结果恒等(=RN 签名);
 *          改位 10-11 才跟着变, 且 enc=0/1/2/3 的签名 = RN(-4,-4,2,4) / RD(-4,-4,2,3)
 *          / RU(-3,-3,3,4) / RZ(-3,-3,2,3), 与 SDM 的 00=就近取偶、01=向 -inf、
 *          10=向 +inf、11=向零 逐档吻合。=> P2 的 fldcw 必须置位 10-11; 而 special 迁来
 *          的 fcw_rt 注里"RC(位 2-3)"是错的(那条 case 只断言"写下去 16 位原样读回",
 *          位序写错也不会响 —— 这类"过而不验"的期望要靠改档看结果变不变来定位)。
 *      g2) **PC = 位 8-9, 且真影响算术结果**: 同一算式三档给出三个互异位形 ——
 *          fadd 1.0+2^-40 存 m80: 24 档 = 1.0(尾数 8000000000000000), 53/64 档 =
 *          1+2^-40(8000000000800000); fmul (2^27+1)^2 存 m80: 24 档 = 2^54
 *          (8000000000000000), 53 档 = 2^54+2^28(8000002000000000), 64 档 =
 *          2^54+2^28+1(8000002000000200)。保留档 PC=01 与 64 档同值。指数恒为
 *          0x3fff/0x4035, 说明变的是尾数位宽、不是量级。而 fildll->fstpl(全程不做
 *          算术)三档恒同 => 旧实测 那半句"装载/存出不受 PC 影响"仍成立, 只是当时
 *          拿不到的前提(位真变了 + 硬件读回)现在补上了。
 *      g3) 控制字**可写位档**: 写 0xffff 读回 0x1f7f、写 0x0000 读回 0x0040 => 位 6 恒 1、
 *          位 7 与 13-15 恒 0, 位 0-5 与 8-12 原样读回(bit12 实测可写)。=> 凡拿
 *          0xffff/0x0000 当 fldcw 入值并要求"逐位读回相等"的期望都是错的; P2 的
 *          rc_fstcw_rt 按计划只断言"两次读回之间仅 RC 两位变", 而这条断言的位段
 *          正是 g1 定下来的。finit 默认 cw=0x037f sw=0x0000(本组 X87_BEGIN() 的落点)。
 *      对本次判据的连带后果(不写清就会被当成随手改口径): 判据三分界把 P3 划给
 *        [档间]、依据是"现代 Intel 硬件忽略 PC、恒用 80 位内部精度", 而该前提在
 *        计划点名的那台机器(参考机)上已被上面 g2 的实测否掉。所以 P3 三条
 *        改走"每档解析期望(纯整数算式推 PC 位宽截断) + 档间包含关系(pc53 结果 == 把
 *        pc64 精确结果舍到 53 位)", **不再**断言"三档逐位相同" —— 留着那条会把正确
 *        实现判成 FAIL。词干与指令序列仍按计划给的三个名字不变。计划里"真机忽略 PC
 *        是实现行为、非 SDM 强制, 不得写成 LATX 违约"那句随之失效: 阶段二 LATX 若
 *        三档同值, 那就是与 SDM 和两台真机都相反的行为, 归因口径要按本节重述并进
 *        设计文档(不擅自改计划文件)。
 *   h) FIST/FISTP 实际写宽与弹栈(目的缓冲预置 0xAA 哨兵数改动字节):
 *      fists 2 不弹 / fistps 2 弹 / fistl 4 不弹 / fistpl 4 弹 /
 *      fistpll 8 弹 / fisttps 2 弹 / fisttpl 4 弹 / fisttpll 8 弹。
 *      注意: special 组原注释里"`fistpll` 编出来是 df /3(SDM 的 FIST, 不弹)"
 *      是把 modrm 0x3c 的**首位 hex 当 reg 号**的误读(reg 实为 7 = FISTP m64int),
 *      而"行为像弹"本来就是 ISA 写的弹 —— 本次迁出时一并订正, 内核语义不变。
 *   i) FST 到 m64real 的舍入会把方向记进状态字(实测 a 的位序在此直接可用): 两台
 *      真机 fild_fstp_q_dbl 的 8 组 fnstsw = 0x000(精确: 2^53、-1、-2^63)、
 *      0x020(舍入且量级变小: 2^53+1 平局取偶、k=2/k=4)、 0x220(舍入且
 *      量级变大: INT64_MAX 舍上到 2^63、k=7)。=> PE 与 C1 都是**可推导的期望**、不是机器噪声;
 *      而"负数 + 量级变大"这一组合本向量没有实测, 所以 kat_audit.py 碰到它
 *      直接点名要新实测, 不拿没验过的"数轴方向"读法替硬件说话。
 *
 * 实测(探针 ABI 对比脚本, 与上面 1-5 不是同一件事: 那五组是"指令行为",
 *   这一组是"登记口径"): 把同一份源用 gcc 不带 -m32 编成 x86_64 ELF 在本机跑 ——
 *   rc=0、164 行齐全、T=18 / K=144、自报 ok=18/18, 且 144 块 K 行(13 列全字段)
 *   与 参考机 上跑的 **i386 ELF** 逐字相同(差异 0 块)。两个直接结论:
 *     a) 文件头原先那条"FLD/FST m80real 在 64-Bit Mode Invalid 所以天然隔离"
 *        不成立 —— 本机微架构照旧执行了 fldt/fstpt, 规范文本没护栏作用;
 *     b) 正因为跑起来全绿、数据还一致, 误登记**不会**被任何运行期/比对期检查发现,
 *        所以隔离只能做在编译期: 本文件顶部的 #error + build.sh 的 i386-only 白名单。
 *
 * 实测(B3 前置: P5 栈 / P6 异常 / P7 特殊 的全部空档) —— 两份探针、两次双基准:
 *   校验探针(异常延迟上报 + 栈/标记/环境 + 组合方向, 按 mode 分进程),
 *     输出 实测记录 与 实测记录 各 203 行, 去掉 CR 后逐字节相同;
 *   校验探针(G1..G7), 输出 实测记录 与 实测记录 各 366 行,
 *     同样逐字节相同; 且 G7 是**双基准成立之后**补的一节, 补档前那 245 行旧读数在新拍里
 *     逐行原样还在(校验脚本 的子序列判据 = 0, 两侧各跑一遍) —— 因为
 *     补档时顺带修了打印器 f80() 在非规格化档的一个真错, 而旧读数与它共用打印器。
 *   下面每条都是实跑读数(括号为文件里的行标), P5/P6/P7 的期望只能从这里取。
 *   a) **异常只能走 masked 路径**(早期设计/105 行两处口径按实测改):
 *      清 ZEM 后真造一次 1/0: 出错指令**自身不死**(打印了"div 之后还活着"), fnstsw 也不
 *      死且读回 0xb884(ZE=1、ES=1、B=1、TOP=7) => 早期设计问的"ES 后接 fnstsw 会不会
 *      转成 #MF"答案是不会; 但**下一条 x87 指令 fld1 就没回来** —— 该 mode 的输出正好截
 *      在 fld1 之前那行, 而 stdout 是 _IONBF 无缓冲、参考机 侧同一处截断。另一路把 IEM 清掉
 *      造 sqrt(-1): 读回 0xb881, 再 fnclex -> 0x3800(ES 被清) -> 这次 fwait 活着回来。
 *      三条合起来 = **延迟上报模型成立**(出错指令完成、#MF 在下一条"检查形"指令交付),
 *      而 fnstsw 不是检查形。special 旧注记过"fmul 溢出挂起导致其后两个 case 没行、整组无
 *      DONE", 当时只当经验教训, 现在有了机制解释 => 本组所有内核必须全程 CW=0x037f 全屏蔽。
 *      还有一条堵掉"手动造 ES"这条路: 用 frstor 装一个 ES=1 的状态镜像, 装 0x0080 读回
 *      0x0000、装 0x0081 读回 0x0001、装 0x00bf 读回 0x003f => **ES 与 SF 都不在可装载
 *      位范围内**, 想给 ES 造期望只有真发异常一条路, 而那条路会把进程带走(见 h) ②)。
 *   b) **fnclex 清什么**: 置 IE 之后 fnclex -> 0x3801 变 0x3800(IE 清、TOP 不变); 无异常时
 *      fnclex 前后逐位相同(不误伤); 而**栈溢出**那档 fnclex 后是 0x3a41 -> 0x3a00 ——
 *      IE 与 SF 清了, **C1 仍留着**。早期设计"清全部 Px 与 ES"因此限定为"清 Px 与 ES、
 *      不清 C1"(fnclex_clears 的判据就按这条写)。
 *   c) TOP 与栈操作: 压栈 TOP 逐次 -1(第 1 次压栈读回 0x3800 即 TOP=7, 第 8 次 TOP=0),
 *      第 9 次才报 IE|SF 且 C1=1(0x3a41); 弹栈逐次 +1, 8 压 8 弹后 TOP 回 0 且 C1=0、全程
 *      无异常; 8 压 8 弹的**值序**是 LIFO 反序(G2 逐值核过)。fincstp 每步 +0x0800 且 8 步
 *      回环, fdecstp 反向、从 0 退到 7。ffree st0 / st2 之后 fnstenv 读回的 tag 字 =
 *      0x00ff -> 0x03ff -> 0x33ff(每寄存器两位、ST(k) 在 bit 2k, 置 11=空), 且**后续压栈不
 *      复用空槽**、照旧从 TOP 走位(所以 ffree 之后还要多压几次才会溢出)。注意连续多次
 *      溢出的 C1 是 1/0 交替的(0x3a41/0x3041/0x2a41/0x2041/0x1a41), 机制未明 => P5 的入值
 *      一律只造**一次**溢出, 不把这条模式写成期望(不拿没解释的图案当架构承诺)。
 *   d) FXCH / FLD st(i): FXCH st(i) 只换 ST0 与 ST(i)、TOP 不变(4 项时 fxch st3 之后的弹栈
 *      序列 = 1,4,2,8, 与"入栈 1,2,4,8 后 ST0<->ST3"逐项吻合), FLD st(i) 是**压栈**(TOP 继续
 *      -1)且压的是 ST(i) 的副本; i=1..7 逐档核过(G3/G3b/G3c)。空栈上的两档另记: 空栈
 *      FLD st(0) -> 0x3841(压栈方向 TOP->7, IE|SF), 空栈 **FXCH st(1) -> 0x0041**(确实报
 *      IE|SF 而 TOP 不变) —— 这一档是本次按 SDM 推"fxch 不压不弹故不报栈错"被实测推翻的。
 *   e) masked 下每类异常置哪几位 + 结果位形(ES 恒 0): 1/0 与 -1/0 -> 0x0004 + 结果 +Inf/
 *      -Inf(mant 0x8000….、se 0x7fff/0xffff; 符号 = 两操作数符号亦或); 0/0 的四种符号组合
 *      **全部**给同一个 -QNaN indefinite(c000….ffff) 且只置 IE; sqrt(负) -> 只 IE + 同一个
 *      indefinite, 而 sqrt(-0) = **-0 且无任何异常**、sqrt(-QNaN) 不置 IE 原值返回、
 *      sqrt(+dmin) -> DE|PE 结果 6.0375e-2476 = sqrt(2^-16445); FISTP 越界在 m64/m32/m16
 *      三档同形 = **只 IE(不是 OE)** + 写整数最小值, 且 2^31-0.5 / 2^15-0.5 也越界 =>
 *      先按当前 RC 舍(RNE, ties 取偶)再判界, 边界"含下不含上"(-2^31 / -2^15 在范围内);
 *      下溢三段式 = DE 跟**入值**走、UE 跟"结果下溢**且**不精确"走、PE 跟精度损失走
 *      (G7c 的 min_norm*0.5 读回 0x0000 —— 结果是非规格化而两个入值都规格化, 这一档正是
 *      把"结果非规格化就置 DE"那条错判据否掉的); FLD 一个 SNaN 置 IE、FLD 一个非规格化
 *      m80 **不**置 DE(DE 由算术指令按"操作数无效编码"置); C1(bit9) 在算术语境 = **结果被
 *      向上舍**(1/3 有、1/7 无、舍到 +Inf 有) => 实测 i 的"负侧未实测"仍不写期望, 但正侧
 *      这条已从[采集]升为可推导。
 *      另有一条**只约束读数位置、不写成期望**的机制: 同一次运算的 fnstsw 取在存回指令
 *      之前还是之后, C1 会不一样 —— G7d 的 2^16383*2 是 运算后 0x3a28 / 弹后 0x0028,
 *      实测 的 a6 同形(post-store 无 C1), 而 G7a 的 sqrt(+dmin) 是 fsqrt后 0x3822 /
 *      弹后 0x0022(那行本就没有 C1) => 存回类指令会把 C1 写掉, 机制未展开、双机一致。
 *      所以**本组内核的 sw 一律取在存回之前**(与探针 hp_bin80 的 fnstsw s1 位置同形),
 *      与 c) 的"连续溢出 C1 交替"同一处置: 不拿没解释的图案当架构承诺。
 *   f) FXAM 实测分类表: 双机逐条与公开表吻合(C3C2C0 = Unsupported 000 / NaN 001 /
 *      Normal 010 / Infinity 011 / Zero 100 / Empty 101 / Denormal 110, C1 = 符号), 三处
 *      "看着矛盾"的读数各自有解释: 用 FLD m64real 装的 double 非规格化数分类读回 **Normal**
 *      (010)且带 DE —— 加载时已规格化成 m80, DE 来自"入值非规格化"(见 e); 真 m80 非规格化
 *      入值与"整数位=1 但指数域=0"的伪非规格化都给 110; 整数位=0 而指数域正常的伪规格化给
 *      000(Unsupported); SNaN 那行的 IE 来自**加载**不是 FXAM(文档明写 FXAM 不产生异常)。
 *      => fxam_kinds 可走[解析]: 类由 m80 位形的纯整数判据算, CC 由这张表映射。
 *   g) 比较与组合: FCOM/FCOMP 内存形与 FCOMPP 三路在同一对值下 CC 一致而 TOP 分别
 *      0/7/0(b9: 相等 C3=0x4000、ST0<ST1 C0=0x0100、ST0>ST1 全 0、无序 C3C2C0=111 + IE);
 *      1 项时执行 FCOMPP -> C3C2C0=111 + IC|IE(G7e), 即"第二格按空栈读、且按无序处理"。
 *      b9 的标签是按**先入栈的 lhs**(=ST1)命名的: "gt(2 vs 1)"就是 lhs>rhs 即 ST0<ST1 即
 *      C0=1, 与新位序自洽 —— 拿它当"ST0 vs ST1"读才会读反 => 本组内核的入值一律显式写
 *      (ST0, ST1) 两个数, 不用 gt/lt 这种省略主次的名字(省掉操作数次序的名字就是下一个
 *      错读, 与"人眼不读裸位形"同源)。弹栈双目族按 AT&T `faddp/fsubp/fmulp/fdivp
 *      %%st,%%st(1)` 写出时算的是 **ST(0) op ST(1)** 且弹栈 —— 这条由 G7c/G7d 的两档
 *      **非对称**除法钉住(先入栈的是 2 与 3、后入栈的是 dmin 与 1, 读回 dmin/2 与 1/3:
 *      反向的话两档都差 10^9846 量级, 不存在撞对), 与 G6 的 FISUB=ST0-m 同读法;
 *      FSUB/FISUB/FISUBR 的方向 c1/c2 + G6 逐值核过
 *      (FISUB = ST0-m, FISUBR = m-ST0, m16/m32 都按**符号扩展**参与运算)。
 *      FSCALE 两件事按实测钉: ① ST1 取整方向是**向零截断**不是 floor(n=-2.5 -> 2^-2、
 *      n=-0.5 -> 2^0; 而 n=+1.5 -> 2^1 又排除"按 RC 舍", 因为默认 RNE 会把 1.5 舍成 2);
 *      ② **不弹栈** —— fscale 之后 fnstsw 恒为 0x3000(TOP=6 = 两项), 再两次 fstpt 读到的是
 *      结果与原 ST1 两个实值且 sw 全程无 IE|SF; 这与文档里 FSCALE 结尾那句 FPOP ST(1)
 *      相反, 两台真机一致。②是阶段二 LATX 的重点对照项, 因为它是"照文档实现反而与真机
 *      不一致"的形状, 归因时必须按本条写(不预先判 LATX 违约)。
 *   h) 四条**撤回/订正**(写在这里, 免得后人以为下面的口径是随手改的):
 *      ① 早期设计的位序"TOP=bits 8-10、C1=bit11、C0/C2/C3=bits 12-14"错, 真序见实测 a)
 *        (本文件上面的 a) 条); 探针打印器把两种读法并排打(TOP11_13 与 TOP8_10), 后者在有
 *        CC 位的行里读出垃圾(0x3a41 -> TOP8_10=2), 这张自证表在 实测记录 每行里。
 *      ② 早期设计 fdiv_zero_ze 的"ES=1"在 0x037f 全屏蔽路径上取不到(见 a)), 改成断言
 *        ZE=1 + 结果 ±Inf 位形 + ES 恒 0; fnclex_clears 的"清全部 Px 与 ES"按 b) 限定。
 *      ③ 早期设计 fninit_defaults 的"SW=0x4020"不成立: finit 与 fninit 之后都是
 *        **cw=0x037f / sw=0x0000 / tag=0xffff**(b1/b11 双机同值)。
 *      ④ 撤回上一轮据"读错的 c1/c2"开的两条计划偏差(DE 族 AT&T 名字与方向相反、C 节不可
 *        作期望来源)与第三条(±Inf 被写成 indefinite) —— 成因是把 80 位的**显式整数位**按
 *        double 的隐含整数位读了, 原始记录在 校验探针 头注, 重推后 c1/c2/c3 与
 *        (b-a, a-b, a-b, b-a) 逐行吻合。早期设计给 P7 的 FSCALE 划"采集 golden", 现按
 *        g) ① 改走[解析](这是**收紧**不是放宽: 采集值仍填表, 审计端多一条独立断言)。
 *
 * 实测编码表(gas -m32 逐条汇编 + objdump, 见 校验脚本; 十六进制为
 *   操作码/modrm.reg, 全部 mod=00 内存形):
 *     filds DF/0  fildl DB/0  fildll DF/5(=fildq 别名)   fists DF/2  fistl DB/2
 *     fistps/fistp DF/3  fistpl DB/3  fistpll DF/7      fisttps DF/1
 *     fisttpl DB/1 fisttpll DD/1  fldt DB/5  fstpt DB/7  fbld DF/4  fbstp DF/6
 *     被 as 拒: fistll / fbstkp / fisubrll / fildw
 *
 * 内核纪律(与原 special 第 6 节同源 —— 那一节已整体迁入本文件, 此处是唯一副本;
 *   逐条都有实测理由):
 *   - 每个内核/探针入口 X87_BEGIN()(finit): 不把栈深指望在"上一个内核进出平衡"
 *     上, 顺带把控制字钉回 0x037f(PC=64 位扩展档) —— 否则 PC 跟着 libc 起值飘。
 *   - 操作数槽一律文件作用域数组(g_f/g_cw/g_sw/g_t/g_bcd), 不用栈上自动变量:
 *     IB_SETF/IB_GETF 的 push 写的是 [rsp-8], -O2 叶子函数里 GCC 会把按地址逃逸
 *     的局部量放红区, 实测被踩成 0(special 的 x87_fcw_rt 第一代表就是全 0)。
 *   - 期望位形全部用整数算式算(ext_form/dbl_rt), 不在 C 里写浮点表达式: i386 默认
 *     -mfpmath=387, 一旦让 C 的浮点参与, 编译器会在我们种栈与还栈之间插它自己的
 *     fld/fstp, 栈深不再可控(唯一的例外是 qbits() 里那个 <=24 位整数的精确转换)。
 *   - 窄宽度(m16/m32)的入值口径: **取 XVEC 对应的高位段再按该宽度做符号扩展**
 *     (xw() 取 bit48-63, xd() 取 bit32-63), 不取低 W 位 —— 低 16/32 位全是哈希
 *     噪声的小值, 既无高有效位也不碰边界; 取高位段则天然覆盖 0x7fff/INT16_MIN 与
 *     0x7fffffff/INT32_MIN 这两对边界(实测c/3b 的入值就是它)。
 *   - 标志口径: x87 整型搬运族按架构**全不碰 EFLAGS** => 断言是 outf == inf & ~2。
 *     不是字面的 outf == inf: inf 由 IB_FV() 生成、被强制置了 bit1(架构保留位恒 1),
 *     而 outf 过的是 IB_FLG_MASK = 0x8d5(不含 bit1) —— 两者只差这一位(special 旧表
 *     同形: fcw_rt 的 inf=0x16 / outf=0x14)。这条抓的正是"把 x87 降级成 SSE/整型
 *     模拟时顺手踩了标志": 除 bit1 外任一位不等即为本组违约。
 */

#include "ib_core.h"
#include "ib_buf.h"
#include "isb_x87_kat.h"
#include "isb_x87.h"

/* 编译期硬拦: 本组只允许 i386(理由与实测实测见文件头「为什么只在 i386 注册」)。
 * 为什么不写成运行期判断就够: 实测 x86_64 下这份源编得动、跑得通、还全绿, 任何
 * 下游对账都看不出它测的是不存在的路径 —— 只有编译器能把它挡在门外。
 * (gcc -m32 与 i686-w64-mingw32-gcc 都定义 __i386__; x86_64 两种形态不定义) */
#if !defined(__i386__)
#error "isb_x87.c 只在 i386 编译: x86_64 的 psABI 用 SSE2 做浮点, 不发射 x87 整型搬运, 该探针在 x86_64 上测的是不存在的路径(误登记还全绿, 见文件头说明)"
#endif

/* ---------------- 入值向量(全部高有效位, 不靠哈希推: 哈希推不出 >=2^53 的
 * 可控边界值, 而本组的看点恰好是位 53..63 有没有被舍掉) ----------------
 * XVEC: 64 位整型搬运的主向量。逐位为什么是这 8 个:
 *   [0] 2^53        double 能精确表示的最大连续整数下界(缺陷分界线的左端点)
 *   [1] 2^53 + 1    第一个 double 表示不了的整数 => 只要走 double 就必丢
 *   [2] 0x37a64339803cdc21  一般性高有效位正数(≈4.0e18)
 *   [3] 0x7fffffffffffffff  INT64_MAX(左规后需要 63 位有效位)
 *   [4] 0xcbf29ce484222325  FNV-1a 的偏移基数, 即上层症状里真正被搬运的那个值
 *   [5] 0xffffffffffffffff  -1(负侧最"密"的值: 64 位全 1)
 *   [6] 0x8000000000000000  INT64_MIN(负侧极值, 且是 2 的幂 -> 走 double 精确,
 *                            所以它专门用来抓"按无符号比较判量程"的翻译错误)
 *   [7] 0x123456789abcdef1  低 4 位非 0 的高有效位数(抓"先按 16 对齐再转"这类)
 */
const uint64_t XVEC[IB_KAT_N] = {
    0x0020000000000000ULL, 0x0020000000000001ULL,
    0x37a64339803cdc21ULL, 0x7fffffffffffffffULL,
    0xcbf29ce484222325ULL, 0xffffffffffffffffULL,
    0x8000000000000000ULL, 0x123456789abcdef1ULL
};
/* BVEC: FBLD 的入值(取绝对值使用, 符号由 kk&4 定)。FBLD 只有 18 位十进制量程
 * (实测f), 所以全部 < 1e18; 里面既有 >=2^53 的(6 个)也留一个 <2^53 的对照。 */
const uint64_t BVEC[IB_KAT_N] = {
    0x0020000000000001ULL, 0x0020000000000000ULL,
    0x0de0b6b3a763ffffULL, 0x0de0b6b3a763fffeULL,
    0x0003ffffffffffffULL, 0x0003000000000001ULL,
    0x07a64339803cdc21ULL, 0x00aaaaaaaaaaaaabULL
};
/* IVEC: 喂给 FISTP m64int 的 double 位形, 8 个全在 int64 量程**之外** ->
 * 期望恒为 integer indefinite(SDM) + IE。含 2^63(刚好越界一格)、-(2^63+2)、
 * 2^64、+Inf/-Inf、QNaN、SNaN。 */
const uint64_t IVEC[IB_KAT_N] = {
    0x43e0000000000000ULL, 0x43e0000000000001ULL,
    0x43f0000000000000ULL, 0xc3e0000000000001ULL,
    0x7ff0000000000000ULL, 0xfff0000000000000ULL,
    0x7ff8000000000000ULL, 0x7ff4000000000001ULL
};

/* 窄宽度入值: 取操作数宽度对应的高位段 + 该宽度的符号扩展(理由见文件头) */
/* ---------------- 操作数缓冲(全静态, 见文件头"内核纪律") ---------------- */


uint64_t g_f[16] __attribute__((aligned(64)));   /* 8 字节槽: 源 0-7 / 目的 8-15 */

uint16_t g_cw[8];                                /* 控制字槽 */

uint16_t g_sw[8];                                /* 状态字回读槽 */

uint16_t g_env[32] __attribute__((aligned(16))); /* fnstenv/fnsave 环境槽: 按 16 位

 * 索引 cw@0 sw@2 tw@4 = 字节偏移 0/4/8(32 位模式的 28 字节布局, 实测 的 b13 核过) */
xb80 g_t[8] __attribute__((aligned(16)));        /* m80real 槽 */

unsigned char g_bcd[16] __attribute__((aligned(16))); /* packed BCD 槽(0-9) */

uint64_t xq(int kk)
{
    return XVEC[kk];
}

uint64_t xd(int kk)
{
    return (uint64_t)(int64_t)(int32_t)(uint32_t)(XVEC[kk] >> 32);
}

uint64_t xw(int kk)
{
    return (uint64_t)(int64_t)(int16_t)(uint16_t)(XVEC[kk] >> 48);
}


/* 按位形把值填进第 idx 个 8 字节槽并返回其地址。noinline 有两个用处: 让探针非叶子
 * (pushf/popf 不落红区), 以及保证「填槽」不会被搬到种栈之后。 */
__attribute__((noinline)) void *fput(int idx, uint64_t bits)
{
    g_f[idx] = bits;
    return &g_f[idx];
}

uint64_t fget(int idx)
{
    return *(volatile uint64_t *)&g_f[idx];
}

/* 状态字按槽取: P5/P6/P7 的一条序列里常常要同时留三个读数(运算前/运算后/弹栈后),
 * 而实测 e) 要求所有 sw 读数都必须落在存回之前 —— 一个槽装不下这种形状。 */
uint16_t swgetn(int idx)
{
    return *(volatile uint16_t *)&g_sw[idx];
}

uint16_t swget(void)
{
    return swgetn(0);
}

/* fnstenv/fnsave 回读: 与 swget() 同口径(volatile, 不让编译器把 asm 写进全局槽的值
 * 当可折叠常数)。P5 的 ffree_tag 与 P7 的 fninit_defaults 要的是 tag 字 —— 它不在
 * 状态字里, 只能从环境块取(实测 的 b13: 环境头三字段就是 cw/sw/tw)。 */
uint16_t envget16(int idx)
{
    return *(volatile uint16_t *)&g_env[idx];
}

/* 控制字回读: 与 swget() 同口径(经 volatile 读, 不让编译器把 asm 写进全局槽的值
 * 当成可折叠的常数)。P2 的 rc_fstcw_rt 要在**两段 asm 之间**改控制字, 必须读它。 */
uint16_t cwget(int idx)
{
    return *(volatile uint16_t *)&g_cw[idx];
}

__attribute__((noinline)) void *tput80(int idx, uint64_t mant, uint16_t se)
{
    g_t[idx].mant = mant;
    g_t[idx].se = se;
    return &g_t[idx];
}

uint64_t tget_m(int idx)
{
    return *(volatile uint64_t *)&g_t[idx].mant;
}

uint16_t tget_s(int idx)
{
    return *(volatile uint16_t *)&g_t[idx].se;
}

/* 18 位十进制 -> packed BCD 9 字节(低位在前, 每字节低半字节=低位数字) + 第 10
 * 字节 bit7 负号(实测f 实测布局)。入值已由 BVEC 限定 < 1e18, 不校验截断。 */
__attribute__((noinline)) unsigned char *bput(uint64_t v, int neg)
{
    int i;
    uint64_t x = v;

    for (i = 0; i < 9; i++) {
        unsigned lo = (unsigned)(x % 10u);
        unsigned hi;

        x /= 10u;
        hi = (unsigned)(x % 10u);
        x /= 10u;
        g_bcd[i] = (unsigned char)((hi << 4) | lo);
    }
    g_bcd[9] = (unsigned char)(neg ? 0x80 : 0x00);
    g_bcd[10] = 0;                      /* 万一有人多读: 保持确定性 */
    return g_bcd;
}


/* 80 位是**左规**格式: 整数部分(显式整数位)恒为 1, 尾数 = |v| << (63-位长+1),
 * 指数 = 16383 + 位长 - 1。所以「FILD 是否无损」不能拿低 8 字节与入值直接比,
 * 必须先按这个式子算出期望尾数/指数 —— 若装载被按 double(53 位)舍过, 舍入痕迹
 * 会落在尾数低位上, 与这里的期望值不等。这就是判 LATX 违约的比对式。
 * (与 校验探针 里已被两台机器验过的 ext_expect() 同式) */
void ext_form(uint64_t v, uint64_t *mant, uint16_t *se)
{
    uint64_t u;
    unsigned sign = 0;
    int hi;

    if ((int64_t)v < 0) {
        sign = 1;
        u = (uint64_t)0 - v;            /* -2^63 -> 2^63, 无符号回绕故无 UB */
    } else {
        u = v;
    }
    if (u == 0) {
        *mant = 0;
        *se = (uint16_t)(sign ? 0x8000u : 0u);
        return;
    }
    for (hi = 63; hi > 0; hi--)
        if ((u >> hi) & 1ULL)
            break;
    *mant = u << (63 - hi);
    *se = (uint16_t)((sign << 15) | (unsigned)(hi + 16383));
}


/* q/4 的 double 位形(与 qbits() 同式, 差别只在**先按有符号**转 double): 指数域减 2
 * = 除 4。不能拿 qbits((uint64_t)q) 走捷径 —— 负数被当成 64 位无符号数转出去就是
 * 1.8e19 那一档, 整行输入静默变形(本函数的存在理由就是把这条堵住)。 */
uint64_t q4bits(int32_t q)
{
    union { double d; uint64_t u; } t;

    t.d = (double)q;
    return t.u - (2ULL << 52);
}


/* 四档共用的取值内核。stem 是**入参字串**而不是宏粘token: IB_KFL() 里的
 * ib_strhash() 是运行期哈希(见 ib.h 的 #define IB_KFL), 所以一个核心能接四个词干;
 * 而下面 RC_ARM() 用 #sn 把词干串与函数名从**同一个 token** 推出来 —— 两者合起来,
 * "函数名与真值表宏后缀不同源"这个整组都在防的抄错形状结构上不可能出现。 */
void rc_fistp_core(int kk, unsigned enc, const char *stem, ib_kv *g)
{
    X87_BEGIN();
    uint64_t bits = q4bits(RVQ[kk]);
    const void *s = fput(0, bits);
    void *d64 = fput(8, IB_POISON);
    void *d32 = fput(9, IB_POISON);
    uintptr_t fv = (uintptr_t)IB_KFL(stem, kk), fl = 0;

    g_cw[0] = RC_CW(enc);
    __asm__ volatile(IB_SETF
                     "fldcw (%[cw])\n\t"
                     "fldl (%[s])\n\t"
                     "fistpll (%[d0])\n\t"
                     "fldl (%[s])\n\t"
                     "fistpl (%[d1])\n\t"
                     IB_GETF
                     : [fl] "=&r"(fl)
                     : [cw] "r"(&g_cw[0]), [s] "r"(s), [d0] "r"(d64),
                       [d1] "r"(d32), [fv] "r"(fv)
                     : "cc", "memory");
    g->i0 = bits;   g->i1 = enc;   g->inf = fv;
    g->o0 = (uint64_t)(int64_t)fget(8);                      /* m64int 存回 */
    g->o1 = (uint64_t)(int64_t)(int32_t)(uint32_t)fget(9);    /* m32int 存回(低 4 字节) */
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}


uint64_t rc_fistp_tp_core(ib_uw iters, unsigned enc)
{
    X87_BEGIN();
    ib_uw i;
    const void *s = fput(0, q4bits(RVQ[0]));
    void *d64 = fput(8, IB_POISON);
    void *d32 = fput(9, IB_POISON);

    /* fldcw 只在循环外一次: RC 是状态而不是操作数, 循环体里重复设它会把"两条
     * 指令的相对代价"混进定时长。循环体自身进出平衡(fld 一次、两次存回各弹一次)。 */
    g_cw[0] = RC_CW(enc);
    __asm__ volatile("fldcw (%[cw])" : : [cw] "r"(&g_cw[0]) : "memory");
    for (i = 0; i < iters; i++)
        __asm__ volatile("fldl (%[s])\n\tfistpll (%[d0])\n\t"
                         "fldl (%[s])\n\tfistpl (%[d1])"
                         : : [s] "r"(s), [d0] "r"(d64), [d1] "r"(d32) : "memory");
    return fget(8) ^ fget(9);
}


void pc_fadd_core(int kk, unsigned enc, const char *stem, ib_kv *g)
{
    X87_BEGIN();
    const void *a = fput(0, FAVEC[kk]);
    const void *b = fput(1, FBVEC[kk]);
    uintptr_t fv = (uintptr_t)IB_KFL(stem, kk), fl = 0;

    g_cw[0] = PC_CW(enc);
    __asm__ volatile(IB_SETF
                     "fldcw (%[cw])\n\t"
                     "fldl (%[a])\n\t"
                     "faddl (%[b])\n\t"
                     "fstpt (%[t])\n\t"
                     IB_GETF
                     : [fl] "=&r"(fl)
                     : [cw] "r"(&g_cw[0]), [a] "r"(a), [b] "r"(b),
                       [t] "r"(&g_t[0]), [fv] "r"(fv)
                     : "cc", "memory");
    /* 控制字回读单独一条 asm: 六个 "r" 输入 + 一个 early-clobber 输出在 -m32 下
     * 要同时占满 7 个通用寄存器(实测报 impossible constraints), 而这一条与上面
     * 两条 asm 之间**没有任何 C 语句也没有调用** -> 中间没人能改控制字, "设进去的
     * 原样读回"与写在同一个 asm 里等价。 */
    __asm__ volatile("fnstcw (%[rb])" : : [rb] "r"(&g_cw[2]) : "memory");
    g->i0 = FAVEC[kk];   g->i1 = FBVEC[kk];   g->inf = fv;
    g->o0 = tget_m(0);
    g->o1 = (uint64_t)tget_s(0) | ((uint64_t)cwget(2) << 16);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}


/* 乘法一条换的是助记符与操作数向量(两侧同值), 档位仍只有 enc 一个自变量;
 * 与加法侧同形, 所以两个 core 签名一致、能接同一个 PC_ARM 包裹宏。
 * 两侧同值就**只用一个内存槽**(fldl/fmull 读同一地址), 与 pc_fmul_tp 同形。
 *   写成两个槽时会踩 i386 的寄存器墙: 6 个 "r" 输入 + 1 个 early-clobber 输出要
 *   同时在册 = 恰好吃满 7 个通用寄存器, 再加本函数的 g 指针就"impossible
 *   constraints"(实测 gcc -m32 在 fmull 那条报 asm operand has impossible
 *   constraints)。少一个输入不是省事, 是唯一符合事实的写法: 这里没有第二个操作数。 */
void pc_fmul_core(int kk, unsigned enc, const char *stem, ib_kv *g)
{
    X87_BEGIN();
    const void *a = fput(0, FMVEC[kk]);
    uintptr_t fv = (uintptr_t)IB_KFL(stem, kk), fl = 0;

    g_cw[0] = PC_CW(enc);
    __asm__ volatile(IB_SETF
                     "fldcw (%[cw])\n\t"
                     "fldl (%[a])\n\t"
                     "fmull (%[a])\n\t"
                     "fstpt (%[t])\n\t"
                     IB_GETF
                     : [fl] "=&r"(fl)
                     : [cw] "r"(&g_cw[0]), [a] "r"(a),
                       [t] "r"(&g_t[0]), [fv] "r"(fv)
                     : "cc", "memory");
    /* 回读单独一条 asm, 理由与 pc_fadd_core 里那条完全相同 */
    __asm__ volatile("fnstcw (%[rb])" : : [rb] "r"(&g_cw[2]) : "memory");
    g->i0 = FMVEC[kk];   g->i1 = FMVEC[kk];   g->inf = fv;
    g->o0 = tget_m(0);
    g->o1 = (uint64_t)tget_s(0) | ((uint64_t)cwget(2) << 16);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}


/* 定时长体与取值体的差别只在"循环里重复那三条": fldcw 落在循环外(同 RC 一侧的
 * 理由), 不种异常(finit 已把挂起异常清零, 本组入值不溢出不除零)。 */
uint64_t pc_fadd_tp(ib_uw iters, unsigned enc)
{
    X87_BEGIN();
    ib_uw i;
    const void *a = fput(0, FAVEC[0]);
    const void *b = fput(1, FBVEC[0]);
    void *t = &g_t[0];

    g_cw[0] = PC_CW(enc);
    __asm__ volatile("fldcw (%[cw])" : : [cw] "r"(&g_cw[0]) : "memory");
    for (i = 0; i < iters; i++)
        __asm__ volatile("fldl (%[a])\n\tfaddl (%[b])\n\tfstpt (%[t])"
                         : : [a] "r"(a), [b] "r"(b), [t] "r"(t) : "memory");
    return tget_m(0) ^ (uint64_t)tget_s(0);
}


uint64_t pc_fmul_tp(ib_uw iters, unsigned enc)
{
    X87_BEGIN();
    ib_uw i;
    const void *a = fput(0, FMVEC[0]);
    void *t = &g_t[0];

    g_cw[0] = PC_CW(enc);
    __asm__ volatile("fldcw (%[cw])" : : [cw] "r"(&g_cw[0]) : "memory");
    for (i = 0; i < iters; i++)
        __asm__ volatile("fldl (%[a])\n\tfmull (%[a])\n\tfstpt (%[t])"
                         : : [a] "r"(a), [t] "r"(t) : "memory");
    return tget_m(0) ^ (uint64_t)tget_s(0);
}


/* =====================================================================
 * 4) 自 special 迁入的 6 条(原名、原词干、原内核写法逐字搬, 只把缓冲与
 *    X87_BEGIN 换成本文件的): fld+fstp 对 / fadd / fmul / fistp / fcomip /
 *    控制字往返。迁入理由见文件头: special 原口径的入值是 n/4(<=24 位, 刻意保证
 *    double 也能精确表示), 它测的是 x87 的**功能通路**(软浮点的算术、标志、控制
 *    字), 与 P1 测的**整型搬运精度**是两条独立的翻译路径, 但同属 x87 组 -> 归并
 *    到本文件后, "x87 只注册 i386" 这条 ISA 约束只需在一个地方登记。
 *    本节的验证通道(六条全有 C 侧对应物 —— 编译器天天在发这六条):
 *      fcomip   -> x87 位序校验探针 的 G2 八行。反汇编坐实 cc_after 发的就是
 *                  fcomip/fucomip + seta —— 它同时是 P7 那条"比较结果只进 EFLAGS、
 *                  不在状态字里留 CC"的唯一证据行, 两条内核共用一次归因。
 *      fcw_rt   -> x87 位段校验探针 的 H2 行末 cwTC 列(glibc 的 __fesetround 体内
 *                  就是一次 fnstcw + 一次 fldcw, 与内核那对同形)。
 *      fld_fstp -> 探针里每一次 `volatile double` 的赋值与读回(p1chk D1、A4 的 viaD,
 *                  p7chk 的 d2m80_asloaded) 都是 fldl + fstpl。
 *      fistp_m64-> p1chk A1(直接强转) 与 E1(glibc __llrint 体内一条裸 fistpll)。
 *      fadd_m64 / fmul_m64 -> 半锚: p7chk B/F 节的链式 double 算术、p1chk H2 的
 *                  `(long double)q / 4.0L`(编译器把它编成 fmuls, 见反汇编)。注意那些
 *                  是 **m32real 宽度形**(fadds/fmuls), 与内核的 faddl/fmull 只差操作数
 *                  宽度 —— 宽度本身的影响归 o1 的写宽断言管, 不拿半锚当全锚。
 *    入值口径两套并存且**不许互相统一**: 本节继续用 n/4(算术结果在 double 与
 *    80 位里都精确 -> 「参考机按 64 位存、目标机软浮点按 80 位算」污染不到表),
 *    P1 用高有效位向量(要的正是两者不等)。分母是 4 -> 小数部分只有 .00/.25/
 *    .50/.75 四种, 四种舍入情形在 8 组入值里都会被采到, 正好卡住 fistp 的舍入
 *    路径。位形用整数算(qbits(): 指数域减 2), 全程不走 C 的浮点运算。
 * ===================================================================== */
/* n/4 的分子(24 位)与它的 double 位形。qbits(): 整数转 double(24 位内精确)
 * 后指数域减 2 即除 4; 唯一的 C 浮点运算是那个整数->浮点转换, 且整个函数
 * 自平衡, 不会把 x87 栈留在半途。
 * 强制低位为 1: 担心的是 n == 0 —— qbits(0) 算出来是 0xffe0000000000000 而非
 * 0x0(对 0.0 的位形做"指数域减 2"本就得到 NaN), 而 NaN 进 FIST 是 invalid
 * operation、进 fadd/fmul 是安静 NaN 传递, 两者的结果位形在不同 CPU 上不必相同 ——
 * 一个靠哈希推入值的口径不能把宝押在"实测没抽到 0"上。 */
uint64_t x87n(const char *sn, int kk, int slot)
{
    return (IB_KIN8(sn, kk, slot, uint32_t) & 0xffffffu) | 1u;
}

uint64_t qbits(uint64_t n)
{
    union { double d; uint64_t u; } t;

    t.d = (double)n;
    return t.u - (2ULL << 52);
}

uint64_t qv(const char *sn, int kk, int slot)
{
    return qbits(x87n(sn, kk, slot));
}


/* P8 精度边界用例的 8 组尾数扰动(口径见 isb_x87.h 的常量注):
 *   两档共享同一高位(位 63..11): bit63 整数位恒 1, bits62..11 由哈希每 kk 翻若干
 *   位(变化量左移到 bit11 起, 不碰 bit63 与低 11 位) -> 8 组各不同但仍 double 可容;
 *   低 11 位 = 两档唯一分界: f64 置 0(卡 double 53 位上界, 对照组)、f80 置 1(满 64
 *   位, 超 double)。同一 kk 下两档严格只差 0x7FF 这 11 位, 把精度变量隔离到最小。 */
uint64_t op_mant(const char *stem, int kk, uint64_t base)
{
    char seed[24];
    size_t n = strlen(stem);
    uint64_t hi, shared;

    if (n > 4)
        n -= 4;                 /* 去掉 "_f64"/"_f80" 后缀 -> 两档哈希同一前缀, 高位完全相同 */
    if (n >= sizeof seed)
        n = sizeof seed - 1;
    memcpy(seed, stem, n);
    seed[n] = '\0';

    hi = (uint64_t)(IB_KIN8(seed, kk, 0, uint32_t) & 0x3FFFFFu) << 11;
    shared = (MANT_F64 ^ hi) & ~0x7FFULL;   /* 两档同源的高位(低 11 位清 0) */

    if (base == MANT_F64)
        return shared;            /* f64: 低 11 位 = 0 -> double 精确(卡 53 位) */
    return shared | 0x7FFULL;     /* f80: 低 11 位 = 1 -> 满 64 位, 超 double */
}


/* P8 的 13 行入值表(lat/tp/kat 三处共用, 注释里的区间值可逐位反验:
 * X1|M80_E(0)=1.0、M80_1PN(1)|M80_E(0)=1.5、X1|M80_E(-1)=0.5、
 * M80_1PN(1)|M80_E(1)=3 不在表里 —— 副操作数全取 2 的幂或 1.5, double 精确)。 */
const struct ib_opinfo g_opinfo[OPINFO_N] = {
    /* stem      ise  smant(D=缺哨兵 1.0)  sse          dual drain */
    { "fsin",     0,   X1,                 M80_E(0),     0,   1    },  /* [1,2) */
    { "fcos",     0,   X1,                 M80_E(0),     0,   1    },
    { "fsqrt",    0,   X1,                 M80_E(0),     0,   1    },  /* 正数, 避开 fsqrt_neg_ie */
    { "f2xm1",   -1,   X1,                 M80_E(0),     0,   1    },  /* [0.5,1) */
    { "fsincos",  0,   X1,                 M80_E(0),     0,   2    },  /* ST0=sin ST1=cos */
    { "fptan",   -2,   X1,                 M80_E(0),     0,   2    },  /* 小角: 角在 ST1=smant(边界槽),
                                                                          * 主槽只是哨兵 1.0, tan 在倒数第二次 fstpt 读 */
    { "fpatan",   0,   X1,                 M80_E(0),     1,   1    },  /* 弹栈类 */
    { "fyl2x",    0,   X1,                 M80_E(0),     1,   1    },
    { "fyl2xp1", -10,  X1,                 M80_E(0),     1,   1    },  /* x~1e-3 */
    { "fprem",    2,   X1,                 M80_E(-1),    1,   2    },  /* [4,8) % 0.5 */
    { "fprem1",   2,   X1,                 M80_E(-1),    1,   2    },
    { "fdiv",     2,   M80_1PN(1),         M80_E(0),     1,   2    },  /* [4,8)/1.5 */
    { "fdivr",    2,   M80_1PN(1),         M80_E(0),     1,   2    },
};


__attribute__((noinline)) void x87_bin80_core(int kk, const struct xbop *t,
                                                    const char *stem, ib_kv *g)
{
    X87_BEGIN();
    const struct xbop *e = &t[kk];
    const void *pr = tput80(0, XBOP[e->ri].mant, XBOP[e->ri].se);   /* 先入栈 -> ST(1) */
    const void *pl = tput80(1, XBOP[e->li].mant, XBOP[e->li].se);   /* 后入栈 -> ST(0) */
    uintptr_t fv = (uintptr_t)IB_KFL(stem, kk), fl = 0;

    tput80(2, IB_POISON, IB_POISON >> 48);       /* 结果槽哨兵 */
    switch (e->op) {
    case XB_ADD:
        XB_ACT("faddp %%st,%%st(1)\n\t");
        break;
    case XB_MUL:
        XB_ACT("fmulp %%st,%%st(1)\n\t");
        break;
    case XB_DIV:
        XB_ACT("fdivp %%st,%%st(1)\n\t");
        break;
    default:
        break;                                  /* op 写错时一个 asm 都不发 -> 结果槽留哨兵 */
    }
    __asm__ volatile("fstpt (%[t])" : : [t] "r"(&g_t[2]) : "memory");
    g->i0 = XBOP[e->li].mant;   g->i1 = XBOP[e->ri].mant;   g->inf = fv;
    g->o0 = tget_m(2);
    g->o1 = (uint64_t)tget_s(2) | ((uint64_t)swget() << 16);
    g->outf = (uint64_t)fl & IB_FLG_MASK;
}


/* 定时长体与取值体同形(两条指令一进一出, 栈深每圈回到 finit 后的 0) */
uint64_t x87_bin80_tp(ib_uw iters, const struct xbop *t)
{
    X87_BEGIN();
    ib_uw i;
    const struct xbop *e = &t[0];
    const void *pr = tput80(0, XBOP[e->ri].mant, XBOP[e->ri].se);
    const void *pl = tput80(1, XBOP[e->li].mant, XBOP[e->li].se);
    void *rt = &g_t[2];

    for (i = 0; i < iters; i++) {
        switch (e->op) {
        case XB_ADD:
            __asm__ volatile("fldt (%[rh])\n\tfldt (%[lh])\n\tfaddp %%st,%%st(1)\n\tfstpt (%[t])"
                             : : [rh] "r"(pr), [lh] "r"(pl), [t] "r"(rt) : "memory");
            break;
        case XB_MUL:
            __asm__ volatile("fldt (%[rh])\n\tfldt (%[lh])\n\tfmulp %%st,%%st(1)\n\tfstpt (%[t])"
                             : : [rh] "r"(pr), [lh] "r"(pl), [t] "r"(rt) : "memory");
            break;
        case XB_DIV:
            __asm__ volatile("fldt (%[rh])\n\tfldt (%[lh])\n\tfdivp %%st,%%st(1)\n\tfstpt (%[t])"
                             : : [rh] "r"(pr), [lh] "r"(pl), [t] "r"(rt) : "memory");
            break;
        default:
            break;
        }
    }
    return tget_m(2) ^ (uint64_t)tget_s(2);
}


/* 把 FPU 打进八种**已知脏态**的生成序列 —— fstsw_allbits 与 fninit_defaults 共用一个
 * helper, 于是"同一状态下三种读法同字"与"同一状态下 fninit 后全归零"量的是同一批状态;
 * 抄两遍就是两条会互相漂移的期望。每档后面那十六进制是**本档期望的完整 sw**,
 * 都能对回实测 c)/d)/e)/g) 里具体哪一行(与 fnclex_clears 的 switch 同形, 差别只两处:
 * 这里第 2 档换成`fldl D_DMIN`把 DE 取进来(DE 被 IB_FLG_MASK 挡在 outf 之外、只在状态
 * 字里看得见), 第 3 档额外 `fldcw PC_CW(0)` 把控制字也弄脏(只挂在这一档上: 两条各只
 * 8 档, 而"fninit 连 PC 一起还原"没别的档能证)。 */
void x87_dirty(int kk)
{
    switch (kk) {
    case 0:                                             /* 1/0 -> ZE + TOP7 = 0x3804 */
        fput(0, D_ONE); fput(1, 0);
        __asm__ volatile("fldl (%[a])\n\tfdivl (%[b])"
                         : : [a] "r"(&g_f[0]), [b] "r"(&g_f[1]) : "memory");
        break;
    case 1:                                             /* sqrt(-1) -> IE + TOP7 = 0x3801 */
        fput(0, D_ONE | D_NEG);
        __asm__ volatile("fldl (%[a])\n\tfsqrt" : : [a] "r"(&g_f[0]) : "memory");
        break;
    case 2:                                             /* 装载非规格化 double -> DE = 0x3802 */
        fput(0, D_DMIN);
        __asm__ volatile("fldl (%[a])" : : [a] "r"(&g_f[0]) : "memory");
        break;
    case 3: {                                           /* PC 换档 + 第 9 次压栈 = 0x3a41 */
        int j;

        *(volatile uint16_t *)&g_cw[3] = PC_CW(0u);      /* 24 位档(0x007f), 保留位照文档写 */
        __asm__ volatile("fldcw (%[c])" : : [c] "r"(&g_cw[3]) : "memory");
        for (j = 0; j < 9; j++)
            __asm__ volatile("fld1" : : : "memory");
        break;
    }
    case 4:                                             /* 空栈弹一格 -> IE|SF, TOP=1 = 0x0841 */
        __asm__ volatile("fstpt (%[s])" : : [s] "r"(&g_t[5]) : "memory");
        break;
    case 5:                                             /* 空栈压栈 -> IE|SF, TOP=7 = 0x3841 */
        __asm__ volatile("fld %%st(0)" : : : "memory");
        break;
    case 6:                                             /* 空栈交换 -> IE|SF, TOP 不动 = 0x0041 */
        __asm__ volatile("fxch %%st(1)" : : : "memory");
        break;
    default:                                            /* 只有一项时 fcompp -> IE|SF|C3C2C0
                                                          * =111, TOP=1 = 0x4d41(实测 g) G7e)) */
        __asm__ volatile("fld1\n\tfcompp" : : : "memory");
        break;
    }
}

RC_ARM(rc_fistp_q_rn, 0)
RC_ARM(rc_fistp_q_rd, 1)
RC_ARM(rc_fistp_q_ru, 2)
RC_ARM(rc_fistp_q_rz, 3)


PC_ARM(pc24_fadd, 0, pc_fadd_tp, pc_fadd_core)
PC_ARM(pc53_fadd, 2, pc_fadd_tp, pc_fadd_core)
PC_ARM(pc64_fmul, 3, pc_fmul_tp, pc_fmul_core)



/* =====================================================================
 * 用例表(声明式, 一行一 case; 字段序 = ib_case)。
 * x87 族的 lat 只有 fadd/fmul 能自串 ST0 依赖链 -> 其余用通用延迟函数
 * (不依赖链, 测的是吞吐型延迟, 但比 NULL 强)
 * ===================================================================== */
static const ib_case g_cases[] = {
    /* --- P1 精度(12): 整型搬运的往返位精度, 入值全在高有效位 --- */
    { "x87_fild_fistp_q_rt", NULL, k_fild_fistp_q_rt_lat, k_fild_fistp_q_rt_tp, 0, NULL, 0, NULL, 0,
      k_fild_fistp_q_rt_kat, IB_KAT_fild_fistp_q_rt, "fild_fistp_q_rt" },
    { "x87_fild_fistp_d_rt", NULL, k_fild_fistp_d_rt_lat, k_fild_fistp_d_rt_tp, 0, NULL, 0, NULL, 0,
      k_fild_fistp_d_rt_kat, IB_KAT_fild_fistp_d_rt, "fild_fistp_d_rt" },
    { "x87_fild_fistp_w_rt", NULL, k_fild_fistp_w_rt_lat, k_fild_fistp_w_rt_tp, 0, NULL, 0, NULL, 0,
      k_fild_fistp_w_rt_kat, IB_KAT_fild_fistp_w_rt, "fild_fistp_w_rt" },
    { "x87_fild_fistp_q_neg", NULL, k_fild_fistp_q_neg_lat, k_fild_fistp_q_neg_tp, 0, NULL, 0, NULL, 0,
      k_fild_fistp_q_neg_kat, IB_KAT_fild_fistp_q_neg, "fild_fistp_q_neg" },
    { "x87_fild_q_odd_rt", NULL, k_fild_q_odd_rt_lat, k_fild_q_odd_rt_tp, 0, NULL, 0, NULL, 0,
      k_fild_q_odd_rt_kat, IB_KAT_fild_q_odd_rt, "fild_q_odd_rt" },
    { "x87_fild_fstp_q_dbl", NULL, k_fild_fstp_q_dbl_lat, k_fild_fstp_q_dbl_tp, 0, NULL, 0, NULL, 0,
      k_fild_fstp_q_dbl_kat, IB_KAT_fild_fstp_q_dbl, "fild_fstp_q_dbl" },
    { "x87_fild_fstp_t_ext", NULL, k_fild_fstp_t_ext_lat, k_fild_fstp_t_ext_tp, 0, NULL, 0, NULL, 0,
      k_fild_fstp_t_ext_kat, IB_KAT_fild_fstp_t_ext, "fild_fstp_t_ext" },
    { "x87_fistp_q_indef", NULL, k_fistp_q_indef_lat, k_fistp_q_indef_tp, 0, NULL, 0, NULL, 0,
      k_fistp_q_indef_kat, IB_KAT_fistp_q_indef, "fistp_q_indef" },
    { "x87_fisttp_q_rt", "sse3", k_fisttp_q_rt_lat, k_fisttp_q_rt_tp, 0, NULL, 0, NULL, 0,
      k_fisttp_q_rt_kat, IB_KAT_fisttp_q_rt, "fisttp_q_rt" },
    { "x87_fld_t_fstp_t_rt", NULL, k_fld_t_fstp_t_rt_lat, k_fld_t_fstp_t_rt_tp, 0, NULL, 0, NULL, 0,
      k_fld_t_fstp_t_rt_kat, IB_KAT_fld_t_fstp_t_rt, "fld_t_fstp_t_rt" },
    { "x87_fbld_fistp_q_rt", NULL, k_fbld_fistp_q_rt_lat, k_fbld_fistp_q_rt_tp, 0, NULL, 0, NULL, 0,
      k_fbld_fistp_q_rt_kat, IB_KAT_fbld_fistp_q_rt, "fbld_fistp_q_rt" },
    { "x87_fild_fistp_q_x8", NULL, k_fild_fistp_q_x8_lat, k_fild_fistp_q_x8_tp, 0, NULL, 0, NULL, 0,
      k_fild_fistp_q_x8_kat, IB_KAT_fild_fistp_q_x8, "fild_fistp_q_x8" },
    /* --- P2 舍入模式(5): fldcw 置 RC(位 10-11) 后的浮点->整数存回 --- */
    { "x87_rc_fistp_q_rn", NULL, k_rc_fistp_q_rn_lat, k_rc_fistp_q_rn_tp, 0, NULL, 0, NULL, 0,
      k_rc_fistp_q_rn_kat, IB_KAT_rc_fistp_q_rn, "rc_fistp_q_rn" },
    { "x87_rc_fistp_q_rd", NULL, k_rc_fistp_q_rd_lat, k_rc_fistp_q_rd_tp, 0, NULL, 0, NULL, 0,
      k_rc_fistp_q_rd_kat, IB_KAT_rc_fistp_q_rd, "rc_fistp_q_rd" },
    { "x87_rc_fistp_q_ru", NULL, k_rc_fistp_q_ru_lat, k_rc_fistp_q_ru_tp, 0, NULL, 0, NULL, 0,
      k_rc_fistp_q_ru_kat, IB_KAT_rc_fistp_q_ru, "rc_fistp_q_ru" },
    { "x87_rc_fistp_q_rz", NULL, k_rc_fistp_q_rz_lat, k_rc_fistp_q_rz_tp, 0, NULL, 0, NULL, 0,
      k_rc_fistp_q_rz_kat, IB_KAT_rc_fistp_q_rz, "rc_fistp_q_rz" },
    { "x87_rc_fstcw_rt", NULL, k_rc_fstcw_rt_lat, k_rc_fstcw_rt_tp, 0, NULL, 0, NULL, 0,
      k_rc_fstcw_rt_kat, IB_KAT_rc_fstcw_rt, "rc_fstcw_rt" },
    /* --- P3 精度控制(3): fldcw(PC, 位 8-9) 后算术再存 m80 --- */
    { "x87_pc24_fadd", NULL, k_pc24_fadd_lat, k_pc24_fadd_tp, 0, NULL, 0, NULL, 0,
      k_pc24_fadd_kat, IB_KAT_pc24_fadd, "pc24_fadd" },
    { "x87_pc53_fadd", NULL, k_pc53_fadd_lat, k_pc53_fadd_tp, 0, NULL, 0, NULL, 0,
      k_pc53_fadd_kat, IB_KAT_pc53_fadd, "pc53_fadd" },
    { "x87_pc64_fmul", NULL, k_pc64_fmul_lat, k_pc64_fmul_tp, 0, NULL, 0, NULL, 0,
      k_pc64_fmul_kat, IB_KAT_pc64_fmul, "pc64_fmul" },
    /* --- 自 special 迁入的 6 条(保持原名与原词干) --- */
    { "x87_fld_fstp", NULL, k_fld_fstp_lat, k_fld_fstp_tp, 0, NULL, 0, NULL, 0,
      k_fld_fstp_kat, IB_KAT_fld_fstp, "fld_fstp" },
    { "x87_fadd_m64", NULL, k_fadd, k_fadd_tp, 0, NULL, 0, NULL, 0,
      k_fadd_kat, IB_KAT_fadd, "fadd" },
    { "x87_fmul_m64", NULL, k_fmul, k_fmul_tp, 0, NULL, 0, NULL, 0,
      k_fmul_kat, IB_KAT_fmul, "fmul" },
    { "x87_fistp_m64", NULL, k_fistp_m64_lat, k_fistp_tp, 0, NULL, 0, NULL, 0,
      k_fistp_kat, IB_KAT_fistp, "fistp" },
    { "x87_fcomip", NULL, k_fcomip_lat, k_fcomip_tp, 0, NULL, 0, NULL, 0,
      k_fcomip_kat, IB_KAT_fcomip, "fcomip" },
    { "x87_fcw_rt", NULL, k_fcw_rt_lat, k_fcw_rt_tp, 0, NULL, 0, NULL, 0,
      k_fcw_rt_kat, IB_KAT_fcw_rt, "fcw_rt" },
    /* --- P5 栈(6): TOP 走位 / LIFO 弹序 / tag 字, 判据全在状态字与环境块 --- */
    { "x87_stack_top_after_fild", NULL, k_stack_top_after_fild_lat, k_stack_top_after_fild_tp, 0, NULL, 0, NULL, 0,
      k_stack_top_after_fild_kat, IB_KAT_stack_top_after_fild, "stack_top_after_fild" },
    { "x87_stack_fld8_st8", NULL, k_stack_fld8_st8_lat, k_stack_fld8_st8_tp, 0, NULL, 0, NULL, 0,
      k_stack_fld8_st8_kat, IB_KAT_stack_fld8_st8, "stack_fld8_st8" },
    { "x87_fxch_st3", NULL, k_fxch_st3_lat, k_fxch_st3_tp, 0, NULL, 0, NULL, 0,
      k_fxch_st3_kat, IB_KAT_fxch_st3, "fxch_st3" },
    { "x87_fldst_st1_to_st0", NULL, k_fldst_st1_to_st0_lat, k_fldst_st1_to_st0_tp, 0, NULL, 0, NULL, 0,
      k_fldst_st1_to_st0_kat, IB_KAT_fldst_st1_to_st0, "fldst_st1_to_st0" },
    { "x87_fincstp_fdecstp_rt", NULL, k_fincstp_fdecstp_rt_lat, k_fincstp_fdecstp_rt_tp, 0, NULL, 0, NULL, 0,
      k_fincstp_fdecstp_rt_kat, IB_KAT_fincstp_fdecstp_rt, "fincstp_fdecstp_rt" },
    { "x87_ffree_tag", NULL, k_ffree_tag_lat, k_ffree_tag_tp, 0, NULL, 0, NULL, 0,
      k_ffree_tag_kat, IB_KAT_ffree_tag, "ffree_tag" },
    /* --- P6 异常(7): masked 路径上每类异常置哪几位 + 同时结果是什么位形 --- */
    { "x87_fdiv_zero_ze", NULL, k_fdiv_zero_ze_lat, k_fdiv_zero_ze_tp, 0, NULL, 0, NULL, 0,
      k_fdiv_zero_ze_kat, IB_KAT_fdiv_zero_ze, "fdiv_zero_ze" },
    { "x87_fsqrt_neg_ie", NULL, k_fsqrt_neg_ie_lat, k_fsqrt_neg_ie_tp, 0, NULL, 0, NULL, 0,
      k_fsqrt_neg_ie_kat, IB_KAT_fsqrt_neg_ie, "fsqrt_neg_ie" },
    { "x87_fistp_oe", NULL, k_fistp_oe_lat, k_fistp_oe_tp, 0, NULL, 0, NULL, 0,
      k_fistp_oe_kat, IB_KAT_fistp_oe, "fistp_oe" },
    { "x87_stack_underflow_is", NULL, k_stack_underflow_is_lat, k_stack_underflow_is_tp, 0, NULL, 0, NULL, 0,
      k_stack_underflow_is_kat, IB_KAT_stack_underflow_is, "stack_underflow_is" },
    { "x87_denormal_ue", NULL, k_denormal_ue_lat, k_denormal_ue_tp, 0, NULL, 0, NULL, 0,
      k_denormal_ue_kat, IB_KAT_denormal_ue, "denormal_ue" },
    { "x87_precision_pe", NULL, k_precision_pe_lat, k_precision_pe_tp, 0, NULL, 0, NULL, 0,
      k_precision_pe_kat, IB_KAT_precision_pe, "precision_pe" },
    { "x87_fnclex_clears", NULL, k_fnclex_clears_lat, k_fnclex_clears_tp, 0, NULL, 0, NULL, 0,
      k_fnclex_clears_kat, IB_KAT_fnclex_clears, "fnclex_clears" },
    /* --- P7 特殊与组合(8): 比较码 / 方向对 / FSCALE / FXAM / 状态字全位 / fninit ---
     * 入值表与期望式全在 P7 节头与各自注里; 每行的 C 侧锚点(探针哪一节)也写在注里。 */
    { "x87_fcom_cc", NULL, k_fcom_cc_lat, k_fcom_cc_tp, 0, NULL, 0, NULL, 0,
      k_fcom_cc_kat, IB_KAT_fcom_cc, "fcom_cc" },
    { "x87_fcompp_cc", NULL, k_fcompp_cc_lat, k_fcompp_cc_tp, 0, NULL, 0, NULL, 0,
      k_fcompp_cc_kat, IB_KAT_fcompp_cc, "fcompp_cc" },
    { "x87_fsubr_pair", NULL, k_fsubr_pair_lat, k_fsubr_pair_tp, 0, NULL, 0, NULL, 0,
      k_fsubr_pair_kat, IB_KAT_fsubr_pair, "fsubr_pair" },
    { "x87_fisubr_m64", NULL, k_fisubr_m64_lat, k_fisubr_m64_tp, 0, NULL, 0, NULL, 0,
      k_fisubr_m64_kat, IB_KAT_fisubr_m64, "fisubr_m64" },
    { "x87_fscale_int", NULL, k_fscale_int_lat, k_fscale_int_tp, 0, NULL, 0, NULL, 0,
      k_fscale_int_kat, IB_KAT_fscale_int, "fscale_int" },
    { "x87_fxam_kinds", NULL, k_fxam_kinds_lat, k_fxam_kinds_tp, 0, NULL, 0, NULL, 0,
      k_fxam_kinds_kat, IB_KAT_fxam_kinds, "fxam_kinds" },
    { "x87_fstsw_allbits", NULL, k_fstsw_allbits_lat, k_fstsw_allbits_tp, 0, NULL, 0, NULL, 0,
      k_fstsw_allbits_kat, IB_KAT_fstsw_allbits, "fstsw_allbits" },
    { "x87_fninit_defaults", NULL, k_fninit_defaults_lat, k_fninit_defaults_tp, 0, NULL, 0, NULL, 0,
      k_fninit_defaults_kat, IB_KAT_fninit_defaults, "fninit_defaults" },
    /* --- P8 超越函数/除法精度边界(26): 13 指令 x {f64 对照, f80 越界} 两档尾数。
     * lits=200000: 软模拟 fsin/fprem 单条可达微秒级, 默认 200 万会把单条拉到 2s+;
     * 入值/形态表在 g_opinfo, 真值由 gen_val.sh x87 采集(未采前 IB_KV_UNSET 自动跳过)。 */
    { "x87_fsin_f64",     NULL, k_fsin_f64_lat,     k_fsin_f64_tp,     0, NULL, 0, NULL, 200000,
      k_fsin_f64_kat,     IB_KAT_fsin_f64,     "fsin_f64" },
    { "x87_fsin_f80",     NULL, k_fsin_f80_lat,     k_fsin_f80_tp,     0, NULL, 0, NULL, 200000,
      k_fsin_f80_kat,     IB_KAT_fsin_f80,     "fsin_f80" },
    { "x87_fcos_f64",     NULL, k_fcos_f64_lat,     k_fcos_f64_tp,     0, NULL, 0, NULL, 200000,
      k_fcos_f64_kat,     IB_KAT_fcos_f64,     "fcos_f64" },
    { "x87_fcos_f80",     NULL, k_fcos_f80_lat,     k_fcos_f80_tp,     0, NULL, 0, NULL, 200000,
      k_fcos_f80_kat,     IB_KAT_fcos_f80,     "fcos_f80" },
    { "x87_fsqrt_f64",    NULL, k_fsqrt_f64_lat,    k_fsqrt_f64_tp,    0, NULL, 0, NULL, 200000,
      k_fsqrt_f64_kat,    IB_KAT_fsqrt_f64,    "fsqrt_f64" },
    { "x87_fsqrt_f80",    NULL, k_fsqrt_f80_lat,    k_fsqrt_f80_tp,    0, NULL, 0, NULL, 200000,
      k_fsqrt_f80_kat,    IB_KAT_fsqrt_f80,    "fsqrt_f80" },
    { "x87_f2xm1_f64",    NULL, k_f2xm1_f64_lat,    k_f2xm1_f64_tp,    0, NULL, 0, NULL, 200000,
      k_f2xm1_f64_kat,    IB_KAT_f2xm1_f64,    "f2xm1_f64" },
    { "x87_f2xm1_f80",    NULL, k_f2xm1_f80_lat,    k_f2xm1_f80_tp,    0, NULL, 0, NULL, 200000,
      k_f2xm1_f80_kat,    IB_KAT_f2xm1_f80,    "f2xm1_f80" },
    { "x87_fsincos_f64",  NULL, k_fsincos_f64_lat,  k_fsincos_f64_tp,  0, NULL, 0, NULL, 200000,
      k_fsincos_f64_kat,  IB_KAT_fsincos_f64,  "fsincos_f64" },
    { "x87_fsincos_f80",  NULL, k_fsincos_f80_lat,  k_fsincos_f80_tp,  0, NULL, 0, NULL, 200000,
      k_fsincos_f80_kat,  IB_KAT_fsincos_f80,  "fsincos_f80" },
    { "x87_fptan_f64",    NULL, k_fptan_f64_lat,    k_fptan_f64_tp,    0, NULL, 0, NULL, 200000,
      k_fptan_f64_kat,    IB_KAT_fptan_f64,    "fptan_f64" },
    { "x87_fptan_f80",    NULL, k_fptan_f80_lat,    k_fptan_f80_tp,    0, NULL, 0, NULL, 200000,
      k_fptan_f80_kat,    IB_KAT_fptan_f80,    "fptan_f80" },
    { "x87_fpatan_f64",   NULL, k_fpatan_f64_lat,   k_fpatan_f64_tp,   0, NULL, 0, NULL, 200000,
      k_fpatan_f64_kat,   IB_KAT_fpatan_f64,   "fpatan_f64" },
    { "x87_fpatan_f80",   NULL, k_fpatan_f80_lat,   k_fpatan_f80_tp,   0, NULL, 0, NULL, 200000,
      k_fpatan_f80_kat,   IB_KAT_fpatan_f80,   "fpatan_f80" },
    { "x87_fyl2x_f64",    NULL, k_fyl2x_f64_lat,    k_fyl2x_f64_tp,    0, NULL, 0, NULL, 200000,
      k_fyl2x_f64_kat,    IB_KAT_fyl2x_f64,    "fyl2x_f64" },
    { "x87_fyl2x_f80",    NULL, k_fyl2x_f80_lat,    k_fyl2x_f80_tp,    0, NULL, 0, NULL, 200000,
      k_fyl2x_f80_kat,    IB_KAT_fyl2x_f80,    "fyl2x_f80" },
    { "x87_fyl2xp1_f64",  NULL, k_fyl2xp1_f64_lat,  k_fyl2xp1_f64_tp,  0, NULL, 0, NULL, 200000,
      k_fyl2xp1_f64_kat,  IB_KAT_fyl2xp1_f64,  "fyl2xp1_f64" },
    { "x87_fyl2xp1_f80",  NULL, k_fyl2xp1_f80_lat,  k_fyl2xp1_f80_tp,  0, NULL, 0, NULL, 200000,
      k_fyl2xp1_f80_kat,  IB_KAT_fyl2xp1_f80,  "fyl2xp1_f80" },
    { "x87_fprem_f64",    NULL, k_fprem_f64_lat,    k_fprem_f64_tp,    0, NULL, 0, NULL, 200000,
      k_fprem_f64_kat,    IB_KAT_fprem_f64,    "fprem_f64" },
    { "x87_fprem_f80",    NULL, k_fprem_f80_lat,    k_fprem_f80_tp,    0, NULL, 0, NULL, 200000,
      k_fprem_f80_kat,    IB_KAT_fprem_f80,    "fprem_f80" },
    { "x87_fprem1_f64",   NULL, k_fprem1_f64_lat,   k_fprem1_f64_tp,   0, NULL, 0, NULL, 200000,
      k_fprem1_f64_kat,   IB_KAT_fprem1_f64,   "fprem1_f64" },
    { "x87_fprem1_f80",   NULL, k_fprem1_f80_lat,   k_fprem1_f80_tp,   0, NULL, 0, NULL, 200000,
      k_fprem1_f80_kat,   IB_KAT_fprem1_f80,   "fprem1_f80" },
    { "x87_fdiv_f64",     NULL, k_fdiv_f64_lat,     k_fdiv_f64_tp,     0, NULL, 0, NULL, 200000,
      k_fdiv_f64_kat,     IB_KAT_fdiv_f64,     "fdiv_f64" },
    { "x87_fdiv_f80",     NULL, k_fdiv_f80_lat,     k_fdiv_f80_tp,     0, NULL, 0, NULL, 200000,
      k_fdiv_f80_kat,     IB_KAT_fdiv_f80,     "fdiv_f80" },
    { "x87_fdivr_f64",    NULL, k_fdivr_f64_lat,    k_fdivr_f64_tp,    0, NULL, 0, NULL, 200000,
      k_fdivr_f64_kat,    IB_KAT_fdivr_f64,    "fdivr_f64" },
    { "x87_fdivr_f80",    NULL, k_fdivr_f80_lat,    k_fdivr_f80_tp,    0, NULL, 0, NULL, 200000,
      k_fdivr_f80_kat,    IB_KAT_fdivr_f80,    "fdivr_f80" },
};
#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

int main(int argc, char **argv)
{
    volatile uint64_t *vf = g_f;
    int i;

    /* 经 volatile 指针填缓冲: 内容对编译器不可知, 不会把被测指令当常数折叠掉。
     * 16 个槽全填 1.0(合法有限值): 内核里真正的取值路径都会自己 fput/fput 毒值,
     * 这里只是保证万一有人读到空槽也不会碰上非法浮点值。 */
    for (i = 0; i < 16; i++)
        vf[i] = 0x3ff0000000000000ULL;
    ib_init(argc, argv);
    ib_hdr("x87", NCASES);
    /* 不回传 ib_run_cases 的返回值: 它返回的是「全绿用例数」, 而 isbench.py 与
     * gen_val.sh 都按 rc!=0 判整组失败并丢弃输出。口径与其余各组一致 —— 成败看
     * T 行的 status/kat_st/CRASH 列, 不看进程退出码。 */
    ib_run_cases("x87", g_cases, NCASES);
    return 0;
}

