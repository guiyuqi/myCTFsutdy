# 12069 · FedResNyFinLedgerOs（PWN / HARD / 500 / 0 解）

- **状态**: 未解出（BLOCKED）
- **flag**: 未解出
- **提交**: NOT_ATTEMPTED（无可复现 flag）
- **工具**: objdump / gdb(pwndbg) / Ghidra headless（自写 DecompAddr.java）/ 自写反汇编器 / 自写 YOLOFS1 文件系统工具 / 靶机内 `as` 汇编器
- **SKILLS**: competition-reverse-pwn, ctf-pwn
- **SKILLS_USED**: competition-reverse-pwn 的「先把 loader / payload / 配置 / post-decode 行为分开 + 记录 primitive / 可控字节 / 泄漏源 / 目标对象」直接用于把三件套拆成
  `vm`(宿主模拟器) / `image.bin`(YOLOOS 内核+OS)/ `disk.bin`(YOLOFS1) 三层并分别建模；ctf-pwn 的
  「custom VM / emulator OOB → ret2libc」判据（sandbox-escape.md 章节）确认了本路线：**MMIO 设备 handler 的
  长度检查 vs host 缓冲大小不一致** 才是逃逸点（CPU cache 写 0xd00 / 读 0x200）。

## 题目形态
三件套：`vm`（850KB static-pie，自研 16-bit CPU 模拟器 + 7 个 MMIO 设备 + 两层 seccomp）、
`image.bin`（YOLOOS：内核 + OS shell + 全部系统调用）、`disk.bin`（8MiB YOLOFS1，FAT + 目录 +
7 个 YOLOEX 程序，含一个**靶机内汇编器 `as`**）。启动后得到 `yolo>` shell（OS 特权 1）。

## 已确认（全部带一手证据，详见 FINDINGS）
1. 完整 ISA（33 条指令 + 3 种特权级 + trap/enteru/iret 机制）→ 自写反汇编器，反汇编结果自洽，
   并用靶机内 `as` 汇编器交叉验证（`ldi/add/mov/ld/st/ldw/stw/inc/shl/enteru/iretos` 全部对上）。
2. 7 个 MMIO region 与 ctx 布局（gdb 实测宿主栈）；**CPU cache 设备 (0xf300) 的宿主写窗口 0xd00
   字节、读窗口仅 0x200**，其 buf 就是宿主 main 的栈（实证 `rsp+0x3c0`）→ 写满 0xd00 即可覆盖
   main 保存的 rbx/rbp/ret，具备完整 ROP 空间。
3. 宿主 seccomp 两层：只禁 execve/execveat；runtime 层白名单含 openat/read/write → 逃逸后
   open+read+write 足以读 flag。
4. 内核 syscall 表 16 个；`SYS_ZCACHE_STORE/LOAD(12,13)` 被硬编码为 UNSUPPORTED（禁用），
   说明作者刻意把「写 cache」留给 KERNEL 内部 staging。
5. **可复现漏洞 A**：USER 系统调用缓冲区校验范围表（kernel RAM 0x2a7a..0x2a84 =
   {0,0x1000,0x3000,0x6000,0x7000,0xf000}）对 USER 放行 `[0,0xfff] ∪ [0x3000,0xf000)`。
   于是 `syscall 0`（READ fd=0，len≥0x201 的大块路径）可以 `read(0, 0x3000, 0x1000)`
   —— 内核以 **KERNEL 权限**把 stdin 逐字节写进 **内核栈 0x3000-0x3fff**。本地已实测
   （填充 0xAA 后内核 `pop r0` 得到 0xAAAA）。
   同一区间还可用 `read(0, 0, 0x1000)` 覆盖**内核低 1KB**：RAM[0]=TRAP_CALLER、宿主注入的
   48-bit machine token(RAM[8..0xf])、FD 表(0x320-0x3a0)、FS 状态(0x120-0x126)。
6. **可复现漏洞 B（信息泄漏）**：USER 可 `write(1, 0x3000, 0x200)` 把内核栈打印出来；
   machine window 设备读允许到 offset 0x20f，可读到宿主 stack canary。
7. 文件读路径对 USER 额外要求 `buf >= 0xe000`（0x2608），因此内核栈写入只能走 stdin/磁盘读。

## 卡点（BLOCKED）
把 (5) 的「内核栈可写」升级为控制流劫持失败：stdin/磁盘读的**大块路径**在写入后直接
`pop r0; iret`，没有 `ret`；内核最大调用深度只用到 0x3ff8-0x3ffe，而每次 syscall 入口的
push 会把这几字节重新覆盖，所以预先污染更低地址无效（精确到字节推演 + 实测）。
文件读路径虽嵌套更深但没有活跃返回地址落在可写区（被 `buf>=0xe000` 挡住）。
→ 需要再找一条 **KERNEL 权限下把 >0x200 字节写进 0xf300** 的路径（或伪造 FD 表/FS 状态
让内核 staging 的 r2 超限）。已排除：所有 `st [0xf3xx]` 站点（0x1337/0x1369/0x13fa/0x14bb/
0x1515/0x1570）的循环计数都被调用方限制在 ≤0x200；0x131b staging 的循环在 dest 回绕到
0xf300 时停止（最多 0xd00，但调用方 r2 仍是 ≤0x200）。

## 产出
- `work/12069_fedres/FINDINGS.md`（完整逆向笔记：ISA 表、MMIO 表、ctx 布局、ABI、漏洞）
- `work/12069_fedres/{vmdis.py,disimg.py,fs.py,runvm.py,asmfile.py,mkstage.py,probe.py,consts.py}`
  可复用工具（反汇编 / YOLOFS1 / 用靶机 `as` 汇编任意程序 / 一次会话造二进制载荷文件）
- `work/12069_fedres/image.dis.txt`（整份 guest 镜像反汇编）、`handlers.dec.txt`（宿主设备 handler 反编译）
- `work/12069_fedres/prog/p1..p9.asm`（已实测的 USER 程序，含内核栈写原语）
- `evidence/12069-FedResNyFinLedgerOs-FINDINGS.md`

## 追加（本轮最后阶段）：已打通 USER → KERNEL 控制流劫持
`read(0, 0x3e00, 0x200)`（SYS_READ fd=0 小块路径）：
内核先把 stdin 读进 CPU-cache staging（0xf300），再 `call 0x134d` 复制到调用者缓冲；
buf=0x3e00 + count=0x200 时复制范围正好覆盖 0x3ffc（0x134d 自己 push 的 r2）与
0x3ffe（`call 0x134d` 的返回地址）。`pop r2` / `ret` 弹出攻击者字节 →
**PC 落进 kernel 代码区且 PRIV=KERNEL**。实测 panic：
`PC=0x1386 SP=0x4000 PRIV=KERNEL R0=0 R1=0x4001 R2=0xffff R3=0x1`。
剩余最后一段：在该寄存器组合下找 gadget 把 >0x200 字节写进 0xf300，
即可用 CPU cache 的 0xd00 宿主写窗口覆盖宿主 main 返回地址完成逃逸。

## 追加 2：已打通 VM 逃逸的 2/3（实测，宿主 SIGSEGV）
- 控制流劫持：`read(0,0x3e00,0x200)` 覆盖内核已入栈返回地址 → **PC 精确可控、PRIV=KERNEL**
  （实测落地 0x1234→panic PC=0x1235；0x1789→PC=0x17bc），寄存器 R0=0, R1=0x4000,
  R2=攻击者, R3=0xf500-R2。
- 写 CPU cache：劫持目标 `0x13fa`（`ldi r1,0xf300` + stdin 读循环），P2=0xd01 ⇒
  **把 0xd01 字节 stdin 写进 0xf300..** = CPU-cache 的 0xd00 宿主写窗口 = 宿主 main 栈
  （buf = `local_248[65]`，≈main rsp+0x3c0）。实测宿主进程 **SIGSEGV**。
- 宿主栈布局已测：offset 0x208 = stack canary（可用 machine-window 读泄露），
  0x218.. = saved rbx/rbp/r12-r15，0x248 = main 返回地址。
- 剩余：canary 泄露（路线明确）+ PIE base（读不到代码指针 → 采用**低 16 位部分覆盖 + 16 次
  暴力 bits12-15**）+ payload 必须**无 0x0a**（stdin 换行过滤）。之后 openat/read/write 读 /flag。

## 可复用工具链（work/12069_fedres/，通用自定义 VM 逆向资产）
| 文件 | 用途 |
|---|---|
|`vmdis.py`|YOLOOS 16-bit CPU 反汇编器（33 条指令，含特权级语义注释）|
|`disimg.py`|按正确偏移（RAM[x]=image.bin[0x20+x]）反汇编 guest 镜像|
|`image.dis.txt`|整份 guest 镜像（0x0-0x6960）反汇编|
|`fs.py`|YOLOFS1 文件系统读写（FAT 链、目录项 name/size/first/flags/checksum）|
|`asmtest.py`/`probe.py`/`consts.py`|用**靶机内汇编器 `as`** 汇编任意源码并回读字节（ISA/助记符/常量探测）|
|`asmfile.py`|同一 VM 会话内 `run write`+`run append` 分段建 .asm → `run as` 汇编 → 回读 YOLOEX|
|`mkstage.py`|一次会话内“汇编程序 + 用裸 stdin 生成任意二进制载荷文件”|
|`runvm.py`|本地启动 vm（自动回写 disk.bin），返回 rc/stdout|
|`remote.py`|远端单连接交互（<target>:22088）|
|`prog/p*.asm`|已实测的 USER 程序：p1 内核栈写、p10/p15/p16 控制流劫持+宿主栈覆盖、p13/p14 中间试验|
|`handlers.dec.txt`/`dec.log`|宿主 7 个 MMIO 设备 handler 与 main 的 Ghidra 反编译|
`scripts/DecompAddr.java`|按地址定向反编译的 Ghidra 脚本（大函数巨帧下比 fw-decompile 好用）|

## 追加 3：宿主泄漏窗口的硬结论（gdb 实测）
可读宿主窗口 = main `rsp+0x3c0` 起 0x210 字节：
- 0x000-0x1ff：全 0（machine-record 缓冲）
- **0x200-0x207：`0x7ffff7ff80e0` = base+0xce0e0（唯一的 PIE 相对指针）→ 被 machine window 读
  精确隐藏（返回 0），cache 读又卡在 `<0x200` ⇒ guest 拿不到 base**
- 0x208-0x20f：**stack canary（8B）→ 可泄露**（可写成“guest 程序 zstream 读 → write 打印 →
  交互式拿到 canary 再发最终 payload”的自包含 exploit）
⇒ 出题人**故意关掉了 PIE 泄漏**（连同 SYS_ZCACHE_STORE/LOAD 一起），所以预期解法不是常规
  ret2libc；仍需找到**不依赖 base** 或能**二次泄漏**的宿主控制流目标，或第二条 host 写路径。

## 追加 4（收尾）
- **canary 已实测可泄漏**：`prog/p18.asm` = `syscall 15`(SYS_ZSTREAM, r0=0 读方向, buf=0xe400, len=0x210)
  + `write(1,0xe608,8)` → 输出 `00 9a 0c 39 6e 49 88 1d` = 宿主 main 的 stack canary。
- 顺带确认内核替 USER 服务时的写窗口：**不能写 [0x8000,0xdfff]**（user-memory-window 保护），
  可写 <0x8000 与 [0xe000,0xffff]。
- 磁盘设备 ctx 已 dump：+0x00 是 8MiB 缓冲指针，但 MMIO 只暴露 +0x28 的随机 seed ⇒ 无泄漏。
- 分段写可行：cache 写偏移 r3 可控（r3=0x248 只改返回地址低 2 字节；r3=0x250 单独写链），
  但**链项绝对地址仍需 base**。
- 最终判定：卡点唯一且明确 = 宿主 PIE base 高位不可得（作者隐藏了唯一指针）。所有 guest 可达的
  宿主读路径已穷尽。若继续，建议换「篡改宿主自身会解引用的栈上指针」这条非 ret2libc 路线。

## 追加 5（延时阶段，最关键）
- **main 返回地址 = base+0xeca1 < 0x10000** ⇒ 返回地址高位落在 `[base, base+0xffff]` 窗口。
  **只改低 2 字节**（保留高 6 = base）即可跳到该窗口内任意位置，**不需要 base**（只暴力 base bits12-15，
  页对齐 16 种）。该窗口含：main(0x9cb0)、整个 VM 主循环(0xa3ec-0xb4d0)、**全部 7 个 MMIO handler**
  (0xba70-0xd1f0)、panic 打印器(0xc380)、image 加载器(0xe310)。
- cache 写偏移 r3 可控 ⇒ **定向局部覆盖**：`r3=0x208, len=0x43` 只重写 canary+saved regs+返回地址低 2 字节，
  返回地址高 6 字节（=base）原样保留。canary 已可交互泄漏 ⇒ **base-free 的一次跳转+6 受控寄存器原语成立**。
- main 返回瞬间寄存器实测：rdi=0x7ffff7721000, rsi=0x801000, rdx=0, rbx=CPU state, r14=VM RAM,
  r15=8MiB 磁盘缓冲；rbx/rbp/r12-r15 可被我们的 payload 覆盖。
- **缺的一环**：一个 base-free 的单次跳转目标。最希望的两条：①跳 main 的 0x9e2b（argc 检查之后）
  = VM 重新加载并重启（进程不退出，且**同进程内 canary/base 不变** ⇒ 可泄漏后再打第二击）；
  ②跳 panic 打印器的 fprintf 点(0xc3ab) 配合 `mov rsi,rXX` gadget 泄漏宿主内存。

## 追加 6（硬停收尾）
- **修正**：cache 写起始偏移**不可控**（`0x13fa` 只能从偏移 0 写，`0x1331` 的源是 OS 代码）。
  "只改 ret 低 2 字节"只能靠**长度**控制（P2=0x24a），结论仍成立。
- **未解异常**：p19（zstream+write 后再劫持）里 P2 落地为 0 而非 0x24a；p10/p16 同机制正常。
  怀疑 `write` 的 cache staging（0x131b）干扰了 0x3ffc，需用"只加 syscall 1"的变体二分定位。
- reboot(0x9e2b) 因该异常未验证成功；判据要用"让 host 正常 exit 以 flush 块缓冲的标准输出"。
- 已确认 `[0x9340,0xffff]` 窗口内有 128 处 `mov rdi/rsi/rdx,rbx|rbp|r12-r15`、24 处 printf 调用点，
  泄漏 gadget 的搜索面很小。

## 追加 7（本轮结束，重要修正）
- **修正寄存器映射**：劫持落地是 `R0=0, R1=0x4000, R2=0, R3=payload[0x1fc]`（不是 R2=P2）。
- **cache 写长度用 EOF 控制**（关 stdin 写端）：`R1=0xf54a` 证明精确写了 0x24a 字节；
  用换行结束会多写 1 字节并破坏返回地址高位。
- **【新证明】宿主 PC 劫持成功**：canary 正确 + ret 低 2 字节改为 `(base+0x9e2b)&0xffff` ⇒ main 第二次执行，
  打印 `Cannot lock disk directory (another VM/build may be using it)`。
  ⇒ **不需知道 PIE base，只需暴力 base bits12-15（16 种）**。
- **reboot 不可行**：改跳 0x9e5d 后停在 `signal(SIGPIPE): Operation not permitted`
  （runtime seccomp 白名单无 rt_sigaction/mmap，malloc 8MB 也会 EPERM）。
- **缺口**：单次 host 跳转需要 1 个绝对地址；窗口内候选点已列表（0xd6f0 open 包装 / 0x128a0 fopen /
  0x9de0 `Usage:%s` / 0x937a fprintf 包装 / 0xa28d 磁盘重载 / 0xa71d「回到 VM 循环」）。
  跳转瞬间 r14=VM RAM、r15=8MB 磁盘缓冲（内容 guest 可控），但缺 `mov rdi,r14|r15` → open 的连续序列。

## 追加 8（最终）
- 否定性结论：跳转瞬间 `rdi=0x7ffff7721000` **未映射**（gdb: Cannot access memory）⇒ 不能拿它当路径；
  `0xe940` 以上不是我们的数据（len=0x24a 只写到 0xe939，且原始栈 0xe940 首字节 0xff、0xe950 首字节 0x00
  会把 %s 截断）⇒ 路径不能放宿主栈。
- 唯一自洽出路：窗口内 `mov rdi/rsi, r14`（r14=仍映射的 guest RAM，内容可控）→ 短跳到
  `fopen`(0x128a0，需 base&0xffff≥0x2000) 或 `0xd6f0`（app open 包装），"/flag\0" 放 guest RAM 非 0 偏移。
- 远端 22088 在 13:10 左右变为 ConnectionRefused（平台修复），已即时回报父代理，未自行 start。

## 追加 9（离线收官：gadget 组合审计）
本轮把"最后一块拼图"的形状精确化并**逐项排除**（全部写入 FINDINGS §22-§23）：
1. 六个 `mov rdi,r14` 站点（0x953d/0x95f7/0x965e/0x96bb/0x9718/0x9ad5）代码完全相同，是 glibc stdio
   的锁定/flush 内部（`call 0x97180` + `[rbx+0x88]` 锁），r14 被当 FILE* ⇒ **无法导向 open/fopen**。
2. 三个常量/半常量指针全部不可用（gdb 实测）：`rdi=0x7ffff7721000` **未映射**、`rsi=0x801000` **未映射**、
   `r9=base+0x9d210` 虽是 PIE 指针但内容是 exec-region 表（第 3 字节 0x00，作路径为空串）。
3. 全窗口**没有** `lea rdi,[rsp-X]`（只有 image loader 里的 `lea r11,[rsp-0xf000]`），所以不能把路径放在
   我们写到宿主栈上的字节里（rsp=0xe940，我们只写了 rsp 以下的 0x250 字节）。
4. 新发现：`__libc_start_call_main` 用 `call [rbp-0x88]` 调 main，而 `[rbp-0x88]=0xe958`（= &main）
   **落在我们的写窗口内**，但只在启动时消费 ⇒ 无收益。
5. 0x10000-0x1ffff 段内唯一 open 站点 0x1568e 前置 `mov rdi,rax`，而跳转瞬间 rax=0 ⇒ open(NULL) EFAULT。
⇒ 结论：单次宿主跳转需要"已映射且 guest 可控的路径指针 + 窗口内 mov rdi,rXX→open 的短路径"，
   前半只有 r14 满足、后半在 0x9340-0x1ffff（约 3.5 万条指令）全段筛不到。**这不等于不可解**，
   只是这一形状不存在；剩余方向是"让宿主把宿主内存写回 guest 可读的 machine window"（需要 rsp 复原 gadget，
   而 rsp 复原需要栈地址 ⇒ 又回到"需要一个宿主指针"）。

## 交付物（下次拿到靶机 5 分钟内可验证）
- `prog/p22.asm` + `gen_exploit.py --canary <hex> --target-off 0x9e2b`：
  自动列出 16 个 base_hi 中可达者与对应 ret 低 16 位（0x9e2b 实测 11/16 可达；base_hi=10 → 0x3e2b，已本地验证成功）。
- 远端判据：① 必现 guest `KERNEL PANIC: stack pop outside stack bounds ... R1=0xf54a`；
  ② 命中 base_hi 时额外出现 `Cannot lock disk directory (another VM/build may be using it)`
  （目标 0x9e5d 则出现 `signal(SIGPIPE): Operation not permitted`）；③ 未命中则无此两行。

## 追加 10（交付：一键自检 + 参数化生成器）
- `work/12069_fedres/selftest.sh` **已跑通 PASS**：本地 10~20 秒复现
  "0x24a 字节精确写宿主栈 + main 二次执行（= 宿主 PC 被 base-free 劫持）"。
- `gen_exploit.py --canary <hex> --target-off <hex>`：给出 16 个 base_hi 中可达者及对应 ret 低 16 位
  （target=0x9e2b 时 11/16 可达；base_hi=10 → 0x3e2b，即本地已验证的组合）。
- **坑（已修）**：`asmfile.py` 原先复用固定 `src.asm`，若盘上已有旧源文件会导致汇编出**旧程序**
  （我一度因此得到"File not found/无 canary"的假失败）；现改为按输出名生成唯一源文件名。
- **坑**：canary 有 ~2.7% 概率含 0x0a，会被内核 stdin 读循环截断 ⇒ 重连重试。

## 追加 11（穷尽审计·最终）
可达区 0..0x20000（22297 条指令）内「路径来自寄存器 + 8 条内 call open/fopen」的站点**只有 10 个**，
其中唯一"来自仍映射寄存器"的是 `mov rdi,rsp`（rsp=0xe940 → 原始栈，不是我们的数据；且 0xd85d 那处
随后被 `mov edi,eax` 覆盖），其余全是固定串（"."、"image.bin"、"disk.bin"）或 rax=0。
⇒ **不存在** `路径←r14` 的 open 站点，也**不存在** `lea rdi,[rsp-X]`。
⇒ 逃逸链完成 4/5 步（USER→KERNEL 劫持 / 0xd00 写宿主栈 / canary 泄漏 / **宿主 PC base-free 劫持**），
最后一步"读 flag"缺一个新原语，三条候选方向已写进 FINDINGS §24(a)(b)(c)。
