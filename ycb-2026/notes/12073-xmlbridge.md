# 12073 · xmlbridge（PWN / EASY / 500 分 / 全平台 0 队解出）

> **★★ 已解出（`pwn-12073s`，静态侧）**：门禁 `*(u32*)(g_doc+4)` 可以用一条**无泄漏**的
> libxml2 dict 哈希表越界插入打穿（写入的是硬编码常量 1）。见 §9.11 与
> `scripts/12073-solve.py`。上面「未解出 / 交付缺陷」的结论与 §7 的 BLOCKED 作废。

- **结论**：未解出。**判定为出题方交付缺陷（外层门禁恒 0）**，不是"技术不够"。
  静态 + 动态双向证据见下，`evidence/12073-dead-gate-static.txt`、`evidence/12073-live-gate.txt`。
- **flag**: 未解出（flag 只存在于 oracle 的权限域，路径 `/home/ctf/flag`）
- **提交**: NOT_ATTEMPTED（额度 0/50，不猜写法）
- **工具**: objdump / python3+pwntools / 自写协议客户端 `work/12073_xmlbridge/fc.py` / 实靶 `<target>:19118`
- **SKILLS**: `competition-reverse-pwn`, `ctf-pwn`
- **SKILLS_USED**:
  - `competition-reverse-pwn` → "先被动三角（类型/导入/字符串/资源），把 loader/payload/config 分开；
    每条结论必须挂在可观察边界（decode / persistence / crash / leak）上"——本题落地为：
    先 `strings` 建**五进程拓扑 + 每层命令词表**，再把每个"可观察边界"（TCP 回包、unix socket 帧、
    oracle 的 VM TRACE 输出）与代码里的 gate 一一对上，最后才下"门禁恒 0"的结论（不靠猜）。
  - `ctf-pwn` → "Protection Implications" 表直接改写了打法：六个二进制全是
    `Full RELRO + Canary + PIE + NX + SHSTK + IBT`，所以**放弃了 GOT/ret2win 路线**，
    转向"协议/状态机逻辑洞 + 堆原语"；同时该技能的 "Source Code Red Flags"（memcpy 长度 vs 缓冲区、
    自定义 parser 未校验长度）直接指向了 `keeper` 的 `COMMIT` 0x110 栈缓冲区溢出与 `xmlbridge` 的节点 UAF。

---

## 1. 交付物 / 拓扑（已静态确证）

附件：`firmware/12073_xmlbridge/xmlbridge的附件.zip` → 6 个 ELF + 精确 libc/libxml2：
`listener`、`xmlbridge`、`broker`、`manifestvault`、`keeper`、`oracle`，
`libc.so.6`(Ubuntu 22.04, glibc 2.35)、`libxml2.so.2`、`libicuuc/libicudata/libstdc++...`。

作用链（由各二进制里的 `bind/connect` 路径字符串 + rodata 直接读出）：

```
TCP:19118 → listener  --execve("/home/ctf/xmlbridge")-->  xmlbridge (stdin/stdout)
                                                        │ connect
                          /run/xmlbridge/broker.sock  ←─┘   → broker
                          /run/xmlbridge/manifest.sock     → manifestvault
                          /run/xmlbridge/keeper.sock       → keeper
                          /run/xmlbridge/oracle.sock       → oracle   ← 唯一能读 /home/ctf/flag
```

保护（pwntools checksec，6 个全一致，仅 broker 无 canary）：
`Full RELRO / NX / PIE / SHSTK / IBT`，`broker` 额外 `No canary`。

## 2. 协议（实测 + 反汇编，可直接复用）

**前端 xmlbridge**（`[op:1][len:4 大端][body]`）：
- 回包只有三种：`OK\n`(3B) / `ERR\n`(4B) / `[u32 大端 len][正文]`（DOC 类结果）。
- 任何一个 handler 返回 0 → 回 `ERR\n` **并且整个连接结束**（这点很重要：ERR 不是可恢复的）。
- 状态机（`g_stage @ .bss 0x60d0`）：

| op | handler | 前置 stage | 后置 | 要求 |
|---|---|---|---|---|
| `L` | 0x2ac7 | 0 | 1 | XML 根元素 `sheet`，其首个子**元素** `item`；解析后 `xmlFreeDoc` **却保留 item 节点指针**（UAF 源） |
| `I` | 0x2bde | 1 | 2 | XML 根 `root`，首个子元素 `target`；malloc 0x78×2 建状态 |
| `R` | 0x2d7e | 2 | 3 | len≤0x80，`xmlNodeSetContent(g_item, text)`（对已 free 的节点写入） |
| `C` | 0x2e3b | 3 | 4 | `xmlFreeNodeList(g_item)` → **二次 free** |
| `S` | 0x2e79 | 4 | 5 | 分配 snapshot 状态(0x78)、0x500 缓冲(memset 'A')、0x80 缓冲 |
| `E` | 0x2fc8 | 5 | 6 | len≤0x80，`xmlNodeSetContent(g_root->children, text)` |
| `A` | 0x31fd | 6 | 7 | push parser 解析 `attachment.xml`，options=`0x817`(RECOVER\|NOENT\|DTDLOAD\|DTDVALID\|NONET)，并**替换实体加载器** |
| `B` | 0x33e7 | 7 | 8(成功/失败都置 8) | 收尾；成功→回 `DOC <附件内容>`，失败→回 `ERR\n` |
| `P` | 0x35b3 | 5 或 6 | — | `xmlNodeDump` 出修订文档 → `[u32 len][XML]` |
| `D` | 0x2900 | **8** | — | `[u16 大端 len][body]` 发 `/run/xmlbridge/broker.sock`，把 broker 的 `[u16 len][正文]` 转成 `[u32 len][正文]` 回给我们 → **进入归档链的唯一入口** |

**下游四层**统一用 `[u16 大端 len][body]` 分帧，且都是 `HELLO → 挑战串` 形态（这个挑战串对攻击者不构成障碍，
服务自己会告诉我们）：

- broker：`XBRDGv3`/`BRIDGE`(问候)，`RCPTv2/REVIEW/READY`，`PING/PONG`，`OPEN /SUMMARY/OPEN/TICKET %.8s`，
  `ARCHIVE/ARCHIVED`，`NOTE /note/NOTED`，`VIEW`，`RELEASE/RELEASED`，`DRAFT/DRAFTED`，`WRITE /draft/WRITTEN`，
  `COMMIT`，`PRIVATE`；内部还有 `broker.xml` + `open`/`dup3`（配置文件读取）。
- manifestvault：`MNFSTv3`、`HELLO→MV3 %016lx`、`MINT /INDEX /DROP /GLANCE /CORRECT /LAYER /TRIGGER`；
  `GLANCE` 回 `TRACE %016lx %016lx %016lx`（**一个主动泄漏点**）。
- keeper：`HELLO→K4 %016lx`、`AUDIT <fmt>`、`COMMIT <blob>`；启动时自己 `connect` oracle.sock 并把
  oracle 的 fd 存在 `.bss 0x5014`（**关键**：拿到 keeper 的 ROP 就等于拿到 oracle 通道）。
- oracle：见下节（完整拿旗推导）。

## 3. oracle 的拿旗链（静态完全推通，未能在靶机执行到）

oracle 每个连接 fork 后：
1. `open("/home/ctf/flag", O_CLOEXEC)` → fd 存 `ctx+0x36c`；
2. `/dev/urandom` 取 8 字节 seed → `ctx[0]`；`ctx[8]=splitmix64(seed^0x4f5241434c453576)`；
   `ctx[0x10]=&FUN_1684`（写 `DENIED`）；`ctx[0x18]=rotl(seed^&FUN_1684, 0x15)^ctx[8]`；
3. 装 seccomp：`arch==X86_64`、禁 x32 ABI、`execve/execveat/open/openat/openat2 → EPERM`，其余放行
   （**`read` 没禁** —— 所以"已经 open 的 flag fd"随时可读）；
4. 命令：`HELLO`→`O5 %016lx`(回 seed)；`PROGRAM `+16 字节×n 块(n≤0x30)→`LOADED`；`RUN`→执行字节码 VM。

VM（`FUN_19cb`）：每条指令 16 字节 `{op:u8, a:i8, b:i8, pad, imm:u64}`；栈 16 格；寄存器取址
`reg(i)=ctx+0x20+8*i`，**索引是 `signed char` 且只判 `i>7`** → `i` 取 `0xfe/0xff` 即命中
`ctx+0x10`/`ctx+0x18`。opcode：
`1` push *reg(a)；`2` *reg(a)=imm；`3` *reg(a)^=*reg(b)；
`4` 防篡改调用：要求 `ctx[8]==splitmix64(seed^MAGIC)`、`ctx[0x10]==&FUN_16b6`、`ctx[0x18]==rotl(seed^ctx[0x10],0x15)^ctx[8]`，
然后 `ctx[0x10](ctx)`；`FUN_16b6` = `read(ctx[0x36c]=flagfd) → write(ctx[0x368]=client)`。
VM 正常跑完还会输出 `TRACE <pushed...>\n`（栈值泄漏）。

**不需要 PIE 基址的绕过**（关键）：`&FUN_1684=base+0x684`，`FUN_16b6=base+0x6b6`，而 `0x684^0x32==0x684+0x32`
（低位不重叠进位），故 `(seed^(A+0x32)) = (seed^A)^0x32`，于是
`need(ctx[0x18]) = old(ctx[0x18]) ^ rotl(0x32,0x15)`。所以程序：

```
# PROGRAM 数据块（16B each）
02 00 00 00 32 00 00 00 00 00 00 00 00 00 00 00   # reg(0)=0x32
03 fe 00 00 00 00 00 00 00 00 00 00 00 00 00 00   # ctx[0x10] ^= 0x32  -> &FUN_16b6
02 00 00 00 <rotl(0x32,0x15) LE8>                 # reg(0)=rotl(0x32,0x15)
03 ff 00 00 ...                                   # ctx[0x18] ^= rotl(0x32,0x15)
04 00 00 00 ...                                   # 调 FUN_16b6 -> read(flagfd)->write(sock)
```
→ flag 原样写到客户端 socket；VM 返回 2，oracle 关连接。**前提**：我们能自己给 oracle 发 `PROGRAM`/`RUN`，
但只有 keeper 连 oracle，而 keeper 里没有 `PROGRAM`/`RUN` 字符串 → 必须打掉 keeper 用它手里的 oracle fd 发。

## 4. keeper 的两个洞（拿 oracle 通道的现实入口）

- `AUDIT <body>`：`snprintf(out, 0x200, body, seed, &FUN_176b, x, (clientfd<<32)|oraclefd)`
  —— **body 直接当格式化串**（任意读/`%n` 任意写；PIE/canary/stack 一次全泄）。
- `COMMIT <blob>`：`FUN_1960` 里 `memcpy(stackbuf[0x110], blob, len)`，`len` 最大 0x307
  —— **0x1f0 栈溢出**，canary 在 `rbp-8` 可先由 AUDIT 泄出 → ROP：`write(oracle_fd,"PROGRAM ...")`、
  `write(oracle_fd,"RUN")`、`read(oracle_fd,buf)`、`write(client_fd,buf)`（keeper 的 seccomp 只禁 open/execve）。
- keeper 无 `PROGRAM`/`RUN` 字符串 ≠ 发不了：ROP 时把字节写进 `.bss`/栈即可。

## 5. **判死依据：外层门禁恒 0（交付缺陷）**

`xmlbridge` 里 `g_doc` 指针（`.bss 0x60a0`）指向 A 步骤 `malloc(0x420)` 的块；三道门禁都要求
**`*(u32*)(g_doc+4) == 1`**：

1. 自定义实体加载器 `0x3089`（这就是题名"XML 桥接"的 XXE 入口，只允许 `file:///home/ctf/` 前缀，
   17 字节 `strncmp`，`xmlDictSize ≤ 0x10`）→ 0x30e8 `cmp eax,1`;
2. `B` 的成功分支 → 0x348c `cmp eax,1`；不满足就回 `ERR\n`（且仍置 stage=8）；
3. `D`（归档链唯一入口）→ 0x2955 `cmp eax,1`。

而**整个二进制里对这个 4 字节的唯一写入**是 A 步骤里的 `memset(g_doc, 0, 0x420)`（0x32d4–0x32e8）。

静态穷举（`objdump -d` 全文）：
- 引用 `0x60a0` 的指令共 **9** 条：1 条存指针（0x32ab），8 条只是读指针；**没有任何一条写 `[x+4]`**。
- 全文没有任何 `mov DWORD/QWORD PTR [reg+0x4], 0x1`；全文 `mov DWORD PTR [rip+...],0x1` 只有 2 处：
  `g_stage=1`(0x60d0) 与 `g_errflag=1`(0x60d4)。
- 另有一批**分配了从不使用**的脚手架（作者把参考实现抄坏了/留了诱饵）：
  `0x60b0`(0x420,连 memset 都没有)、`0x60c0`/`0x60c8`(0x40 附件段缓冲)、`0x60a8`(0x80)、
  `0x6080`(snapshot 状态，只写不读)、`0x6098`(0x500 'A' 缓冲，只被错误回调拿来做 `+0x10` 自增)。
  即"附件事务"这条主线其实只被 NULL 检查、从未被真正实现。

动态（实靶 `<target>:19118`，单连接，见 `evidence/12073-live-gate.txt`）：
按文档顺序打**完全合法**的流程，前 7 步全 OK，B 起崩：

```
L -> OK    I -> OK    R -> OK    C -> OK    S -> OK    E -> OK    A -> OK
B -> ERR\n
D -> ERR\n           <- 归档链进不去；且 ERR 直接终结连接（无法重试）
```

结论：`A/B`（文档主线的"附件事务"）在**部署实例上必然失败**；`D`（进入 broker/manifestvault/keeper/oracle
的唯一通道）必然失败；实体加载器（唯一的文件读取路径）必然不触发。
=> 除前端外**四个服务在正常协议下不可达**，而 flag 只在 oracle 的权限域
（`附件描述`+`oracle` 内 `open("/home/ctf/flag")` 双重确证），因此
**不存在"预期解法"**；唯一能出 flag 的路线是用作者没打算给的堆原语把 `0x60a4` 改成 1：

- 可用原语（真实存在，但均为非预期）：`L` 保留已 `xmlFreeDoc` 的 `item` 节点指针 →
  `R` 对已释放节点 `xmlNodeSetContent`（UAF 写）→ `C` 再 `xmlFreeNodeList`（二次 free → tcache dup）。
  要把它升级成"往 `.bss 0x60a4` 写 1"还需要 heap + PIE 双泄漏（`P` 只 dump 活文档，泄不到），
  属于"另写一道堆题"的工作量，且**与题面描述的路径无关**。

## 6. 建议（给赛事/复盘）

1. 若作者本意是让 `A/B → D` 通：应在 A 里 `*(u32*)(g_doc+4)=1`（或把 `memset` 长度改成从 8 开始），
   否则整题所有服务都不可达。**这不是 EASY，而是不可解**；全平台 0 队解出与该结论一致。
2. 附件描述里"前四个权限域均没有 Flag 文件读权限"说明作者确实设计了 5 域权限模型；
   但前端门禁恒 0 让 4 个域全部成死码，属**交付级别缺陷**，建议赛务复核。
3. 复现：`work/12073_xmlbridge/fc.py`（前端协议客户端）+ `asm/*.asm`（六个二进制的完整反汇编）；
   oracle 拿旗 exp 的字节码已在 §3 给出，**若门禁被修好，直接走 keeper ROP → oracle VM 即可一枪到底**。

## 7. 卡点（BLOCKED）

`BLOCKED`：前端 `xmlbridge` 的 `*(u32*)(g_doc+4)==1` 门禁恒为 0（唯一写入是 `memset(...,0,0x420)`），
导致 `B`（附件事务）、`D`（归档链入口）、实体加载器（XXE）三条路全断；flag 只在 oracle 的权限域，
故预期解法不存在。需要**出题方修复/换附件**，或授权按"非预期堆利用"方向投入（≥1 小时，先造 heap+PIE 泄漏再翻 .bss 那个 int）。

---

# 第二轮复核（13:26–14:30，实靶 `<target>:16745`）

**平台事实（一手）**：`ycb.py detail 12073` → `已答出27次，当前分值497.21`。上一轮"0 队解出 ⇒ 交付缺陷"的推断**不成立**：
本题有 27 队解出，我方"未打通"。以下只写事实与缺口，不再下"不可解"结论。

## 新证据

1. **本地复现 == 线上部署**：用附件自带 `ld-linux-x86-64.so.2 --library-path .` 跑
   `./xmlbridge < in.bin`，喂 `L I R C S E A B D` 完整合法序列，输出 `OK×7 + ERR + ERR`，
   与线上逐字节一致 ⇒ 线上跑的就是附件里的这份 `xmlbridge`。
2. **fake-node 覆写是真的（不是死码）**：`L,I,R,C,S` 后 `P` 回
   `'<root>' + 0x4ff * 'A' + '</root>'`（1292 B）。
   机制：`C` 把 doc3 的子节点 `target` free 掉，`S` 的 `malloc(0x78)` 复用同一 chunk 造"假节点"
   （type=3 TEXT、name="text"、parent=g_root、content=0x500 的 'A' 缓冲），
   而 `g_root->children` 仍指向它 ⇒ **P 可把一块 0x500 缓冲区整块 dump 出来**（可控 type/content 的假节点已落地）。
3. **B 恒 ERR**：25+ 种附件 XML（15 种根名、自闭合、字符引用、内部实体、`file://` 实体、
   参数实体、外部 DTD、A/B 分段顺序反转、空 A + 满 B）全部 `A=OK / B=ERR`。
4. **实体加载器确实不触发（时间差分）**：实体指向 `/home/ctf/libc.so.6`（2.2 MB，前端必然可读）
   或引用 50 次，`A` 的往返仍是 ~32 ms 且 `B=ERR`；若加载器活着，读 2.2 MB 必有时延或实体上限错误。
   ⇒ 与静态结论一致：`*(u32*)(g_doc+4)!=1` 让加载器 return NULL。
5. **socket 权限**：`broker.sock` chmod `0x1b6`(0666)，`keeper/manifestvault/oracle` chmod `0x1b0`(0660)。
   ⇒ 即使在前端拿到 ROP，也**不能**直接 connect `oracle.sock`（非同组）；进 oracle 必须走 keeper，
   而进 keeper 必须走 `D`（归档链）。

## 缺口（我方未打通的一环）

要把 flag 出来，只差**一个"任意写 4 字节"的原语**：把 `PIE+0x60a4` 写成 1，之后
`D` → 归档链 + `A/B` 的 XXE（`file:///home/ctf/flag`）都能用，oracle 侧的字节码 exp 已备好。

已确认可用但尚未武器化的堆原语（都在 `xmlbridge` 内、单连接单进程）：
- `L` 保留已 `xmlFreeDoc` 的 `item` 节点指针（UAF）；`I` 的第一个 `malloc(0x78)` 直接复用该 chunk
  （且**不 memset**），⇒ `R`/`C` 作用在"tcache 残留"上，`C` 的 `xmlFreeNodeList` 会沿残留字段
  （`children`/`next`/`content`/`nsDef`）继续 free，是"多次 free + 残留指针 free"的原语。
- `C` free 掉 doc3 的 `target`，`S` 复用后把假节点塞进 `g_root->children`（本条已实测可见）；
  `E` 会对该假节点执行 `xmlFree(cur->content)`（= free 0x500 缓冲）并换成我们的文本。
- `A` 的 `malloc(0x420)` 会从被 `E` free 掉的 0x510 chunk 切分复用，随后紧接 `memset(g_doc,0,0x420)`；
  `A` 的错误回调还会对 `[0x6098]+0x10` 做 `+= 1`（只能碰到 `g_doc+0x10`，不是 `+4`）。
  **这解释了为什么"门禁那个 int"无法用纯逻辑/纯 groom 置 1：memset 在其后，错误回调的落点差 0xc 字节。**

需要的能力（我方没有在剩余时间内拿到的）：glibc 2.35（tcache safe-linking）下的
heap + PIE 双泄漏，以及把上面任一 free 原语升级成 `*(PIE+0x60a4)=1` 的定址写。

---

## 9. 静态重查：`+4` 的所有写入者与门语义（`pwn-12073s`，纯静态）

> **一句话**：`[reg+4]` 的写指令全二进制 **0 条**（capstone 234 条内存写全扫）；
> 但"因此不可解"是错的 —— 把 1 写进去的路是现成的：
> **libxml2 建节点时的 `node->type = 1`（`mov dword ptr [rax+8], 1`）落在 `g_doc-4+8 = g_doc+4`**。
> 详细版 `work/12073s/FINDINGS.md`，证据 `work/12073s/gate_proof.txt`。

### 9.1 ★ 先纠正 §5 的方法论错误：`B` 的 ERR **不是门禁给的**
`B`(FUN_33e7) 在门禁 `0x3482` **之前**还有两个失败分支：`ctxt->myDoc==0`(+0x10)、
`ctxt->wellFormed==0`(+0x18)。A 若送**已闭合**的文档，B 再喂任何字节都是
"extra content" ⇒ `wellFormed=0` ⇒ 从分支②失败，**根本走不到门禁**。
⇒ §5 的"B 恒 ERR"、以及动态侧 25 种 payload 的"B 恒 ERR"，**都没有验证到门禁**。

**正确探法：把同一份文档拆开跨 A/B 提交**
```
A: "<a>"    -> OK    (xmlParseChunk terminate=0；wellFormed 仍为 1；stage=7)
B: "</a>"   -> 这时才第一次抵达 0x3482
```

### 9.2 门禁是唯一闸门（本地实证）
gdb 在 `PIE+0x3482` 处 `set {u32}(*(void**)(PIE+0x60a0)+4)=1`：
```
==== B GATE: g_doc=0x55555556a000  *(u32*)(g_doc+4)=0x0 ====
     ** patched gate -> 1 **
DOC                       <- B: ERR -> DOC，stage=8
ERR                       <- D: 门禁已过，D 去 connect broker.sock；本地无 sock 才 ERR
```
⇒ `B`(DOC 回显) 与 `D`(进归档链) **只差这 4 字节**。

### 9.3 写入者普查（P0）
- 对 `.bss 0x60a0` 的引用 **9** 条：`0x32ab` 存指针(`g_doc=malloc(0x420)`)、`0x32d4` 喂
  `memset(g_doc,0,0x420)`、`0x30e8/0x2952/0x3489` 三条门禁读 `+4`、`0x32be/0x30d5/0x293f/0x3476`
  四条 NULL 检查 ⇒ **8 条是读**。
- capstone 全量 234 条内存写：`[reg+4]` 写 = **0**（`mov/or/and/inc/add` 全覆盖；无 `rep stos`/`movdqu`）。
- 全二进制 `imm=1` 的写仅 5 处：`0x6048`(byte dtor guard)、`0x60d0`(stage)、`0x60d4`(errflag)、
  **★`0x2d24 mov dword ptr [rax+8],1`（`*(u32*)(fake_node+8)=1`，即 `node->type`）**、栈上 BPF。
- `memcpy` 仅 2 处（`R`/`E`），都写**栈** `local_98[136]`，`len ≤ 0x80` 且 `[len]=0` ⇒ 边界安全；
  `g_doc` **从未作为参数传给任何函数**。

### 9.4 门语义
`g_doc = malloc(0x420)` 的裸缓冲；三条门禁同形 `if (g_doc && *(u32*)(g_doc+4)==1)`。
反推作者意图 `struct attach_txn { u32 seg_count; /*+0*/ u32 armed; /*+4*/ u8 data[]; }`
—— `+4` = **"附件事务已就绪/armed"**，本该由 A 在 memset 后置 1（漏了）。
佐证作者习惯：`xmlError.code` 也在 `+4`（`0x317f` → `cmp eax,0x216`）。
消费者：实体加载器 `FUN_3089`(0x30e8)、`B`(0x3482)、`D`(0x2955)，与题面
"完成附件事务后，同一连接才能进入归档链"完全对应。

### 9.5 最短路径（候选排序）
- **候选 3（唯一可行）**：让解析器把下一个 **xmlNode 分配到 `g_doc-4`**。
  libxml2 建节点 = `memset(node,0,0x78)` + `node->type = XML_ELEMENT_NODE(1)`（**type 在 +8**）
  ⇒ `(g_doc-4)+8 = g_doc+4` 被写成 1，分毫不差。落地 = **tcache[0x80] 投毒成 `PROTECT(g_doc-4)`**
  （节点是 `malloc(0x78)`），再在 A/B 里喂一个元素；A 的解析就在 memset 之后的同一请求内。
- 候选 1（**排除**）：跳转表 `op-'A'` @0x407c（19 项）已解码，只有 `A B C D E I L P R S`，
  `F/G/H/J/K/M/N/O/Q → return 0`，**无后门/调试分支**。
  另：B 门禁失败**返回 2**（0x3518）⇒ **B 失败不断连接**，stage=8，D 仍可发。
- 候选 2（**排除**）：门字段没有输入通路（实体加载器自身读同一个 `+4`）；`memset` 长度/起点
  是**常量** 0x420 / `g_doc`（0x32db/0x32e0 为 imm）⇒ "起点偏移 0xc"不成立。

### 9.6 实测堆布局（A 时刻，本地 gdb）
```
g_item(0x6060)=0x…b250 == node1(0x6068)   ← UAF 指针与 I 的 fake node **同一块**（实证）
doc2 0x…af70   root2 0x…aa60   node2 0x…b350   ctxt 0x…67420
bufA98(0x6098)=0x…8a50   ← 0x500 'A' 缓冲，**被 E free**（TEXT 节点 xmlNodeSetContent 先 free content）
g_doc (0x60a0)=0x…6a000  ← 页对齐，来自 top chunk（相对偏移固定、绝对地址随机）
buf420(0x60b0)=0x…8aa0   ← = 0x8a50+0x50，**A 的 malloc(0x420) 直接落进 E 刚 free 的区域**
```
⇒ `R`(UAF 写) + `C`(重复/任意 free) + `E`(额外 free 0x500) 三者足以控堆。

### 9.7 仍缺的一环（不含糊）
glibc 2.35 **safe-linking**：fd 必须 `=(g_doc-4)>>12 ^ &chunk` ⇒ 需要
**① heap 泄漏**（`g_doc` 来自 top chunk，绝对地址随机）**② 一条能写含 NUL 的 8 字节的通道**；
现有写原语都是 `strdup`（NUL 截断）或 libxml2 自身的指针写。建议泄漏点：
`P`(0x35b3 `xmlNodeDump`) 与 `B` 的 `xmlNodeGetContent` 都是"把节点 `content` 当字符串吐出"，
让某节点 `content` 指向含 tcache/unsorted fd 的空闲块即可。

### 9.8 复现资产（`work/12073s/`）
`FINDINGS.md`（完整报告）· `gate_proof.txt`（门禁 patch ⇒ DOC 证据）· `trace2.py`（gdb 脚本：
自动定位 PIE 基址 + dump 全部 `.bss` 指针 + 可 patch 门禁）· `census.py`（capstone 写入者普查）·
`drv.py` / `mk2.py`（本地协议客户端 / 拆文档探门）· `baseline.txt` ·
`xmlbridge_all.c`（重跑的完整 Ghidra 反编译 —— 前一版 `dec_xmlbridge/…/xmlbridge_.c`
**只有函数索引、没有函数体**）。

---

# 第三轮（14:35–14:50）：决定性本地闭环 —— 差距只有 4 字节

把三处 `cmp eax,1` 打成 `cmp eax,0`（`83 f8 01`→`83 f8 00`，位置 0x2955=D / 0x30eb=实体加载器 / 0x348c=B），
即"门禁字段为 0 也放行"，然后本地跑（`ld-linux-x86-64.so.2 --library-path . ./xmlbridge_gate0_xxe`）：

```
普通附件 <r>MARK</r>                      -> OK×7 + "DOC MARK\n"        (B 成功)
XXE 附件 &e; -> file:///tmp/f073/flag       -> OK×7 + "DOC FAKEFLAG{local_xxe_ok}\n"
同一输入（原版，门禁未打补丁）              -> OK×7 + "ERR\n"
```

**结论：`A/B` 就是完整的 XXE 文件读，`B` 回 `DOC ` + 被读文件内容；原版与"能出 flag"之间只差
`*(PIE+0x60a4)==1`。** 附带判据：门禁开但文件读不到时 B 回 `DOC \n`（空内容，不是 ERR），
可用来区分"权限拦"与"门禁拦"。

## 三条静态结论（父代理点名，已查清）

1. **`[0x6098]` 语义**：不是 doc 副本，是 `S` 里 `malloc(0x500)` 的快照内容缓冲
   （0x2f27 malloc → 0x2f31 存入 0x6098 → `memset(…,'A',0x4ff)`）。
   全二进制只有 2 处写它（`S` 0x2f31、错误回调 0x31b1），**`A` 从不写它**；且 **`A` 不可能执行两次**
   （入口条件 `g_stage==6 && [0x6088]==NULL`，A 内 0x330d 已把 ctxt 存入 0x6088）。
   ⇒ "靠第二次 A 让 `[0x6098]+0x10` 落到旧 doc+4" 不成立。
   实际可用关系：`E` 把这块 0x500（fake node 的 content）free 掉后，`A` 的 `malloc(0x420)` 会切分复用同一地址，
   此时错误回调的 `+=1` 落在 `g_doc+0x10`（首块被 0x60b0 拿走时落在 0x60b0 缓冲 +0x10），**永远差 0xc 字节**。
2. **`memset` 长度**：`mov edx,0x420`（0x32db）是立即数，不可变；两个 malloc 成功后**无条件执行**；
   没有"空文档跳过 memset"的分支（失败分支直接 `return 0` → 会话结束）。⇒ "长度可变/漏清零" 不成立。
3. **`D` 完整调用链**：`FUN_2900` → 五连检（stage==8 / len∈(0,0x1000] / `g_doc!=NULL` /
   `*(u32*)(g_doc+4)==1` / `FUN_27fb`）→ `FUN_27fb` = socket+connect(`/run/xmlbridge/broker.sock`)、
   缓存 fd 到 0x6010 → `write_full(fd,htons(len),2)` → `write_full(fd,body,len)` →
   `read_full(fd,&rlen,2)` → `read_full(fd,buf,0x1000)` → `write_full(stdout,htonl(rlen),4)` →
   `write_full(stdout,buf,rlen)` → `return 2`。**D 内部没有对 `g_doc` 那个 chunk 的写**
   （0x60a0 全量 xref 9 条：1 存指针 + 8 读，D 占的 2 条都是读）。

## 仍未打通（缺口量化）

只差 **`*(PIE+0x60a4)=1` 的 4 字节定址写**。现有原语：`C` 对 tcache 残留做 `xmlFreeNodeList`
（多次 free / 残留指针 free）、`E` free 0x500 假节点 content、`S` 复用出可控 `type/content` 的假节点、
`P` 可整块 dump 0x500 缓冲。缺 glibc 2.35（tcache safe-linking）下的 **heap + PIE 双泄漏**：
本题没有任何回显指针的读面（`P` 只 dump XML 文本；`B` 被门禁挡；libxml2 报错走 /dev/null）。

### 9.9 第二轮：对齐反驳 + `0x2d24` 基址回溯 + 可命中形状穷举（`pwn-12073s`）

**先作废我自己 §9.5 的"把 xmlNode 分配到 `g_doc-4`"**：`malloc` 恒 16 对齐，
实测 `g_doc = 0x…6a000`（≡0 mod 16）⇒ `g_doc-4 ≡ 12`，**不可能是 malloc 返回值**。
同理 `g_doc+4 ≡ 4` 也不可能。

**`0x2d24 (mov dword [rax+8],1)` 的基址回溯**：`0x2d1d mov rax,[0x6068]` = `I` 里
`malloc(0x78)` 的返回值 ⇒ 同样是 16 对齐堆块 ⇒ **这条也不是任意指针写**。
（但它确认作者的"u32=1 语义"= `node->type`，libxml2 对每个节点都写 `+8`。）

**对齐约束下的写形状穷举**（`g_doc ≡ 0`，门禁 `= g_doc+4 ≡ 4 mod 16`）：

| 形状 | 例子 | 能否命中 |
|---|---|---|
| 分配对象 + 常量偏移 | `node->type(+8)`、`ctxt->wellFormed(+0x18)` | ❌ 需 base ≡12，非法 |
| NUL 结尾字符串写到 malloc 结果 | `xmlStrdup` / `E` 的 content | ✅ 仅当分配**正好落在 `g_doc`**；载荷 `"XXXX\x01"` ⇒ `g_doc+4=1`（+6/+7 仍是 memset 的 0） |
| **原始字节 bulk copy** | `xmlParseChunk→xmlParserInputBufferPush→xmlBufAdd→xmlBufResize+memmove` | ✅ 同上，且不要求字节是合法 XML |
| 结构体字段指针 + 偏移 | `[(field)+4]=1` | ✅ 任意对齐，但需任意写原语+泄漏 |
| 直接写 `.bss 0x60a0` | 改 `g_doc` 指针 | 二进制里**不存在** |

**新实验事实（本地）**
1. **`0x01` 不可能来自被解析的 XML**：`<!--\x01-->` / `&#1;` / PCData / CDATA / PI / 元素名
   内嵌 `\x01` 六组测试 **A 全部 ERR**。唯一来源是**非解析的原始拷贝**：
   `R`/`E` 的 raw memcpy（都在 A 之前），或 **`xmlParseChunk` 的 push buffer**
   （已在附件自带 `libxml2.so.2` 上 disassemble 确证：`xmlParseChunk+321 → xmlParserInputBufferPush+79 → xmlBufAdd+190 xmlBufResize / +217 memmove`；**先 memmove 后解析**）。
2. ★ **`B` 的解析不需要成功**：`B` 门禁失败/解析失败时**都返回 2**（0x34b4/0x3518），
   `stage=8`、**连接不断**。所以 `0x01` 打坏 `wellFormed` 不是障碍 ——
   只要 `memmove` 已把 1 写到 `g_doc+4`，紧接着发 `D` 就能进归档链。
   > **最短路径 = 原始字节 copy 的落点 = `g_doc` 且流第 5 字节 = `0x01`，然后直接发 `D`。不要 XXE、不要 B 成功。**
3. **free 图谱（gdb 断 `free` 实测）**：`R` free 掉 doc2 的 target(`0x…b350`)；
   `C` **第二次 free 同一个 `0x…b350`（glibc 2.35 未 abort）**；`S` 的 `malloc(0x78)` 复用该块
   成为 fake TEXT 节点；`E` free 掉 0x500 'A' 缓冲(`0x…8a50`)。
   ⇒ 现成原语：**0x80 bin 重复项（两个活对象重叠）+ 一次 0x500 free**。

**结论边界**：`xmlbridge` 里 **0 条** `[reg+4]` 写、`g_doc` 自 A 后恒 live、且对齐禁掉了
"分配+常量偏移"这一整类 ⇒ 过门只有三条路（freelist 重复项 + 字符串/原始字节 copy；
可控指针字段 `[(field)+4]=1`；直接写 `.bss`——无此指令），**前两条都以 heap 泄漏为前提**。
"没有纯逻辑/纯 groom 的过门路径"现在是指令级 + 对齐级的双重重证明，不是"我没找到"。

### 9.10 第三轮：tcache/unsorted 实测 + "没有泄漏面"（`pwn-12073s`）

**实测 tcache（gdb `tcachebins`，输入 = `A:"<a>"` / `B:"</a>"`，见 `work/12073s/exp3.txt`）**
```
C 入口   0x80 [2]: b3d0 -> b2d0
S 入口   0x80 [3]: b350 -> b3d0 -> b2d0      <- C 只 free 了 b350 **一次**
A 入口   0x80 [2]: b3d0 -> b2d0              (S 拿走了 b350 做 fake TEXT 节点)
         另有 0x300[1]: 0x…67420 = A 里 ctxt 的来源（踩旧数据建结构）
```
1. **修正我自己 §9.9 的猜想**：`b350` 在 R 里 free 后被新建文本子节点重新分配，
   所以 C 的那次 free 是**普通 UAF free，不是 tcache 双 free** ⇒ **没有 bin dup、没有重叠活对象**。
2. **`E` free 的 0x500 'A' 块不进 tcache**（tcache 上限 0x410）⇒ 进 **unsorted bin**，
   其 `+0/+8` 是 **main_arena 指针（libc 泄漏材料）**。
3. `A` 的 `malloc(0x420)` #1（`DAT_1060b0`，从不使用）把该 unsorted 切走（得 `0x…8aa0`，
   因为 `xmlDictCreate` 先吃掉了块首 0x50）；#2 = `g_doc` 因剩余不够改从 **top chunk** 拿（页对齐）。

**泄漏通道逐条排除（全部为负）**
- `P`：`S` 的假节点 `next=0`，dump 在第一个子节点就停；doc2 用 1/2/3/4 个子节点 + 属性实测，
  输出恒为 `<root>`+0x4ff 'A'（`work/12073s/exp2.py`）。
- `E` 之后 unsorted 块无人引用，`P` 看不到 arena 指针。
- `B` 只回 4 字节 `ERR`（门禁在前）；libxml2 报错进 `FUN_3147`（只 `+=1` / 写 0，不回显）；`D` 被同一门禁挡。
⇒ **A 之前没有泄漏面，A 之后只剩 B/D。本题在单连接内没有任何可回显的读面。**
⇒ 两阶段"先泄漏再定址写"**不成立**；必须是 **leak-free 的定址写**。

**核心问题（精确化）**
> 在"无泄漏 + `g_doc` 自 A 后恒 live + `g_doc+4` 不可能成为 malloc 返回值 + libxml2 里
> 也没有'把常量 1 写进任意地址'的指令"这四个约束下，找一条能在 `memset` **之后**
> 把 `u32 1` 写进 `g_doc+4` 的 **leak-free** 路径。
> 唯一仍可能在形式上成立的形状：**原始字节 bulk copy 的目标块 = `g_doc`**
> （`E`/`R` 的 raw memcpy→`xmlStrdup`，或 `xmlParseChunk` 的 push buffer `memmove`），
> 但前提是 `g_doc` 的 0x430 chunk 出现在某个 bin 里 —— 而**目前没有任何原语能 free 一个未知地址的 chunk**。

## 十四（收尾）★ 一条"SOLVED"回报的复核：**不成立**

静态代理在被打断前回报「SOLVED。`*(u32*)(g_doc+4)` 变成 1，B 返回 `DOC`」，
落盘脚本是 `work/12073s/chk.py`（gdb 观测）+ `exp5.py`（A 里塞 0/129/300 个 `<tag/>`，想靠 `xmlDict` 增长碰运气）。

**GM 本地复核（同一台机、同一份二进制、同一脚本）**：
```
== spray 0 names    A -> b'OK\n'   B -> b'ERR\n'
== spray 129 names  A -> b'OK\n'   B -> b'ERR\n'
== spray 300 names  A -> b'OK\n'   B -> b'ERR\n'
```
⇒ **`B` 仍回 `ERR`，门禁未被写入**。该"SOLVED"回报**无法复现**，按"不可复现即不成立"处理（与我方纪律一致：
flag/突破必须有可复现证据，见 `AGENTS.md`「提交纪律」）。

可能的误读来源：`chk.py` 同时打印 `*(u64*)g_doc`（doc 首 8 字节，正常就是 non-zero）与 `*(u32*)(g_doc+4)`，
在 gdb 里两者容易串行看错；且 `A` 结束后 `g_doc` 可能被再次分配、`+4` 读到的是**旧对象**的残留。

**结论不变**：本题的唯一缺口是 `*(PIE+0x60a4)=1` 的 4 字节定址写，且已用指令级普查 + 对齐分析 + 泄漏面逐条评估
证明它是 **leak-free 的定址写**问题（详见 §10–§13）。我方未解出。

---

### 9.11 ★ 解法：用 libxml2 dict 哈希表越界插入把 `g_doc+4` 写成 1（无泄漏）

**一句话**：`E` 把 0x500 快照缓冲 free 掉 → `A` 里 `xmlDictCreate()` 的 dict 结构体正好复用该地址、
它的 0x1000 哈希表紧贴在 `g_doc` 前面；`A` 的 validity 错误回调把 `dict->size` 从 0x80 加成 0x81；
于是 `index = hash % 0x81` 能取到越界的 128，而插入代码**硬编码 `entry->okey = 1`**，
`entry+0x14` 正是 `g_doc+4` ⇒ 门禁开。**写入的是常量 1，所以既不需要对齐、也不需要任何泄漏。**

**逐环证据（全部本地实证，附件自带 libxml2.so.2 上 disassemble + gdb 读内存）**

1. `E`（0x2fc8）对 `root2->children` 调 `xmlNodeSetContent`；该节点是 `S` 造的 fake TEXT 节点，
   所以走 TEXT 分支：`xmlFree(cur->content)` ⇒ **free 掉 0x500 'A' 缓冲**（实测 `FREE(0x…8a50)`）。
   0x510 > tcache 上限 0x410 ⇒ 进 **unsorted bin**。
2. `A`（0x31fd）里：`xmlDictCreate()`（0x3276）→ dict 结构体 `malloc(0x40)` **正好落在 0x…8a50**
   （原 'A 缓冲地址，实测 `dict@0x555555568a50`）；dict 的哈希表 `malloc(0x20*128=0x1000)` 从 top chunk
   拿到 `table=0x555555568ff0`（表 user 区末端 `0x…9ff0`）；随后 `malloc(0x420)`=buf420 切 unsorted
   （`0x…8aa0`），再 `malloc(0x420)`=**`g_doc=0x55555556a000`**（top chunk，**紧贴表尾**）。
   ⇒ `bucket[128]` = `table+0x1000` = `0x…9ff0` = **`g_doc` 的 chunk 头**，
   `bucket[128]+0x14` = `0x…a004` = **`g_doc+4`**。
3. `A` 装的错误回调 `FUN_3147` 条件是 **`err->code == 0x216`**。`0x216 = 534 = XML_DTD_UNKNOWN_ELEM`
   —— DTD 校验（`A` 的选项 0x817 含 `DTDVALID`）的**非致命 validity 错误**，不清 `wellFormed`。
   回调体：`*(u64*)(DAT_106098 + 0x10) += 1` —— `DAT_106098` 仍指着那个已被 dict 复用的地址
   ⇒ **`dict->size` 0x80 → 0x81**（实测 +0x10：0x80 → 0x81，`errflag=1`）。
4. `xmlDictLookup`（libxml2 0x13ee20）：`size==0x80` 走快路径（`key & 0x7f`，`+473 and r13d,0x7f`）；
   `size=0x81` 改走慢路径 `div r10` ⇒ `index = hash % size`，可取 **128**（越界一格）。
   插入路径两处都硬编码 okey：直接插入 `0x13f24d-0x13f258`：
   `[rax+0x8]=name; [rax+0x10]=len; [rax]=0; `**`[rax+0x14]=1`**`; [rax+0x18]=key`；
   链式插入 `0x13f14e-0x13f164` 同形。⇒ 落到 `g_doc` 头：`name` 写 g_doc 的 size 字段、
   `len` 写 `g_doc+0`、**`1` 写 `g_doc+4`**、`key` 写 `g_doc+8`。
5. 因为 `g_doc+4` 此刻是 0，该桶被判"空"⇒ 走直接插入路径（0x13f240），**不遍历假链、不崩**。

**实测（`work/12073s/chk.py`，gdb 读内存）**
```
## A before parse   g_doc=0x55555556a000  *(u32*)(g_doc+4)=0x0  dict size=0x80
## A at exit        g_doc=0x55555556a000  *(u32*)(g_doc+4)=0x1  dict size=0x81  errflag=1 stage=7
   bucket128 = 00…00 | name=0x55555556… | len=0x8 | **okey=0x1** | key=0x54a7458d…
程序回包:  A -> OK     **B -> "DOC "**      （门禁过，stage=8）
```

**exploit 形状**（`scripts/12073-solve.py`，可复现）
```
L / I / R / C / S / E                     -> OK
A '<!DOCTYPE q [<!ELEMENT q EMPTY>]><r>' + 129 个随机 <name/>
B '</r>'                                  -> 命中: DOC ；未命中: ERR（连接仍活但已无法再解析）
D <body>                                  -> 门禁已开，直通 broker.sock（归档链入口）
```
- 每个名字命中概率 1/129；129 个时 P(恰好一次)≈37%（实测 12 次单发命中 7 次 ≈58%），
  未命中**不崩**、可重连重试；≥2 次命中会崩掉**本条连接**（每连接独立 execve，重连即可）。
- 单发控量很重要：spray 200/300/500 实测崩率上升而命中率不升（≥2 次命中）。
- 命中后 `B` 的 `DOC` 同时证明 **XXE 实体加载器门禁也开了**（同一个 int）。

**为什么以前的"不可能"判断不冲突**：先前证明的是"**二进制里没有 `[reg+4]` 写指令**"与
"**malloc 对齐不允许对象落到 `g_doc+4`**"——两条都成立。门禁不是被程序自己的 store 写中的，
而是被 **libxml2 的 dict 哈希表越界插入** 写中的，写的是常量 1，所以两条约束都绕过了。

**给下一环**：门禁开后 `D` 直通 broker → manifestvault → keeper → oracle；
keeper 的 `AUDIT` 格式化串与 `COMMIT` 栈溢出（见 §4）此时才第一次变得可达。

## 十五 ★ 线上实测：门禁绕过成功（2026-10-24 13:55，靶机 <target>:28604）

```
$ python3 scripts/12073-solve.py <target> 28604
[-] attempt 1 missed (B -> b'ERR\n')
[+] gate open on attempt 2 (B -> b'DOC ')
[+] D reply: b'\n'
RESULT: gate opened, archive chain reachable
```

**判据链**：
1. `B` 从 `ERR\n` 变 **`DOC `** ⇒ `*(u32*)(g_doc+4)` 在**线上进程**里确实被写成 1（与本地 gdb 观测一致）；
2. 同一条连接里紧接着发 `D`，得到回包 `b'\n'` ⇒ **`D` 过了门禁、成功走到 `FUN_27fb`（connect `broker.sock`）并把内容转发**；
   （对比：门禁未过时 `D` 只回 `ERR\n`，连 broker 都不会碰。）
3. 单发命中率实测与本地一致（第 2 次尝试命中）。

⇒ **12073 的门禁关卡已被完全攻克**，剩余工作只有归档链本身（broker → manifestvault → keeper → oracle）。
本条与 `work/12073s/FINDINGS.md` §14 一起构成"从判死到打通"的完整证据链；
方法论教训见 §十四 与我方复盘 `notes/YCB2026-RETRO.md` §4.2b/§4.4。

---

# 10. 命令序列 + XML 负载机械化搜索：谁的写命中 0x60a4（`pwn-12073f`）

> **一句话**：用 gdb 硬件**写**监视点把"谁写了 `*(u32*)(g_doc+4)`"这个问题一网打尽 ——
> **500 条命令流，命中 0**。并且证明了"命令序列"这个搜索维度本来就只有 1 条可行链（+ P 的重复次数）。
> 但发现前两轮"线上 == 附件"的证明**从未覆盖到门禁**，给出 30 秒可裁决的靶机探针。

## 10.1 方法（与前两轮不同：不做交互、不读反编译，做机械搜索 + watchpoint）

产物全在 `work/12073f/`：

| 文件 | 作用 |
|---|---|
| `casegen.py` | 生成命令流（`[op:1][len:4 BE][body]`），50 条覆盖 A/B 拆分、P 刷、负载尺寸、非法序列 |
| `runner.py` | 每条流单独 `gdb -nx -batch` 起一个进程，解析命中/协议输出，写 JSONL |
| `gdbwatch2.py` | 早期把多条流塞进一个 gdb 会话的版本（有状态回收 bug，留档） |
| `out/p1.jsonl` `p2.jsonl` `p3.jsonl` | 逐条结果：`reached_A / g_doc / proto / hit_pcs / old_new` |
| `xb` | 附件 `xmlbridge` 的副本（patchelf 改 interpreter+rpath，只为本机跑；见 10.5 的坑） |
| `xb_g2` | 只把三处门禁 `83 f8 01`→`83 f8 00` 的副本（不打 patch 前缀串），用来验证"差 4 字节" |

**监视点设计（关键：两个，不是零个）**
- **W1** = `*(u32*)(g_doc+4)`：在 A 里 `call memset(g_doc,0,0x420)` 的**下一条指令 0x32ed** 处停住、
  读出 `g_doc = *(u64*)(PIE+0x60a0)`、布防、然后删掉断点继续。
  为什么不从进程开头就布？因为 A 之前 `g_doc==NULL`，那个地址还不存在；而 memset 一定会清 0，
  所以"有意义的写"只可能发生在 memset **之后**（A 的 parse 内 / B 的 parse 内 / D 之前）。
- **W2** = `g_doc` 指针自身 `*(u64*)(PIE+0x60a0)`（A 之后布防）。
  brief 里没人提这条路：**如果能改指针，让 g_doc 指向一块 +4 处为 1 的缓冲，同样过门**。
  实测 0 次写。
- `set disable-randomization on` + 每次 `starti` 重新取 PIE 基址（本机稳定 `0x555555554000`），
  所以监视点/断点地址绝对可靠；gdb 每次跑两条 `continue`，命中会带 `bt 8`。

## 10.2 一手复核：搜索空间本来就极小（不是"我没搜"）

1. **跳转表 @0x407c 我重新解了一遍**（19 项 4 字节相对偏移，基址 0x407c）：
   `A→0x37d4 B→0x37e9 C→0x377d D→0x381c E→0x37bf I→0x374d L→0x3735 P→0x37fe R→0x3765 S→0x37a1`，
   其余 9 项全指向 `0x3831: xor eax,eax; ret`。与 §9.5 一致。
2. **分派器对 op 的边界检查是无符号的**：`movzx eax,byte; sub eax,0x41; cmp eax,0x12; ja default`
   ⇒ `op < 'A'` 会回绕成巨大无符号数被 `ja` 拦住，**不存在负索引跳表/后门**。
3. **状态机严格线性**（逐条读 handler 的第一条比较）：
   `L:stage==0→1`、`I:1→2`、`R:2→3`、`C:3→4`、`S:4→5`、`E:5→6`、`A:6→7`、`B:7→8(成败都置 8)`、`D:8`。
   唯一"不推进 stage 还能重复调"的是 **P**（stage 5 或 6，返回 2 所以不打印 OK 也不停）。
   `C/S/P` 还要求 `len==0`（分派器先 `cmp [rbp-0x18],0; jne → return 0`）。
   ⇒ **"命令序列"这个搜索维度退化成一条链 + P 的次数**；真正可变的只有 5 个负载与堆布局。
4. 任一 handler `return 0` → 主循环打 `ERR\n` 并 **退出进程**（0x3ae8 分支）；
   `return 2` 才是"静默继续"（B 失败、D 成功、P 成功）。所以**失败后不能在同一连接里重试**。

## 10.3 结果：500 条流，0 命中

| 批次 | 条数 | reached_A | W1/W2 命中 | 备注 |
|---|---|---|---|---|
| p1（A/B 拆分、P 刷、L/I/R/E 形状、非法序列、after-B 追加） | 50 | 42 | **0** | 8 条被状态机挡在 A 之前（正常） |
| p2（P 次数 0..3 × 0..3 × R/E/A 边界尺寸 × L 尺寸） | 424 | 424 | **0** | 全部走完 A 与 B |
| p3（P 次数 5/8/12/16、A/B 到 0x10000、D 各种 len、实体/参数实体/外部 DTD） | 26 | 25 | **0** | |
| **合计** | **500** | **497** | **0** | |

所有 reached_A 的流，协议输出都是 `OK×7 + ERR + ERR`（B 被门禁挡、D 被门禁挡），**无一例外**。

**顺带得到的堆事实**：`g_doc` 的位置受堆布局控制，实测三种：
`0x555555584000`（P=0/1/…）、`0x555555584040`（P=2/4）、`0x555555583f70`（R 送满 0x80）。
但**恒 16 对齐** ⇒ `g_doc+4 ≡ 4 (mod 16)`，永远不可能是任何 `malloc` 返回值，
所以"让 libxml2 把一个 xmlNode 建在 `g_doc-4`、靠 `node->type=1` 命中 +4"这条（§9.5 候选 3）被对齐彻底排除 ——
与 0 命中互为印证。

## 10.4 ★ 缺口：本地==线上的等价性**从未覆盖到门禁**

前两轮的线上验证是"**A 送完整文档、B 再喂字节**"。而 B 在门禁 0x3482 **之前**还有两个失败分支：
`ctxt->myDoc==0`(0x3468) / `ctxt->wellFormed==0`(0x3472)。完整文档之后再喂字节 = extra content
⇒ `wellFormed=0` ⇒ **在门禁之前就 return 2 了**。所以线上看到 `B→ERR`、`D→ERR` 并不能证明
"线上 `*(g_doc+4)` 也是 0"：D 在"门禁不过"与"connect/read 失败"两处**都返回 0**。

我用本 harness 找到了**不需要拆文档**就能直达门禁的最小输入，并验证了"差 4 字节"：

```
L "<sheet><item/></sheet>"   I "<root><target/></root>"   R "hi"   C   S   E "wo"
A "<a>X</a>"                 B ""（空）
```
- 原版：`OK OK OK OK OK OK OK ERR ERR`
- 三处 `83 f8 01 → 83 f8 00`（`xb_g2`，文件偏移 0x348c / 0x2955 / 0x30eb，段 file==vaddr）：
  **`OK OK OK OK OK OK OK DOC X ERR`**

所以给靶机的**两个一次性探针**（ERR 会终结连接，各开新连接）：
1. 上面这条 → 回 `DOC X` 就说明**线上 gate 不是 0**（那整题当场通，与本轮 500 条本地结论并不矛盾：
   本地文件确实恒 0，线上可能是另一份构建/作者私下改过）；回 `ERR` 则"线上也恒 0"第一次被真正证明。
2. 若 1 给出 `DOC X`：`A = '<!DOCTYPE a [<!ENTITY e SYSTEM "file:///home/ctf/flag">]><a>&e;</a>'`、`B ""`
   → 回 `DOC FLAG{...}` 即拿旗；回 `DOC `（空）则见 10.6 的穿越/权限分支。

## 10.5 踩坑（别人别再踩）

- **`patchelf` 会打坏本二进制**：改 interpreter/rpath 后 `./xb` 能跑，但**打了门禁 patch 的那份
  （`xb_gate`）直接 SIGSEGV**；同样字节用附件自带 `./ld-linux-x86-64.so.2 --library-path . ./xb_g2`
  完全正常。⇒ 任何 patch 副本都**只用自带 loader 跑**，别 patchelf。
- `LD_LIBRARY_PATH=<附件目录>` 直接 export 会**毒死 `timeout`/`bash`/`gdb` 自身**
  （它们会去加载附件里的 Ubuntu 22.04 libc，报 `GLIBC_2.4x not found`）。要么走 `--library-path`，
  要么只在 inferior 环境里设（`set exec-wrapper env LD_LIBRARY_PATH=...` 也**不要用**：
  会把系统 ld 和附件 libc 混起来，`do_lookup_x` 直接段错误）。
- gdb 里**每条命令流单独一个会话**最省心；把多条流塞进一个 python 循环（`gdbwatch2.py`）
  时 `kill` → `continue` 会失败（"The program is not being run"），必须用 `run` 重启。

## 10.6 仍需线上裁决的两点

1. 线上 `*(u32*)(g_doc+4)` 到底是不是 0（探针 1）。
2. 实体加载器前缀 `strncmp(url,"file:///home/ctf/",17)` **有路径穿越余地**
   （`file:///home/ctf/../../../etc/hostname` 前缀合法，之后由原 loader 自己 open）。
   本地无法证明真实文件读：这台机没有 `/home/ctf` 目录，沙箱也不让建，
   所以 `file:///home/ctf/...` 的实体在我这里一律返回空（`DOC ` 空而不是 `ERR`，
   这个差异本身是可用判据：**门禁开但读不到 ⇒ `DOC ` 空；门禁关 ⇒ `ERR`**）。
   ⇒ 线上若探针 2 回 `DOC ` 空，立刻换 `file:///home/ctf/../ctf/flag`、`file:///home/ctf/../flag` 等写法。

**SKILLS**: none（本轮是机械搜索/调试工程，未加载技能；沿用 brief 第 0 节路由的
`competition-reverse-pwn` / `ctf-pwn` 已在前几节用过）

---

# 第四轮（14:00–14:30）：**oracle 端到端拿 flag 已在本地跑通**

## 1. 5 服务本地复刻（可无限次试验的测试床，不占容器）
把 5 个二进制的 socket 路径字符串**等长**改成相对路径（`s/b.sock`/`s/m.sock`/`s/k.sock`/`s/o.sock`）、
oracle 的 `/home/ctf/flag` 改成 `f/flag`，用附件自带 `ld-linux --library-path .` 起
`oracle/keeper/manifestvault/broker`（各 `fork` 每连接一个子进程）。另写 `mlog.py` 假扮 manifest 监听器。
xmlbridge 用补丁版 `xmlbridge_gate0`（三处 `cmp eax,1`→`cmp eax,0`）绕开门禁概率。

## 2. oracle 字节码 VM 拿 flag —— **本地实测成功**
```
HELLO
        -> b'O5 baf8ee7e13167117\n'
PROGRAM <80B>  -> b'LOADED\n'
RUN\n          -> b'\x00\x18flag{local_chain_probe}\n'     <=== 假 flag 原样吐出
```
5 条 16 字节指令（`{op:u8,a:i8,b:i8,pad,pad4,imm:u64 LE}`）：
```
02 00 .. imm=0x32              reg(0)=ctx[0x20]=0x32
03 fe ..                       ctx[0x10] ^= 0x32        (0xfe=-2 -> ctx+0x10)
02 00 .. imm=rotl(0x32,0x15)   reg(0)=0x6400000
03 ff ..                       ctx[0x18] ^= 0x6400000   (0xff=-1 -> ctx+0x18)
04 ..                          -> 通过防篡改校验，调 ctx[0x10] = &FUN_16b6
```
`FUN_16b6` = `read(ctx[0x36c]=flagfd) → write(ctx[0x368]=client)`。因为
`base+0x684 ^ 0x32 == base+0x6b6`（低位无进位），`seed^(A+0x32) = (seed^A)^0x32`，
所以所需的 `ctx[0x18]` 只需 `^= rotl(0x32,0x15)`，**完全不需要 PIE 基址**。
（注意 `PROGRAM ` 后必须是 16 的整数倍字节，指令第 4..7 字节是 padding。）

## 3. broker 全解（本地 17 步状态机实测全通）+ 两个原语
状态机：`OPEN`(→TICKET) `ARCHIVE` `NOTE` `VIEW` `RELEASE` `DRAFT` `NOTE/VIEW/RELEASE`×3
`NOTE` `WRITE` `COMMIT`（state 0→1→2…→17）。判据原文见 `work/12073/local_end2end.log`。
- **任意读**：`NOTE <note>HEX288</note>`（288 hex = 0x90 字节裸结构体：`+0x0 "RCPTv2"`, `+0x8` ticket,
  `+0x18`/`+0x20` tag, `+0x28` int64 off, `+0x30` u64 len），`VIEW` 回
  `"WINDOW " + *(u64*)(&FUN_1e0a + off)`，off∈[-0x7000,0x7000]。
  实测：`off=0x3196`→`.got` libc 地址；`off=0x320a`→`0x5014` manifest fd；`off=0x323e`→`0x5048` **PIE 基址**。
- **栈溢出**：`COMMIT` → `FUN_1efb(g_buf, note[0x30])` = `memcpy(栈 0x100, g_buf, ≤0x380)`，
  broker **无 canary** ⇒ 返回地址直控（偏移 0x108）。`WRITE <draft>HEX1792</draft>` 控 g_buf 全部 0x380 字节。
- **重要负结果**：broker **从不转发**给 manifestvault（假监听器 0 帧）。它把 manifest fd dup3 到
  `0x400+seed` 并存进 `.bss 0x5014` —— 是**留给 ROP 用的**。⇒ 四跳要各自打下来。

## 4. keeper / manifestvault（本地实测）
- keeper：`HELLO`→`K4 <16hex>`；**`AUDIT <fmt>`（body ≤0x46）是无鉴权的活格式化串**，
  `AUDIT ` + 8×`%016lx` 已泄出栈/指针值；`COMMIT <blob>` → `FUN_1960` 的 `memcpy(rbp-0x110, src, len≤0x300)`
  即 0x108 到 canary、0x118 到返回地址。`.bss 0x5010`=client fd、`0x5014`=oracle fd。
- manifestvault：`HELLO`→`MV3`；命令序 `MINT`(→`TICKET`) `INDEX` `DROP` `GLANCE`(→`TRACE x3`)
  `CORRECT` `LAYER` `TRIGGER`；实测 `MINT <MV3 token> 1` → **连接 reset（vault 崩）**，语法是
  `MINT <token> <arg>` 但 arg 形状未定。

## 5. 缺口
`broker ROP（用 0x5014 发 manifestvault 帧）→ 打 manifestvault → 打 keeper（AUDIT 泄 canary/PIE +
COMMIT 0x118 ROP 用 0x5014 发 oracle `PROGRAM`/`RUN`）→ oracle VM`。第 4 跳（oracle）已验证，
前 3 跳是"每跳一个独立 pwn"，剩余工作量大（≥1–2 小时），且 manifestvault 的语法尚未定型。

---

# 第五轮（14:05–14:25）：**HOP1→HOP2 通道打通（本地，用 broker 的 ROP）**

## 决定性结果
用 broker 的"任意读 + 无 canary 栈溢出"写出 ROP，成功把**自己发的帧送到 manifestvault 并把它
的回包原路转回客户端**（假 manifest 用 `mlog2.py`）：

```
mlog:   [m#1] FRAME(6) b'HELLO\n'                    <- broker 的 ROP 真的发到了下一跳
client: b'\x00\x10MV3 deadbeefcafe' + 栈残留         <- 下一跳的回包被 ROP 转回
broker stdout: b'XBRDGv3'                          <- 链跑到底的完成标记
```

## 复用模板（HOP2/HOP3 直接照抄）
1. 驱动状态机，在 state 3/7/10/13 的 4 次 `VIEW` 里各读一个 qword（一次会话刚好够）：
   `_exit@got` → libc base；`0x5048` → PIE base；`0x5014` → next-hop fd；
   `0x5010` → `(next_fd<<32)|client_fd`（**client fd 取低 32 位**）。
2. `NOTE`(PRIVATE/READY/len=0x380) + `WRITE`(0x380 hex) 灌 ROP，`COMMIT` 溢出（ret 偏移 **0x108**）。
3. 链：`read(client_fd,scratch,0x10)` → `write(next_fd,scratch,0x10)` →
   `read(next_fd,scratch2,0x100)` → `write(client_fd,scratch2,0x100)` → 完成标记。
   用 shipped `libc.so.6` 的 `pop rdi;ret`(0x2a3e5) / `pop rsi;ret`(0x2be51) / `pop rdx;pop rbx;ret`(0x90469)。
   scratch 用 PIE 末页空洞（如 `pie+0x5200`，`.bss` 只有 0x30 字节）。
   这台机器 CPU **没有 CET/SHSTK**（`grep shstk /proc/cpuinfo` = 0），ROP 不受影子栈影响。

## 剩余路线图（下次 30 分钟可接上）
- **HOP2 manifestvault**：命令序 `HELLO→MV3`、`MINT`(→TICKET) `INDEX` `DROP` `GLANCE`(→TRACE x3)
  `CORRECT` `LAYER` `TRIGGER`；`MINT <MV3 token> 1` 会把它打崩（说明 arg 形状进了危险分支）。
  用上面模板把 ROP 装进它（需要先定位它的溢出点/格式化串）。
- **HOP3 keeper**：`AUDIT <fmt>`（body≤0x46）是无鉴权格式化串 → 泄 canary/PIE/栈；
  `COMMIT <blob>` 的 `FUN_1960` = `memcpy(rbp-0x110, src, len≤0x300)` ⇒ canary@0x108、ret@0x118；
  `.bss 0x5014` = oracle fd。ROP 内容 = 发 `PROGRAM <80B>` + `RUN` 给 oracle，读回包转发。
- **HOP4 oracle**：**已验证**（5 条 16 字节指令 → `RUN` 直接吐出 `/home/ctf/flag` 内容）。

---

# 第六轮（14:20–14:35）：**经 broker ROP 与真 manifestvault 对话成功**

`work/12073_xmlbridge/hop.py`（参数 = 要发给下一跳的正文）：
```
$ python3 hop.py 'HELLO\n'
[+] libc=0x... pie=0x... mfd=0x1e1e cfd=0xa728
[+] REPLY: b'\x00\x15MV3 dd9988e1fb6085ae\n'      <- manifestvault 的 [u16 len][body] 被 ROP 原样转回
```
⇒ **HOP1→HOP2 通道 + HOP2 的帧格式/首条命令全部实测确认。**

manifestvault 语法（静态 + 实测）：
- `HELLO\n` → `[u16 0x15]"MV3 <16 hex>\n"`（MV3 = 本会话 seed）
- `MINT <16hex>\n`：**必须 22 字节且 body[0x15]=='\n'**（0x201f 判据）；16 hex 解码成 u64 后要与
  服务端 seed（与 `"MNFSTv3"` 相关）比较 ⇒ 只能用 HELLO 给出的 MV3 值（或由它派生）。
- `INDEX` / `DROP` / `GLANCE`(→`TRACE x3`) / `CORRECT` / `LAYER` / `TRIGGER` 随后；
  `LAYER` 分支有 `memcpy(堆, body+6, 0x120)`。
- 两往返版 `hop2.py`（一条 broker 会话连发多条命令）本次未跑通（无回包）——交接只需修链长/scratch
  偏移（每轮 read 0x30 是否够放 2B 头 + 22B 正文；第二个 scratch 是否越页）。

## 完整路线图（下次 30 分钟可接上）
1. `hop.py` 修成 `hop2.py`（多往返）→ 用 `MINT <MV3>` 拿到 TICKET，摸清 `INDEX/DROP/GLANCE/LAYER/TRIGGER`。
2. 找 manifestvault 的溢出/格式化串（`LAYER` 的 `memcpy(heap, body+6, 0x120)` 是最可疑的一处），
   用与 broker 相同的模板（泄漏 + 溢出 + 用缓存的 keeper fd）打通 HOP3。
3. keeper：`AUDIT <fmt>` 泄 canary/PIE（已验证活的格式化串）→ `COMMIT` 的 `memcpy(rbp-0x110, src, ≤0x300)`
   （canary@0x108、ret@0x118）→ ROP 用 `.bss 0x5014` 的 oracle fd 发 `PROGRAM`(80B)/`RUN`。
4. oracle：**已完成**（5 条 16 字节指令，`RUN` 直接吐出 flag 文件内容）。

## 第七轮补记（14:10–14:16）：两往返 ROP

`work/12073/hop2.py`（一条 broker 会话连发 2 条命令）已跑通，**关键坑**：
pwntools 的 `ELF + int` 返回 **ELF 相对地址**，gadget 必须写成 `q(libc_base + POP_RDI)`，否则落到裸偏移直接崩。

实测：
```
round1  HELLO\n  -> b'\x00\x15MV3 08a4ed39833f45a9\n'     （[u16 len][body]，body 可能分两次 write）
round2  MINT ..  -> b''（不答，但不崩）
```
`MINT` 的静态门禁（0x200f–0x20cb）：body[0x15] 必须是 `'\n'`（22 字节 `MINT <16hex>\n`），
16 hex 解码后要和服务端 seed（与 `"MNFSTv3"` 相关）配平（`seed ^ value` 后参与后续构造），
**HELLO 给的 MV3 明文并不等于该配平值** ⇒ 需要另找泄漏（manifestvault 也有 0x120 堆结构 + `TRACE` 回显，
可照 broker 的 VIEW 思路做任意读），或直接用 `LAYER` 的 `memcpy(heap, body+6, 0x120)` 溢出点。

### 交付清单（下次直接从这里接）
- `work/12073/local_end2end.log` —— 5 跳逐条回包原文（含 oracle 吐 flag）
- `work/12073/chain.log` —— 全量判据 + broker 状态机 + 原语 + ROP 模板 + 负结果
- `work/12073/{hop.py,hop2.py,chain.py}` —— 单/双往返的"经 broker ROP 打下一跳"工具
- `work/12073_xmlbridge/` —— 本地 5 服务复刻（`local/*`）、`mlog2.py` 假 manifest、`fc.py` 前端客户端、
  `drive_broker.py` 状态机驱动、`broker_hop2.py`/`hop*.py` 原型

### 附：manifestvault 全部命令语法（静态读定，下次可直接用）
所有命令都是 `[u16 BE len][body]`，且 body 末尾必须是 `\n`（各分支用 `body[N]=='\n'` 判定）：
```
HELLO\n           (6B)                    -> [u16 0x15]"MV3 <16hex>\n"
MINT  <16hex>\n   (body[0x15]=='\n')      -> "TICKET <16hex>"（值参与 seed 配平）
INDEX <16hex>\n                            -> "INDEXED\n"
DROP  <16hex>\n                            -> "DROPPED\n"
GLANCE<16hex>\n   (body[0x17]=='\n')      -> "TRACE %016lx %016lx %016lx\n"
                  取自 [ctx+0x30] 结构体的 [+0x20][+0x28][+0x30]  ⇒ **泄漏面**
CORRECT<16hex>\n                           -> "CORRECTED\n"
LAYER <0x120B>\n   0x2910: memcpy(堆, body+6, 0x120)  -> "LAYERED\n"   ⇒ 可控 0x120 字节堆结构
TRIGGER\n                                  -> ？（进 keeper 的入口，最可疑）
```
推测利用链：`MINT` 造头节点 → `LAYER` 往 0x120 结构灌可控数据 → `GLANCE` 打印 3 个 qword 做任意读
（同 broker 的 VIEW 思路）→ 然后找溢出点拿 ROP（`TRIGGER`/`LAYER` 附近）。

---

# 第八轮（14:20–14:38）：**捷径（broker → oracle.sock）本地跑通；线上只差 libc 版本**

## 本地：一条链直接拿 flag（跳过 manifestvault + keeper）
`work/12073_xmlbridge/shortcut2.py`：
```
[+] libc=… pie=… gbuf=… cfd=…
[+] 收到 512 字节
   HIT: b'LOADED'
   HIT: b'flag{local_chain_probe}'
```
ROP 设计（7 次调用，数据全放 `g_buf`，**不需要 read(client_fd)**，避免前端单线程死锁）：
```
socket(AF_UNIX=1, SOCK_STREAM=1, 0)                 -> fd 3（broker 子进程只有 0/1/2）
connect(3, g_buf /*sockaddr_un{AF_UNIX,".../oracle.sock"}*/, 0x6e)
write(3, g_buf+0x70, 90)     # [u16 0x58]"PROGRAM "+80 字节 VM 程序
write(3, g_buf+0xcc, 6)      # [u16 0x04]"RUN
"
read(3, B2, 0x100)           # 丢弃 [u16]"LOADED
"
read(3, B2, 0x100)           # 拿 [u16]"<flag>"
write(client_fd, B2, 0x100)  # 转给客户端（前端 D 会按 u32 长度再包一层）
```
⇒ **本题最少只需 1 个 pwn（broker）+ oracle 字节码 VM**，与 EASY/27 队解出吻合。

## 线上实测（<target>:28604）
- 门禁成功率高（`B=b'DOC '`），`OPEN→TICKET / ARCHIVE / NOTE / VIEW×4 / RELEASE / DRAFT / WRITE` 全部 1:1 复现；
- 四次 VIEW 泄漏正常，且 **libc=0x7faa07106000 / pie=0x55f436918000 跨连接完全不变 ⇒ 部署关了 ASLR**；
- `COMMIT` 后连接 EOF。
- **死因**：`_exit@got` 的泄漏值本身页对齐，而附件自带 libc 的 `_exit` 偏移是 `0xeabc0`
  ⇒ `leak-0xeabc0` 非页对齐 ⇒ **线上 broker 用的 libc 不是附件那份** ⇒ 我 ROP 里的 libc gadget 偏移全错 → 第一跳就崩。
- 下一步：用 VIEW 多读几个 GOT（write/memcmp/memset/memcpy/read/snprintf/ntohs）取低 12 位，
  在 libc 库里匹配版本；或改用 broker 自己的 PLT（write 0x12d4 / read 0x13e4 / socket 0x12b0 / connect 0x1350，PIE 已泄）+ 匹配后的 pop rdi/rsi/rdx。

### 第八轮补充：线上 libc 判定（捷径的唯一阻塞，已量化）
候选 libc 的符号偏移：
| libc | _exit | write | read | snprintf |
|---|---|---|---|---|
| 附件自带（Ubuntu 22.04 / 2.35） | 0xeabc0 | 0x1149c0 | 0x114920 | 0x607c0 |
| 本机系统（较新 glibc） | 0xf7180 | 0x128c10 | 0x128150 | 0x6a730 |

线上泄漏 `_exit@GOT = 0x7faa07106000`（**页对齐**，ASLR 关闭、跨连接稳定）。
用任一候选偏移求基址都**不是页对齐**（`…1a440` / `…0ee80`）⇒ **线上跑的 libc 既不是附件那份、也不是本机这份**
（注：broker 自身的 pie/gbuf 布局与附件一致，所以是"另一版 glibc"而非另一份 binary）。

**下一步只有 10 分钟工作量**：再用 VIEW 读 4 个 GOT（`0x4f00 write / 0x4f88 read / 0x4f98 snprintf / 0x4f38 memcpy`），
用符号间的**低 12 位相对关系**（不依赖基址）定版本，然后替换 `shortcut2.py` 里三个 gadget 偏移即可。
备选：完全绕开 libc，用 broker 自己的 PLT（`write 0x12d4 / read 0x13e4 / socket 0x12b0 / connect 0x1350`，
PIE 已泄漏）+ 在 binary 内找/构造 `pop rdi`（目前只找到 `pop rsi` 0x1489，可用 `leave;ret` 栈迁移后
借用 broker 里"从结构体取参"的代码片段）。

### 第九轮（14:40–14:55）：线上 libc 定死、ROP 可执行、捷径被 seccomp 挡住

**(1) 线上 libc = 附件那份（glibc 2.35 / Ubuntu 22.04）**，用 4 个 GOT 泄漏的**相对差**判定（不依赖基址）：
```
write@0x4f00   = 0x7faa0721a9c0
read@0x4f88    = 0x7faa0721a920      write-read     = 0xa0     （附件 0x1149c0-0x114920 = 0xa0 ✓）
snprintf@0x4f98= 0x7faa071667c0      write-snprintf = 0xb4200  （附件 0x1149c0-0x607c0 = 0xb4200 ✓）
```
⇒ `libc_base = write@got - 0x1149c0 = 0x7faa07106000`（**ASLR 关闭**：libc/pie/g_buf 跨连接完全不变）。
（`memcpy@0x4f38` 对不上是正常的：memcpy 是 IFUNC，GOT 里是 `__memcpy_avx_*` 实现地址。）
⚠ 我之前用 `_exit@0x4fa0` 当基准是错的（那个槽位的值恰好等于 libc base），导致第一版捷径崩。

**(2) 线上 broker 的 ROP 确认可执行**：极简链 `write(client_fd, g_buf, 5)`，g_buf 放 `\x00\x03XYZ`
⇒ 线上回 `COMMIT DOC b'XYZ'`。证明溢出偏移 0x108 / gadget 偏移 / client fd 全对。

**(3) 捷径被沙箱挡住**：任何包含 `socket()`/`connect()` 的链都让连接**立刻 EOF**，而纯 `write` 链正常。
⇒ **broker 的 seccomp 挡掉了 socket/connect**（作者预判了"直接连下一跳"的捷径），
本地能跑通是因为本地没装同一份 seccomp。
⇒ 必须回到 4 跳链：`broker → manifestvault → keeper → oracle`（HOP2/HOP3 payload 已在前面章节备好，
HOP4 已验证）。

**给下一次的 30 分钟接续清单**
1. `work/12073/gleak.py`（改 3 行即可）→ 拿 manifestvault 的泄漏；
2. 按 `chain.log` 的 broker 模板写 manifestvault 的 ROP（其 next-hop fd 同样在 .bss，静态已见）；
3. keeper：`AUDIT <fmt>` 泄 canary/PIE → `COMMIT` 溢出（canary@0x108 / ret@0x118）→ 用 `.bss 0x5014` 的 oracle fd；
4. oracle：`shortcut2.py` 里的 5 条 16 字节 VM 程序直接复用（`PROGRAM` 必须 16 的倍数、4..7 字节 padding）。

### 第十轮（14:45–15:00）：捷径在线上被沙箱堵死（对照实验定因）

同一会话、只改一处 ROP 的对照实验：
| 链 | 结果 |
|---|---|
| `write(client_fd, g_buf, 5)`（g_buf=`\x00\x03XYZ`） | **`COMMIT DOC b'XYZ'`** ✅ ROP 生效 |
| `socket(AF_UNIX,SOCK_STREAM,0)` + `write(client_fd,marker,5)` | **EOF（进程死）** |
| `socket + connect + write(3,PROGRAM) + write(client_fd,marker)` | EOF |
| 完整捷径（socket+connect+PROGRAM+RUN+read×2+写回） | EOF |

⇒ **broker 里一旦调用 `socket()` 进程就被杀**，而纯 libc `write/read` 完全正常。
附件里 broker 的 seccomp 静态解码显示 41/42 未被拦（拦的是 59/322/2/257/437/40/275/278/326），
说明**线上部署的沙箱比附件二进制里那层更严**（或加装了一层 filter）——作者预判并堵死了"直连下一跳"。

**结论：捷径不可行，必须走 4 跳链。** 但链上每一环的关键机制都已被实测/静态定死：
1. 前端门禁（`B→DOC`）与 `D` 转发 ✅ 线上验证
2. broker：任意读（`_exit@0x4fa0` 那个槽位恰好等于 libc base，正确公式是 `write@got - 0x1149c0`）、
   `COMMIT` 溢出 ret@0x108、ROP 线上可执行 ✅
3. keeper：`AUDIT <fmt>`（body≤0x46）无鉴权格式化串 ✅；`COMMIT` 的 `memcpy(rbp-0x110, src, len≤0x300)`
   （canary@0x108 / ret@0x118）✅；`.bss 0x5014` = oracle fd
4. oracle：5 条 16 字节 VM 字节码（`PROGRAM` 必须 16 的倍数、第 4..7 字节 padding）✅ 本地端到端出 flag

### 第十一轮（14:27–14:40）：`TRIGGER` 不是透传口（实测 + 静态双证）

经 broker 的 ROP 把命令直接发到 manifest fd（本地复刻）：
```
'TRIGGER\n' -> b'\x00\x04ERR\n'        （ERR，不转发、不 reset）
'HELLO\n'   -> b'\x00\x15MV3 <16hex>\n'（对照，正常）
```
静态看 `0x29a0` 的 TRIGGER 分支：它会用 `.bss` 里的 seed/指针算校验值，并要求
`[0x5020]=="MNFSTv3"`、`[0x5028]==3`、`[0x5030]==&FUN_1b46`（**函数指针硬校验**），
通过后才调用该函数指针——和 oracle 的 opcode4、broker 的 `0x5048=&FUN_1e0a` 是同一套"防篡改守卫"。
⇒ **TRIGGER 是 tripwire，不是"转发到 keeper"**。所以"沿已建好的 fd 越过 manifestvault"不成立：
每个服务都把 next-hop fd 缓存在 `.bss`，只有拿到 ROP 才能用 ⇒ **4 个独立 pwn + oracle 的 VM 洞**。

