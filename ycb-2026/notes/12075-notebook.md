# 12075 · notebook（PWN / HARD / 500 分 / 0 解）

## 交接摘要（先读这一节就够）
- **结论一句话**：这是 **Linux 内核 PWN**（不是 web）。`/dev/note` 内核 misc 设备（0666），ioctl 请求体固定
  `{u32 idx,f1,len,f2; u8 data[0xF8]}`。已定位到**真实可利用的 UAF 读+写**并本地 PoC 证实；
  但**必须先跑通模块自带的"解锁协议"才能建 channel**，该协议需要复刻模块内置 VM，属数小时实现型工量，
  本场因时间不足**未解出**（未提交 flag，提交额度 0/50 未动）。
- **已证实的 UAF**：`cmd 0x41086e0e`（seal 复制）在 `.text+0xd44` 只写 `holder[0]=new`，却把旧 seal
  `kmem_cache_free`，**holder[1] 变成悬垂指针**；而 seal 读写（`0xc1086e0f` / `0x41086e10`）都走 holder[1]
  ⇒ 对已被新对象复用的 0x100 块 `+0x20` 处有 **0x28 字节 UAF 读/写**。本地实测：
  dup slot0 后 `read_seal(0)` 返回 slot1 的数据、`write_seal(0,'C')` 改写 slot1 的对象。
  可复用对象：note_control={seal type0, gate}、note_seal={seal type1, seal4}（见 §4）。
- **卡点（唯一）**：`cmd 0x27` 的 4 轮 key schedule 需要 `loom+0x100/0x108/0x110/0x118` 四个**随机** qword，
  唯一泄漏途径是 `cmd 0xc1086e26` 返回值里 XOR 进去的 `*(u64*)(loom+uVar16)`，而 uVar16 由模块内置
  32/64 位小 VM 决定 ⇒ 需先用 Python 复刻 `FUN_00100090` / `FUN_00100140` / `FUN_00100420`，
  再用 `cmd 0x25` 里自由的 imm32 搜索，把四个 slot 的 uVar16 分别调到上述偏移（§9 有内建程序表，
  §10 有 0x27 的逐条公式与后续 UAF→ROP 步骤）。
- **产出文件**（都可直接接手）：
  - `notes/12075-notebook.md`（本文件：协议表、priv 布局、对象图、漏洞、全部派生公式、VM 程序表、利用计划）
  - `work/12075_notebook/poc.c`（UAF PoC 源码，头注释有编译+复现命令）
  - `work/12075_notebook/drive.py`（本地 qemu guest 驱动：起停 + 跑命令）
  - `work/12075_notebook/pack.py`（无 cpio 二进制时的 initramfs 重打包）
  - `work/12075_notebook/p/player/{dis/*.asm, decompiled/note.ko_.c}`（反汇编/反编译）
  - 原始附件：`firmware/12075_notebook/notebook的附件.zip`

## 0. 题目与附件
- 平台：ycb-bk.dasctf.com，`endpointType=monopoly`（**需要靶机容器**，每次连接新起 guest）
- 附件（`firmware/12075_notebook/notebook的附件.zip` 62MB，内层 `notebook-附件.zip`）：
  `bzImage`(6.6.74) / `vmlinux`(130MB，带符号) / `System.map` / `initramfs.cpio.gz` / `note.ko`(34KB, 未 strip 但静态函数无名)
- `player/description.txt`：Linux kernel PWN；每次连接起新 guest；flag 在 guest 里（initramfs 本身 flag-free）
- 本地解包产物：`work/12075_notebook/p/player/{rootfs,dis,decompiled}`

## 1. 运行环境
- `/init`：mount proc/sys/devtmpfs → `insmod /note.ko` → `modules_disabled=1` → `exec /bin/su -s /bin/sh ctf`
  ⇒ 落到 uid 1000 `ctf`；不能加载模块。`/dev/note` 由 misc_register 建，mode **0666**。
- 本地跑通：`work/12075_notebook/drive.py`（qemu-system-x86_64 TCG，2s 级启动，prompt `/ $`）
  + `work/12075_notebook/pack.py`（无 cpio 二进制时的 newc cpio 重打包）
  启动参数（本地）：`-m 256M -kernel bzImage -initrd initramfs.cpio.gz -append "console=ttyS0 oops=panic panic=1 kaslr" -cpu kvm64,+smep,+smap`
- 信息泄漏检查（本地 guest 实测）：`kptr_restrict=0` 但 ctf 无 CAP_SYSLOG ⇒ `/proc/kallsyms` 全 0；
  `/sys/module/note/sections/*` 为 `-r-------- root` ⇒ 拿不到模块基址。必须靠模块自身 leak。

## 2. ioctl 协议
```c
struct req { u32 idx; u32 f1; u32 len; u32 f2; u8 data[0x100]; };  // 固定 copy 0x108 字节
// 全局约束：len <= 0xF8
// cmd = _IOW('n',nr,8)=0x41086eNN 或 _IOR('n',nr,8)=0xc1086eNN
```
主要命令（已逐个从反汇编确认）：

| cmd | 语义 | 关键校验 |
|---|---|---|
| 0x01 | 建 control 对象（kmalloc 0x80）到 priv+0x20[idx], idx<0x40 | len<0x69 |
| 0x02 | control 对象加引用+槽位复制 | 目标槽空 |
| 0x03 | 释放槽位（refcount--，到 1 时 kfree） | |
| 0xc1086e04 | 读 control 数据（+8 起） | len ≤ 0x68 |
| 0x05 | 写 control 数据 | len ≤ 0x40 |
| 0x06 | 建 drive（kmalloc 0x80 hdr + kmalloc 0xf8 buf） | 槽空 |
| 0xc1086e07 / 0x08 | 读写 drive buf | len ≤ hdr[8]=0x90 |
| 0x09 | 在 drive buf+0x90 建 journal（size 0x40），并 mallocs piece(0x180) | 槽空、buf+0x90 空 |
| 0x0a | 把 journal->size(=0x40) 字节从 user 写进 piece+0x40 | len ≥ size |
| 0xc1086e0b / 0c | 读 piece(+0xd0) | piece+0xcc!=0 |
| **0xc1086e22** | **session 派生**：返回 {local180,local178,drive+0x20,local168} 并写 priv+0xa20..0xa38 | 需 drive+journal+piece |
| 0x0d | 建 seal（0x100 cache，type0→note_control，type1→note_seal），data@+0x20，holder kmalloc 0x20 | idx<0x10, len≤0x28, type≤1 |
| **0x0e** | **seal 复制**：alloc 新 seal(copy)，refcount++，**free 旧 seal**，holder[0]=新 —— 但 **holder[1] 仍指向被 free 的旧 seal（UAF）** | |
| 0xc1086e0f | 读 seal（走 **holder[1]**，+0x20） | len ≤ 对象[+8] |
| 0x10 | 写 seal（走 **holder[1]**，+0x20） | len ≤ 0x28 且 ≤ 对象[+8] |
| 0x13 / 0x14 | 建/复制 route(0x200 note_frame cache + holder 0x18)，cookie=rand | |
| 0xc1086e15 / 0x16 | 读写 route data(+0x20, ≤0xF8) | |
| **0x11** | 建 channel(0x100 note_channel) 到 priv+0x8a0[idx], idx<8 | **需要 loom 解锁** + priv[2]==data[0] + priv[0x149]==data[1] |
| **0x17** | 建 frame(0x200) + 4×shard(0x58)：校验 `rol29(priv2^chan[0x38]^route[2])^0xa7e35c819b04d26f == data[1]`；成功后 chan[0x50]=frame, chan[0x28]=frame+0x20, chan[0x48]/chan[0x30]=MAC | frame 槽空 |
| **0xc1086e1c** | **泄 `route[2] ^ chan[0x38]`**（`(v<<19|v>>45)^0xc681f7b23a49d50e`）⇒ 这正是 0x17 需要的未知量！ | |
| 0x19 | 建 gate(0x100 note_control) 到 priv+0x8e0[idx]：快照 chan[4..8]；gate+8=0x28, **gate+0xc=1(refcount)** , tag "NLGATE13" | 需 channel、type0 seal 已 dup（holder0!=holder1） |
| 0x1a / 0x1b | gate 刷新 / **commit：chan[0x20]=gate[4]; gate[0xc]=2** | gate refcount==1 |
| 0x1f | 建 seal4(0x100 note_seal) 到 priv+0x920：seal4[4]=chan[0x30], [5]=chan[0x28], [6]=rol(priv0)^chan[0x50], [9]=route holder, [10]=holder[2] | 需 channel+gate+type1 seal 已 dup |
| 0x20 / **0x21** | seal4 刷新 / **commit：chan[0x30]=seal4[4]; seal4[0xc]=2** | gate refcount==2, seal4 refcount==1 |
| 0x1d | 写 shard（+0x18 起 0x40 字节，shard[1] 必须等于 user data[0]） | frame refcount==0 |
| 0x1e | frame 封存：把 4 个 shard 的 +0x18.. 共 25 qword 拼到 frame+0x20..+0xe8，重算 chan[0x30]=MAC，frame[0xc]=1 | |
| **0x12** | **执行**：校验 channel/frame/gate/seal4 全套 tag+MAC，然后 `pcVar19 = rbx ^ chan[0x20]`（`>>0x30==0xffff`）→ **`pcVar19(rdi=chan)`** | gate[0xc]==2, seal4[0xc]==2, priv[2]==data[0] |
| 0x23 | 建 loom(kmalloc 0x250)：+0..0x100 rand×32, +0x100..0x120 rand×4, +0x120 tag "NLLOOM51", +0x128/+0x130 rand | priv[0xa47]!=0, priv[0xa40]==0 |
| 0xc1086e24 | 读 loom+0x128 / loom+0x130 | |
| 0x25 | 装载 loom 程序（0x40 字节）到 loom+0x148+idx*0x40，idx<4；程序前 4 字节/8 字节必须逐字节匹配模块内建表；随后 VM 校验 | len==0x40 |
| 0xc1086e26 | 运行程序派生 key，返回 8 字节（含 `*(u64*)(loom+uVar16)`, uVar16<0x119） | 0x248 位已置 |
| **0x27** | **解锁**：0x24c==0xf 后，4 轮 key schedule（表=loom+0x100/0x108/0x110/0x118 四个随机 qword）比对 data[0]/data[1]；成功⇒priv[0xa50]=1, loom+0x138=priv[0], loom+0x140=priv[0x144], priv[0xa48]=派生值 | |

## 3. priv（per-open，kmalloc 0xa58，GFP_KERNEL|__GFP_ZERO）
```
+0x000 priv[0]=rand          +0x008 priv[1]=rand
+0x010 priv[2]=rol23(priv[0]^priv^&miscdevice^0x6db449a76f3a16c5)
+0x020..0x220  64× control 对象
+0x220..0x420  64× drive hdr
+0x420..0x620  64× journal 指针（= drive buf+0x90，**close 时被 kfree 的“内部指针”**）
+0x620..0x820  64× piece
+0x820..0x8a0  16× seal holder（{obj, obj2, gen, type}）
+0x8a0..0x8e0  8× channel
+0x8e0..0x920  8× gate
+0x920..0x960  8× seal4
+0x960..0x9e0  16× route holder（{obj,obj,gen}）
+0x9e0..0xa20  8× frame
+0xa20 priv[0x144]  +0xa28 +0xa30(journal idx) +0xa34(drive idx) +0xa38=1(0x147)
+0xa40 loom         +0xa48 priv[0x149]  +0xa50=1(0x14a)
```

## 4. 漏洞（已本地 PoC 证实）
**`0x0e` seal 复制的释放/指针不一致 ⇒ UAF 读+写**
- `.text+0xd44`：`holder[0]=new`（只此一句；对照 route 复制 `.text+0x23ca/0x23ce` 是 [0]、[1] 都更新），旧 seal 已被 `kmem_cache_free`；
- seal 读写(0x0F/0x10)都通过 `holder[1]` ⇒ 对“已 free 且已被新对象复用”的 0x100 块，`+0x20` 处 **0x28 字节 UAF 读/写**；
- 同 cache 复用对象：note_control = {seal type0, gate}；note_seal = {seal type1, seal4}。
- PoC `work/12075_notebook/poc.c`（本地 guest 实测）：dup slot0 后新建 slot1 的 seal，
  `read_seal(0)` 返回 slot1 的数据（`42…`），`write_seal(0,'C')` 改写了 slot1 的对象 ⇒ UAF 成立。

## 5. 关键派生公式（从 asm 逐条确认）
- open：`priv[2] = ROL23(priv[0] ^ priv ^ (u64)&miscdevice ^ 0x6db449a76f3a16c5)`
- 0x06 建 drive：`drive[0x18] = (u64)priv ^ (u64)&miscdevice`，`drive[0x20]=rand`，`drive[0x70]=buf`
- 0x09 建 journal：`journal[0x10] = drive[0x18] ^ priv[0]`（= priv ^ &miscdev ^ priv0），piece[0x10]=journal[0x10]
- **0xc1086e22 返回 4 个 qword：{A=180_final, B=178_final, drive[0x20], D=168}**，其 4/8 轮 schedule 可逆（t_i 只用 piece+0x40 与 drive+0x20 计算）⇒
  `journal10 = 178_init - ROR13(drive20)`，`drive18 = 180_init ^ ROL17(drive20)`
  ⇒`priv2 = ROL23(journal10 ^ 0x6db449a76f3a16c5)`，`priv0 = journal10 ^ drive18`
  ⇒`priv[0x144] = ROL27( ROR11(journal10) ^ (drive20 ^ piece40) ^ drive18 ^ 0x27e49a1cb6835fd0 )`
- 0xc1086e1c：`v = route[2] ^ chan[0x38]`，返回 `ROL19(v) ^ 0xc681f7b23a49d50e`
- 0x17 的 data[1] = `ROL29(priv2 ^ v) ^ 0xa7e35c819b04d26f`
- gate（0x19）：`gate[4..8] = {chan[0x20], chan[0x38], chan[0x40], ROL9(priv0)^chan, chan[0x18]^priv[0x144]}`
  ⇒ UAF 读 gate 得 `chan[0x40]=&get_random_u64`（**内核文本泄漏**，32 位符号扩展）、`chan`（heap）、以及
  `rbx = ROL29(priv0 ^ chan ^ priv2 ^ chan[0x38])`，`fn = gate[4] ^ rbx` ⇒ **模块 .text 基址**（fn = .text+0x760）
- MAC：`FUN_00100720(chan, frame, rbx)` 覆盖 chan[0x20]；因此“先改 chan[0x20]（经 0x1b），再建 frame(0x17) 重算 MAC”可让伪造的函数指针通过校验
- 0x12 调用点：`rdi=chan`, `rsi=frame`, `rbx=target`，目标须满足 `target>>0x30==0xffff`

## 6. 利用计划（未完成部分）
1. session（0x06/0x09/0x0a/0xc1086e22）→ 反解出 priv0 / priv2 / priv[0x144]（公式见 §5）
2. loom 协议：0x23 → 0xc1086e24 → 0x25×4（用模块 .rodata 内建程序）→ 0xc1086e26×4（每跑一次可反解 loom+0x100+8i 一个随机 qword，因为返回值里 XOR 进 `*(u64*)(loom+uVar16)`）→ 0x27 解锁
3. 0xc1086e1c 拿 `route[2]^chan[0x38]`；0x11 建 channel；0x13 建 route；0x0d(type0)+0x0e 制造 UAF；0x19 建 gate（复用被 free 的 seal 块）→ **UAF 读 gate[4..8] 泄漏内核文本/堆/模块基址** → 0x10 UAF 写 gate[4]=rbx^target → 0x1b commit → 0x17 建 frame（MAC 重算）
4. 0x1d×4 写 shard（把 ROP 链放进 frame+0x20，长度 0xc8）、0x1e 封存；type1 seal + 0x0e UAF；0x1f 建 seal4（复用被 free 的 type1 seal）→ UAF 读 seal4[5]=chan[0x28]=frame+0x20（ROP 链地址）
5. 0x21 使 seal4 计数=2；0x12 触发 → `target(chan)`；target 选**栈枢轴 gadget**（如 `mov rsp,[rdi+0x28]`），rsp 落到 frame+0x20 的 ROP 链：
   `commit_creds(prepare_kernel_cred(0))` → `swapgs_restore_regs_and_return_to_usermode` + 伪造 iret 帧回到用户态读 /flag

## 7. 已排除 / 注意
- 全局 `len<=0xF8` 上限把所有 memcpy 型越界都堵死；各 handler 的长度检查与对象大小逐一核对过（都刚好贴合）。
- `close()` 里第 3 个循环对 journal 指针（=drive buf+0x90，**内部指针**）做 `kfree` → 非法 free，
  但 kmalloc-256 上只有 drive buf，利用价值低，暂列备用路线。
- gate/seal4/channel 的 +0xc “refcount” 其实是 `+8 = 0x100000028/0x100000050` 那个 qword 的高 32 位（=1），不是单独的初始化。
- 无 KASLR 需求：0x12 的 `chan[0x40] == &get_random_u64` 两侧都用 32S 重定位，KASLR 下也一致。

## 8. 状态
- 已本地证实：UAF 读/写（poc.c）；guest 起停、initramfs 重打包、qemu 驱动脚本可用。
- 未完成：loom/VM 与 0x25/0x26/0x27 的离线实现（含内建程序表定位）、0x12 之前的完整对象链、ROP（枢轴 gadget 选取）。**尚未提交 flag**。
## 9. 内建程序表（cmd 0x25 用）—— 已定位
比较逻辑（`.text+0x2a2a`）：`base = .rodata+0x140 + idx*0x20`；把用户 0x40 字节里每条 8 字节指令的**低 4 字节**
（opcode/dst/src/shift）与表中连续 4 字节逐一比较；**高 4 字节 imm32 用户可自由填**（用于驱动 VM）。

entry0: 07010001 00020003 0b000302 11030004 09000205 05020006 0d000107 17010001
entry1: 09030102 06000105 00010203 1d020104 0f010307 07030106 15010001 1b000102
entry2: 0b010009 00020008 00000203 25030004 05000105 11010307 09020006 1f010201
entry3: 07000305 0d030109 00020108 0b010206 13020007 2b000104 00010303 19010302

T 表（cmd 0xc1086e22 用，`.rodata+0x1c0`，8×u64）：
  0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89, 0x452821e638d01377, 0xbe5466cf34e90c6c, 0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917
轮常量表（cmd 0xc1086e26 用，`.rodata+0x38` 起；`.rodata+0x00..0x20` 另 4×u64）：
  .rodata+0x00: 0xd6e8feb86659fd93, 0xa24baed4963ee407, 0x9fb21c651e98df25, 0xc6bc279692b5cc83
  .rodata+0x20..: fops/misc 区（非数据表）

## 10. 交接（下一步最小工作集）
1. **VM**：按 `decompiled/note.ko_.c` 里 `FUN_00100090`（loom 密钥派生，输入 loom+0x128/0x130 → 4×u32）、
   `FUN_00100140`（32 位 VM，opcode 1..9：1 add+rol / 2 xor+ror / 3 xor*mul / 4 add+rol+xor / 5 add+(xor*mul) /
   6 add+xor+(or*1) / 7 ror+add+xor*mul / 8 条件交换(写 swap 位) / 9 rol+add+xor）与 `FUN_00100420`（64 位版，同样 opcode）
   用 Python 复刻；每条指令 8 字节 {op,dst,src,shift,imm32}。
2. **0x25**：8 条指令的低 4 字节必须等于 §9 表的对应 entry，**imm32 自选**（用来把 VM 返回值调到想要的 loom 偏移）。
   约束：`FUN_00100140(...) <= 0xF8`；idx<2 时 swap 位必须为 0，idx>=2 时必须为 `1<<(idx-1)`。
3. **0x26**：返回 8 字节里 XOR 了 `*(u64*)(loom+uVar16)`（`uVar16 = FUN_00100420(...) & 0x1ff` 且须 <0x119）；
   只要能让四个 slot 的 uVar16 分别命中 **0x100/0x108/0x110/0x118**，即可反解出 §2 中 0x27 需要的 4 个 loom 随机 qword。
4. **0x27**：4 轮（asm `.text+0x1b41`）：
   ```
   u18 = loom[0x128]^priv0^0x8642f5d39a71c0be ; u20 = priv[0x144]^loom[0x130]^0x19ac73e6d4528fb1
   for i in 0..3:
       t = loom[0x100+8*i]
       u18 = ROL(u18 + k*t, 11+5*i)                 # k = 0x9e3779b185ebca87 + 2*i
       u20 = (u20 ^ (ROL(t, 17+3*i) + u18)) * (k + 0x38b18506e06e330c)
       u18 = ROR(u20, 7+i) ^ u18
   # 校验 data[0]==u18, data[1]==u20；成功后 priv[0x14a]=1, loom[0x138]=priv0, loom[0x140]=priv[0x144],
   # priv[0x149] = u20 + priv0 ^ ROL23(loom[0x128] ^ priv2 ^ u18) ^ 0x5e7394c2a18bd60f
   ```
5. 之后按 §6 顺序打；0x12 的 target 建议内核里找 `mov rsp, [rdi+0x28]` 类枢轴（rdi=chan，chan[0x28]=frame+0x20=ROP 链地址）。
6. 本地迭代命令：`source ~/re-tools/fw-env.sh; cd work/12075_notebook; GUEST_INITRD=initramfs_poc.cpio.gz python3 drive.py "/poc"`；
   重打包：`cp <bin> p/player/rootfs/ && python3 pack.py p/player/rootfs p/player/initramfs_poc.cpio.gz`。
7. 靶机到位后：单连接、限流 30–60s 自愈，base64 上传静态 exp（约 800KB static，串口较慢，可 `gcc -Os -static -s` 压缩，或改用 uclibc/musl 静态）。
