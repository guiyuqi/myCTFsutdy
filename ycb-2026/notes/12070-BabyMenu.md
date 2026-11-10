# 12070 · BabyMenu — Windows 11 自定义驱动提权（2026 羊城杯 / DASCTF）

- **分类**: PWN (Windows kernel LPE, 自定义驱动) / HARD / 500 分 / 平台解出 0 次
- **flag**: 未取得（见 §5「为什么拿不到 flag」——本题 flag 由运维人工发放，本地镜像里是占位符）
- **提交**: NOT_ATTEMPTED（不猜写法；`endpointType=monopoly`、`endpoints=[]`、`isNeedCheck=false`）
- **工具**: Ghidra 12.1.3 headless(`fw-decompile`)、objdump、lief、sleuthkit(`mmls/fls/icat`)、自写 regf 解析器、pdftotext
- **SKILLS**: `competition-reverse-pwn`, `ctf-pwn`, `ghidra-reverse`
- **SKILLS_USED**:
  - `competition-reverse-pwn`：**先把"可控字节 / 图元 / 目标对象 / 最终产物"分开记录**——因此把"0x20 越界写"与"最终提权"分成两栏证据，避免把"能写坏邻居"当成"已提权"。
  - `ctf-pwn`：kernel 章 + Windows 提权判据（`Privileges.Present & Enabled` 双重位域、SMEP/SMAP、KASLR）——直接用上"仅改 `Enabled` 在 1607+ 已失效，必须同时压 `Present`"这条判据，废掉了单次任意减一的方案。
  - `ghidra-reverse`：headless 反编译 + 用 **导入表反查**（`ExAllocatePool2`/`ProbeForRead`/`memmove` 语义）确定 w 型 IOCTL 分发，而不是靠字符串猜。
- **产出**: `work/12070_babymenu/`（分析、PoC、exploit 骨架、参考论文）、`scripts/12070-analyze.py`（可复现分析器）

---

## 1. 题目原貌（回源，2026-10-24）

`python3 scripts/ycb.py detail 12070` 原文（`work/ch_12070/detail.json`）：

```
name: BabyMenu    difficulty: HARD    score: 初始/当前/解出 均为 500（已答出 0 次）
description: 听说你是内核高手？（比赛结束前10分钟停止受理新的flag获取请求）
endpointType: monopoly     isNeedInit: true     isNeedCheck: false
endpoints: []              canRefreshEndpoint: false
attachment: BabyMenu.zip -> BabyMenu.sys + README.md（VM 网盘地址/密码）
```

`ycb.py env status 12070` → `{"data": false, "code":"00000"}`：**平台没有可分配的靶机**。

README（题目自带）说明：附件是 Windows 11 虚拟机镜像，选手以 **ctfer/123** 登录，
分析 `C:\Windows\System32\BabyMenu`（驱动）并本地提权到管理员；**本地打通 + 录屏 + 交 EXP 源码**
给运维（QQ 2238811670）校验后，运维给远程靶机地址并**读取 flag 后发放**。
禁止套用公开 CVE / 现成 CVE EXP。

> 判定：本题**没有在线 flag 校验**，flag 是人工发放的 → 我们最多产出"可复现的提权证据 + EXP"。

## 2. 离线取证（64 GiB 镜像，全静态，未启动 VM）

镜像 `work/babymenu/babymenu.raw`，GPT：NTFS 主分区 offset = **444416 扇区**（`mmls` 确认）。

| 事实 | 证据 |
|---|---|
| 驱动部署在 `C:\Windows\System32\BabyMenu.sys`（inode 132315），**与附件 md5 完全一致** `1973359eb038e0060b790c75ef64cf7e` | `icat -o 444416 … 132315` → `BabyMenu_deployed.sys` |
| 服务名 **`ycb`**：`Type=1`(内核驱动) `Start=2`(自动启动) `ErrorControl=1` `ImagePath=\??\C:\Windows\System32\BabyMenu.sys` | SYSTEM hive `ControlSet001\Services\ycb` |
| OS = Windows 11 **26H1 / build 28000.1.br_release / UBR 1450**，EditionID=Professional | SOFTWARE hive `Microsoft\Windows NT\CurrentVersion` |
| 驱动签名 = **`WDKTestCert grz,134248400306672224`**（测试证书）→ 必须 `testsigning on` | PE cert table 0x2800，openssl/正则在 `sig.p7b` |
| 未开 Secure Boot（`Control\SecureBoot\State` 键不存在），HVCI/DeviceGuard **无 Scenario 项**，`RunAsPPL=2`、`IsPplAutoEnabled=1` | SYSTEM hive |
| `C:\flag.txt` = **`flag{test_flag}`**（15 B，占位符） | inode 41693 |
| 作者痕迹：`E:\BabyMenu\x64\Release\BabyMenu.pdb`（PDB 路径）；`Users/Admin/AppData/Local/Temp/vmware-Admin/VMwareDnD/{219b2c8e,6e65b76b}/BabyMenu.sys`（VMware 拖拽进来的原始驱动） | strings + `fls -r` |

一条命令可复现以上全部：`python3 scripts/12070-analyze.py --image work/babymenu/babymenu.raw`
（输出 `work/12070_babymenu/analysis.json`，末尾有断言，任一事实不符即非零退出）。

## 3. 驱动逆向（漏洞就在这 3 个 IOCTL）

`fw-decompile` 伪代码 + `objdump -d -M intel` 交叉验证（完整反编译：`work/12070_babymenu/decompiled/`）。

```
entry / DriverEntry @0x1400013bc → FUN_140001118:  IoCreateDevice(DriverObject, 0,
        "\Device\BabyMenu", FILE_DEVICE_UNKNOWN=0x22, Characteristics=0, FALSE, &dev)
      IoCreateSymbolicLink("\DosDevices\BabyMenu", "\Device\BabyMenu")   → 用户态 \\.\BabyMenu
      MajorFunction[0]=[2]=passthrough(0x140001040)  MajorFunction[0xe]=0x140001070
      DriverUnload = 0x1400012b0（删符号链接+设备）
      ExInitializePushLock(&g_lock)

DriverControl @0x140001070:
      code = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.IoControlCode
      ExAcquirePushLockExclusiveEx(&g_lock, 0)      ← 所有 IOCTL 串行，无竞态
        case 0x222004 → ExFreePoolWithTag(g_buf, 0); g_buf=NULL; g_size=0
        case 0x222008 → len = min(*(u64*)SystemBuffer, 0x140)
                        ProbeForRead(*(void**)(SystemBuffer+8), len, 1)
                        memmove(g_buf, *(void**)(SystemBuffer+8), len)
        case 0x222014 → g_buf = ExAllocatePool2(0x100 /*POOL_FLAG_PAGED*/, 0x120, 'ycb!')
                        （旧指针直接覆盖，不 free → 泄漏，但可用于布局）
        default       → 0xC0000010
      ExReleasePushLockExclusiveEx(&g_lock, 0); Irp->IoStatus = …; IofCompleteRequest
```

三个 IOCTL 都是 **METHOD_BUFFERED + FILE_ANY_ACCESS**（`code & 3 == 0`、`(code>>14)&3 == 0`），
所以任何用户句柄都能发，且输入结构放在 `SystemBuffer` 里由 IO 管理器拷进内核（无 double-fetch）。

### 漏洞

| # | 事实 | 数值 |
|---|---|---|
| 1 | `ExAllocatePool2` 的 flags = **0x100 = `POOL_FLAG_PAGED`**（wdm.h；非 NonPaged） | 288 B 请求 → **PagedPool** |
| 2 | 分配器块 = 0x10 `POOL_HEADER` + 0x120 = **0x130**；≤512 B ⇒ **Segment-Heap LFH** 后端 | 0x130 |
| 3 | 写入上限 0x140 > 0x120 ⇒ **0x20 字节线性池溢出**，落在下一个 chunk 的 `POOL_HEADER`（16 B）+ 其用户数据前 16 B | 0x140-0x120=0x20 |
| 4 | 写入长度**用户可控**，取 `len=0x124` 时只改邻居 header 的 **前 4 字节**（`PreviousSize/PoolIndex/BlockSize/PoolType`），`PoolTag/ProcessBilled` 保持有效 | 0x124 |
| 5 | `0x222004` 无 NULL 检查 → `ExFreePoolWithTag(NULL,0)` = 立刻 BSOD（另一个可作证的次要 bug） | — |
| 6 | `0x222014` 覆盖旧指针不释放 → 可反复分配（布局素材，但只有最后一个是全局可写目标） | — |
| 7 | write handler 带 `__try/__except`（导入表有 `__C_specific_handler`，0x140001234 处 `mov eax,0xC00000E8` 是 except 落点）→ `ProbeForRead` 抛异常不会 BSOD，只返回错误码 | — |

**没有**任意地址读写、没有读回通道（只有 alloc/write/free 三个 op）、free 后立即置空（无 UAF），
所以本题的真实图元就是"**paged-pool 0x20 线性溢出 + 可任意分配/释放受害者 chunk**"。

### POOL_HEADER（x64，SSTIC 2020 实测布局）

```
+0  PreviousSize(u8)  +1 PoolIndex(u8)  +2 BlockSize(u8)  +3 PoolType(u8)
+4  PoolTag(u32)      +8 ProcessBilled(ptr64)
```
`BlockSize/PreviousSize` 单位为 0x10；`PoolType` bit2 = **CacheAligned**、bit3 = PoolQuota。

## 4. 利用路线：Aligned Chunk Confusion → ghost chunk

19H1 起内核池改用 Segment Heap，**对齐 chunk 的释放路径把校验全删了**（Bayet/Fariello,
*Scoop the Windows 10 pool!*, SSTIC 2020, §3.2；本目录 `sstic.txt` 第 1179–1300 行原文）：

```c
if (AlignedHeader->PoolType & 4)                 /* CacheAligned */
    OriginalHeader = AlignedHeader - AlignedHeader->PreviousSize * 0x10;
    OriginalHeader->PoolType |= 4;               /* 然后照 OriginalHeader 的 BlockSize 释放 */
```

这正是我们缺的那把钥匙：只要能把**下一个 chunk 的 `PoolType.CacheAligned` 置位并控制
`PreviousSize`**，内核就会去释放一个**我们伪造的 chunk**（ghost chunk），而该伪造 header
就在我们自己可写的 0x130 里。所需条件（论文 §4.1）我们全部满足：

| 论文要求 | 本题 |
|---|---|
| 能改邻居 `POOL_HEADER` 第 1、4 字节 | `len=0x124` 恰好只改前 4 字节 |
| 能控制受害 chunk 的分配/释放 | `0x222014` / `0x222004` |
| 受害 chunk ≥ 0x130（ghost 需 0x210 别越界到第三个 chunk） | 恰好 **0x130**（本章 §4.7 的下限） |
| paged pool 目标对象 | **PipeAttribute**（`NtFsControlFile 0x11003C/0x110038`，大小完全可控） |

具体编排（已写进 `exploit/babymenu_lpe.c` 的 stage 0–7）：

```
V = 驱动 chunk（block 0x130，user data 从 V+0x10 起）
邻居 = 我们 sprayed 的 0x120 PipeAttribute（block 0x130，header 在 V+0x130）

1) drv_write(len=0x124):
     body[0x30..0x40] = fake POOL_HEADER {Prev=0, Idx=0, BlockSize=0x21(→0x210), PoolType=0x01}
     body[0x120..0x124] = {PreviousSize=0x0F, PoolIndex=0, BlockSize=0, PoolType=0x01|0x04}
   ⇒ 邻居 header 声称"我是 cache-aligned，我的真身在 0x0F*0x10=0xF0 之前" = V+0x130-0xF0 = V+0x40 ✓
2) 释放邻居属性 ⇒ 内核按 fake header 释放 ghost chunk **G = V+0x40 .. V+0x250**，尺寸 0x210
   （G..G+0x10 就是 ghost 的 POOL_HEADER；G+0x10 起是它的用户数据；若 VS 后端另加 0x10 头
     则对象落在 G+0x20 —— 这一点**用泄漏内容自标定**，见 §10 判定点 B3）
   （0x210>0x200 ⇒ VS/Dynamic Lookaside 后端；先 spray+free 0x200 请求的属性把该 size 的
     DLA 打开，让 free/realloc 变确定）
3) 释放驱动 chunk（0x130 进 LFH）→ 用 0x120 请求的 PipeAttribute(LEAKATTR) 抢回 V：
   struct 在 V+0x10，其 data 从 V+0x38 起，正好覆盖 ghost 头部 V+0x40
4) 用 0x200 请求的属性(GHOSTATTR, block 0x210) 落进 ghost chunk ⇒ 它的 struct 写在
   **G+0x10 = V+0x50**（VS 头存在时 G+0x20），压在 LEAKATTR 的 data 上
   —— 注意 LEAKATTR 的名字必须是 **7 字符**（8 含 NUL），它的 value 才正好从 V+0x40 = G 开始
5) 读 LEAKATTR 的 value ⇒ 直接拿到 GHOSTATTR 的 struct：
   list.Flink/Blink、AttributeName、AttributeValue —— 全是内核堆指针
   ⇒ ghost 地址 = name_ptr 对齐回推，V = ghost - 0x40（V 就是我们自己 chunk 的地址）
6) 拿到堆地址后：再抢一次 V（free LEAKATTR → 0x222014 或新属性），用驱动写直接改写
   GHOSTATTR 的 struct（AttributeName/Value/ValueSize）⇒ **任意内核读**
7) 任意读 → 沿 list 走到 FILE_OBJECT/npfs.sys 指针 → 读 npfs 导入表 → ntoskrnl 基址（破 KASLR）
8) 写图元两条候选：
   (a) Quota Process Pointer Overwrite：把 ghost header 改成 PoolType=8(PoolQuota)、
       ProcessBilled = fakeEprocess ^ ghostAddr ^ ExpPoolQuotaCookie，free ghost ⇒
       对 fake_EPROCESS 指向的计数器做 **BlockSize 大小的减**
       （需 ExpPoolQuotaCookie 偏移 + 一个可控内容的假 EPROCESS，属性 data 即可提供）
   (b) 若有写图元：读 PsInitialSystemProcess→EPROCESS.Token，写回自身 EPROCESS.Token
   注意（`ctf-pwn` 判据）：1607+ 起必须**同时**压 `TOKEN.Privileges.Enabled` 和
   `Privileges.Present`，只改 Enabled 拿不到 SeDebugPrivilege。
```

> 合规：Aligned Chunk Confusion 是**公开的通用技法**（会议论文 + 原理），不是 CVE，
> 也不是任何 CVE 的现成 EXP；题目禁的是"公开 CVE 及其现成 EXP"。本 Expoit 针对自定义驱动，
> 按题目要求自己实现对自定义驱动的分析与利用。

## 5. 为什么拿不到 flag（硬边界）

1. 平台侧 `detail.json`：`endpoints: []`、`isNeedCheck: false`、`endpointType: monopoly`，
   `env status 12070` 返回 `data:false` ⇒ **没有可提交 flag 的在线校验，也没有靶机**。
2. 题目自带 README：flag 在**运维的远程靶机**上，必须"本地提权成功 + 录屏 + EXP 源码"经运维
   （QQ 2238811670）校验后才发远程地址、并由运维**读取 flag 发放**。
3. 镜像里的 `C:\flag.txt` = `flag{test_flag}` —— 明确是占位符，**不是**本题 flag。
   （若把 `flag{test_flag}` 拿去提交，就是 RULES §2 说的"猜写法"，本代理**未提交任何串**。）

⇒ 本题对 agent 的**可得产物上限** = 可复现的漏洞证据 + 可编译的 EXP + 给运维的说明；
flag 必须由人类走运维通道。已在最终报告里以 `BLOCKED` 标注。

## 6. 卡点与待办（给人类/接手者）

| 风险 | 说明 | 怎么验证/解决 |
|---|---|---|
| **A. 对齐 chunk 释放路径是否在 28000 上被重新加固** | 论文写于 19H1/20H1，本机是 2025-11 的 build 28000。若 MS 把校验加回来了，阶段 4 会直接 0xC2/0xC1 | 两机内核调试（WinDbg），`sxe ld BabyMenu`；stage 4 后在 `!pool <V+0x40>` 必须看到 **0x210 free** 块。否则改走"纯数据攻击"：0x20 溢出还能改邻居 body 前 0x10 B（用 `len>0x130`） |
| B. stage 8–10 的偏移 | `ExpPoolQuotaCookie`、`_EPROCESS.Token`、`_TOKEN.Privileges`、npfs 结构都随 build 变 | 用任意读在目标上解析内存里的 PE 头取 RVA（参考 `ommadawn46/HEVD-BufferOverflowNonPagedPoolNx-Win10-22H2` 的做法），不要硬编码 |
| C. LFH 随机化 | LFH 在 32 块分组里随机挑空位，邻居未必紧邻 | 论文建议受害者前后各 alloc >32 块；stage 2/7 已按此实现，失败就整链重试（每次成本 = 一块 ghost） |
| D. 设备 ACL | 假设普通用户可 Open `\\.\BabyMenu`（MS 文档：默认设备 SD 给管理员 GENERIC_ALL、其余人 RWX；HEVD 同型驱动标准用户可开）。**未能在离线验证** | VM 上先跑 `poc/BabyMenuProbe.ps1`（默认模式，不破坏任何东西），3 秒出结论 |
| E. 我没法编译/测试 | 本工作区无 mingw-w64 / MSVC（见 `needs-approval.md`），也无 `/dev/kvm`，无法跑这 64 GiB Win11 镜像 | 人类在 Windows/VS 或装 mingw-w64 上编译；PoC 用 PowerShell 版可直接跑 |

## 7. 次要 bug（可作"漏洞确实存在"的演示）

`0x222004` 不检查 `g_buf == NULL`：`alloc → free → free` 触发 `ExFreePoolWithTag(NULL,0)`，
必然 BSOD（`BAD_POOL_CALLER`）。`poc/BabyMenuProbe.ps1 -CrashPoC` 就是这条，
录屏里可作"驱动路径已打通"的前置证据（正式证据仍应是 stage 4 的 ghost chunk + whoami 变化）。

## 8. 关键文件

```
scripts/12070-analyze.py                 一键复现本文全部静态事实（含断言）
work/12070_babymenu/analysis.json        分析结果（机器可读）
work/12070_babymenu/decompiled/          Ghidra 全函数伪代码
work/12070_babymenu/poc/BabyMenuProbe.ps1   VM 上可直接跑（探测 / 溢出 PoC / free-NULL PoC）
work/12070_babymenu/win/BabyMenuKit.ps1    **主交付物**：分阶段 EXP（probe/leak/unlinktest/steal/quota，免编译）
work/12070_babymenu/win/WINDBG-CARDS.md    WinDbg 标定操作卡（命令/期望/不符怎么办/回填清单）
work/12070_babymenu/exploit/babymenu_lpe.c  C 版参考实现（stage 0–7 + 设计注释）
work/12070_babymenu/sstic.txt            SSTIC 2020 "Scoop the Windows 10 pool!" 全文
work/12070_babymenu/README.md            构建/运行/待办
```


---

## 9. 交付清单（管理员口径：**必须拿到 SYSTEM shell，单读 flag 不算**）

### 9.1 判定「算完成」的硬指标

在 VM 里以 `ctfer/123` 登录 → 跑利用 → **新开的控制台**里：

```cmd
whoami
echo %USERNAME%
```

- `whoami` 必须输出 **`<机器名>\system`** 或 **`nt authority\system`**（取决于显示格式；
  两者都是 SYSTEM，录屏里要能看清）
- `echo %USERNAME%` 必须输出 **`SYSTEM`**
- 加分佐证：`whoami /priv` 里出现 `SeDebugPrivilege` / `SeTcbPrivilege`；
  `whoami /groups` 里出现 `Mandatory Label\System Mandatory Level`

> `whoami /user` 显示 `S-1-5-18` 是最硬的单条证据（SYSTEM 的 SID）。

### 9.2 录屏必须包含的 6 个镜头（运维校验要的）

| # | 镜头 | 为什么 |
|---|---|---|
| 1 | 登录界面/桌面 + `whoami` = `…\ctfer` | 证明起点是普通用户 |
| 2 | `sc query ycb` + `dir C:\Windows\System32\BabyMenu.sys` | 证明用的是题目驱动（md5 `1973359e…`） |
| 3 | 跑 `BabyMenuKit.ps1 -Stage leak`，屏幕出现 `PASS arbitrary read works: read 'MZ'` | 证明拿到了内核任意读（漏洞被真正利用） |
| 4 | `-Stage unlinktest` 的 PASS（或 `-Stage quota` 的减一标定） | 证明拿到写图元 |
| 5 | `-Stage steal` 打印 `PASS token swapped` | 证明 token 被改成 SYSTEM |
| 6 | **新窗口** `whoami` = SYSTEM + `echo %USERNAME%` = `SYSTEM` + `whoami /user` = `S-1-5-18` | 管理员要的"SYSTEM 权限的 shell" |

### 9.3 交付物

- `EXP 源码`：`work/12070_babymenu/win/BabyMenuKit.ps1`（PowerShell，无需编译；注明
  「开发环境：Windows 11 26H1 28000.1；工具：PowerShell 5.1 内联 C#；无第三方依赖」）
  + `exploit/babymenu_lpe.c`（C 版，注明 MSVC 需要，可选）
- `录屏`：按 §9.2 六镜头
- `文字说明`：本题笔记（本文件）+ `win/WINDBG-CARDS.md` 的回填结果
- 交给运维后由运维在**远程靶机**复跑（远程是同一镜像），把 `whoami` = SYSTEM 的画面一并提交

### 9.4 提交给运维的说明模板

```
题目：12070 BabyMenu（Windows 本地提权，自定义驱动）
起点：ctfer / 123（普通用户）      终点：whoami = nt authority\system
漏洞：C:\Windows\System32\BabyMenu.sys 服务名 ycb；IOCTL 0x222008 写入上限 0x140 >
      分配 0x120（POOL_FLAG_PAGED）⇒ 0x20 字节 paged-pool 溢出到相邻 chunk 的 POOL_HEADER。
利用：Aligned Chunk Confusion（SSTIC 2020 通用技法，非 CVE）造 ghost chunk → 内核任意读
      → 覆盖本进程 EPROCESS.Token 为 SYSTEM token → start cmd.exe。
环境：Windows 11 26H1 build 28000.1（UBR 1450），VMware，testsigning。
交付：EXP 源码（BabyMenuKit.ps1，免编译）+ 录屏 + 本说明。
```

---

## 10. 路线选择与逐步骤判定点（给人类在 VM 里手跑）

### 10.1 两条终点路线

| 路线 | 机制 | 需要 | 优点 | 风险 |
|---|---|---|---|---|
| **R1（主推）unlink → `EPROCESS.Token`** | 控制 ghost 里 `PIPE_ATTRIBUTE.list` 的 Flink/Blink，让 npfs 的链表摘除做一次「任意指针对写入」：`[Blink] = Flink` | 任意读 + 4 个符号偏移（卡 2 的 B/C/C'） | **一步到位**，直接变 SYSTEM，不需要 SeDebug、不需要 258 次循环 | 依赖 npfs 摘链路径可控（`-Stage unlinktest` 30 秒可判定）；附带一次对 `[token+8]` 的写（落在 `_TOKEN.TokenSource.SourceIdentifier`，审计字段，实测应无害但未在 28000 验证）；token 引用计数没加 1（录完屏回滚快照即可） |
| **R2（备用）quota 减一 → SeDebug → 注入 winlogon** | 伪造 ghost 的 `POOL_HEADER`（`PoolType|=8`、`ProcessBilled = fakeEproc ^ G ^ ExpPoolQuotaCookie`）→ free 时对任意地址做一次减 | 任意读 + 卡 2/2b 全部量 | 论文原路线，每一步都可观测 | 要 ~258 次 ghost free 才把 `Privileges.Present` 抬到含 bit20（`0x100000 = 0xFF0×256 + 0x100`），慢且依赖 quota 内部结构在 28000 未变 |

**推荐顺序**：先 R1（`-Stage unlinktest` 判定），PASS 就走 R1；FAIL 再 R2。

### 10.2 逐步判定点（每步"成功/失败怎么区分"）

| 步 | 动作 | 成功判据 | 失败判据 / 怎么办 |
|---|---|---|---|
| A1 | `-Stage probe` | 三行 `PASS`（open / alloc / free） | `FAIL CreateFile` → `sc query ycb`、确认 testsigning；仍失败则设备 ACL 不允许普通用户（需要另一条路：见 §11） |
| B1 | spray 0x130 邻居 | `PASS sprayed N` | 中途抛 `SetAttr` → 管道属性 size 算错（改 `-NameEnc`） |
| B2 | 溢出 + 释放邻居 | 不蓝屏，`PASS neighbours freed` | **蓝屏 0xC2/0xC1** ⇒ 对齐 chunk 校验被加固，R1/R2 全废 → 见 §11 |
| B3 | `PASS ghost struct at G+0x10/0x20` + 打印 `G=`/`V=` | 泄漏里出现一对 `ffff…` 内核指针 | 没有 → 邻居没紧邻（LFH 随机），整条重跑；把泄漏十六进制贴回来我判断 |
| B4 | 任意读自检 | `PASS arbitrary read works: read 'MZ'` | 两种编码都失败 → 用 B3 的十六进制确认结构体偏移，再试 `-GhostReq 0x1f0` |
| C1 | `-Stage unlinktest` | `PASS npfs performs a controllable unlink` | `FAIL` → 走 R2；把 before/after 十六进制贴回来 |
| D1 | `-Stage steal` | `PASS SYSTEM token = …` / `PASS own EPROCESS` / `PASS token swapped` | 任一行 FAIL → 把该行 + 卡 2 回填值贴回来，我改参数 |
| D2 | 新窗口 `whoami` | `nt authority\system` + `%USERNAME%`=`SYSTEM` + SID `S-1-5-18` | 仍是 ctfer → 回到 D1 的偏移 |
| Q1 | `-Stage quota` 标定 | 目标地址的 8 字节按预期减少 | 减的量和预期不符 → 把"减前/减后"贴回来，我改公式（单位可能是 1 或 0x10） |

### 10.3 我需要的回填数据（一次贴回即可）

`win/WINDBG-CARDS.md` 末尾的「回填清单」+ 各 Stage 的 PASS/FAIL 行 + B3 的十六进制泄漏。

---

## 11. 万一「对齐 chunk 混淆」在 28000 已被加固（Plan B）

判据：B2 蓝屏（`BAD_POOL_CALLER`）或 `!pool <V+0x40>` 看不到 0x210 free 块。

此时我们只剩"0x20 线性溢出"本身。可用的纯数据攻击：

1. **改用 `len > 0x130`**：溢出会覆盖邻居 **用户数据的前 (len-0x130) 字节**。选邻居为
   `0x120` 的 `_WNF_STATE_DATA`（`NtUpdateWnfStateData`，数据长度 0x110）→ 覆盖它头部的
   `DataSize`（+0x4）→ `NtQueryWnfStateData` 返回超出分配的长度 ⇒ **越界读泄漏**
   （这是 CVE-2021-31956 用过的公开技法）。**前提**：WNF 状态数据必须落在 **PagedPool**
   的同尺寸桶里 —— 这一点本机无法离线证实，需在 VM 里用 `!poolfind` 确认。
2. 邻居换成 `PipeAttribute` 且它是链表**第一个**元素时，可直接改它的
   `list.Flink/Blink` ⇒ 对 npfs 摘链的**盲写**；但盲写需要先破 KASLR，只能配 1 的越界读一起用。
3. 有了越界读 → KASLR/堆地址 → 再用 1 的盲写打 `EPROCESS.Token`（同一思路的 R1，只是写图元
   从 unlink 换成"直接溢出写邻居 body"）。

> Plan B 的每一步都要在 VM 里用 `!poolfind` / 泄漏内容做判据，**不要盲试**。


---

## 12. "key" 到底在哪？—— 2026-10-24 追加取证结论

管理员实测远程 `<target>:16816` 的 banner 是
`Please contact pwn customer service to input key get flag`（输错回 `key:\nError!`）
⇒ 远程不是做题环境，是**"输 key 换 flag"的登记服务**。据此把三个问题都查了一遍：

### 12.1 驱动/服务里有没有 key？（否定）

- `BabyMenu.sys` 的全部字符串只有：`\Device\BabyMenu`、`\DosDevices\BabyMenu`、
  `KmdfLibrary`、`E:\BabyMenu\x64\Release\BabyMenu.pdb`、KMDF 的几条 `DriverEntry failed 0x%x` 格式串。
  **没有** key/secret/pass/token/flag 任何子串（ascii + utf16 都扫过，脚本 `scripts/12070-analyze.py`）。
- 导入表里**没有任何安全检查 API**（无 `SeAccessCheck` / `SeSinglePrivilegeCheck` /
  `SeQueryInformationToken` / `Zw*` / `Nt*`），也没有文件/注册表读取。
  三个 IOCTL 全部 `FILE_ANY_ACCESS`，**不区分调用者**。
- 池对象是 `POOL_FLAG_PAGED`（`ExAllocatePool2` 默认清零），不存在"未初始化残留数据"泄漏。
- 结论：**驱动不持有、也不校验任何 key**；它只提供"0x20 paged-pool 溢出"这个能力。

### 12.2 VM 里有没有 SYSTEM-only 的载体？（有，且只有一个）

从 `$Secure:$SDS` + `$MFT` 全量比对（脚本 `work/12070_babymenu/ntfs_acl_audit.py`，
SDS 用 0x10 网格扫描恢复 **3282 个唯一安全描述符**；MFT **234 273** 条记录）：

| 统计 | 值 |
|---|---|
| 唯一 SD | 3282 |
| "不含任何普通用户 SID（Users/Everyone/Authenticated Users/INTERACTIVE/CREATOR OWNER）"的 SD | 60 |
| 其中**恰好只给 `S-1-5-18`** 的 SD | 9 |
| 使用这些 SD 的对象 | 39 |
| 落在标准 Windows/ProgramData/WinRE/SVI/回收站之外的对象 | **1 —— `C:\flag.txt`** |

`C:\flag.txt`：`sid=3518`，owner=`S-1-5-32-544`，DACL 只有一条
`ACCESS_ALLOWED  S-1-5-18  0x120089` ⇒ **只有 SYSTEM 能读/写，ctfer 连读都不行，
Administrators 也只是 owner（无 ACE）**。
内容 = `flag{test_flag}`（15 B，占位符；inode 41693，MFT 时间 2026-10-11）。

⇒ 作者刻意把"真载体"设成 SYSTEM-only，分发镜像时把内容换成占位符。
**这就是"必须 SYSTEM shell"的技术原因**：以 ctfer 身份连这个文件都打不开。

### 12.3 key 的形态判断

| 候选 | 判断 | 依据 |
|---|---|---|
| 驱动里的常量 | ❌ | 12.1：无 key 串、无安全检查、无秘密数据 |
| SYSTEM shell 里某条命令的输出 | ❌ 不太可能 | 本地 flag.txt 是占位符；若 key 是命令输出，作者不必设成 SYSTEM-only 再发客服 |
| 注册表 SYSTEM-only 值 | ❌ | 全镜像里唯一的自定义系统对象是服务 `ycb`（值只有 type/start/errorcontrol/imagepath） |
| **客服人工发放** | ✅ **最可能** | ① 远程服务原文"contact pwn customer service to input key"；② 题目 README："运维校验后…运维读取 flag 后发放"；③ 平台描述"比赛结束前 10 分钟停止受理新的 flag 获取请求"（=人工受理）；④ 载体文件被刻意做成 SYSTEM-only 且本地是占位符 —— 说明真 flag 只在运维机上，key 是人工对照凭据 |

**结论**：key 不在 VM 里，也不在驱动里；它是**客服核对"你确实拿到 SYSTEM shell"之后给的凭据**。
因此本题 agent 侧的正确交付 = **保证人类能一次跑出 SYSTEM shell + 完整取证**，
最小步骤见 `work/12070_babymenu/win/MINIMAL-STEPS.md`。

### 12.4 复核方式（可复现）

```bash
cd ~/ctf-2026 && source ~/re-tools/fw-env.sh
# 1) 抽 MFT + $Secure:$SDS
icat -o 444416 work/babymenu/babymenu.raw 0        > mft.bin
icat -o 444416 work/babymenu/babymenu.raw 9-128-18 > sds.bin
# 2) 全量 ACL 审计（会打印 flag.txt 的 ACL 与全盘 SYSTEM-only 对象）
python3 work/12070_babymenu/ntfs_acl_audit.py mft.bin sds.bin
```
