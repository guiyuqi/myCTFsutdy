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
2) 释放邻居属性 ⇒ 内核按 fake header 释放 ghost chunk [V+0x40, V+0x250)，尺寸 0x210
   （0x210>0x200 ⇒ VS/Dynamic Lookaside 后端；先 spray+free 0x200 请求的属性把该 size 的
     DLA 打开，让 free/realloc 变确定）
3) 释放驱动 chunk（0x130 进 LFH）→ 用 0x120 请求的 PipeAttribute(LEAKATTR) 抢回 V：
   struct 在 V+0x10，其 data 从 V+0x38 起，正好覆盖 ghost 头部 V+0x40
4) 用 0x200 请求的属性(GHOSTATTR, block 0x210) 落进 ghost chunk ⇒ 它的 struct 写在 V+0x40，
   压在 LEAKATTR 的 data 上
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
work/12070_babymenu/exploit/babymenu_lpe.c  stage 0–7 实现 + 8–10 设计注释
work/12070_babymenu/sstic.txt            SSTIC 2020 "Scoop the Windows 10 pool!" 全文
work/12070_babymenu/README.md            构建/运行/待办
```
