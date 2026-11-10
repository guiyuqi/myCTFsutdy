# 12074 · redisrelay（PWN / MEDIUM / 500 分 / 全平台 0 队）

- **flag**: 未解出（只打通前 3 跳）
- **提交**: NOT_ATTEMPTED（无可复现 flag，按纪律不猜）
- **工具**: `fw-decompile`(Ghidra)、objdump、python3 struct 手写协议、自建 RESP 客户端、真机 `<target>:16587`
- **SKILLS**: `competition-reverse-pwn`、`ctf-pwn`
- **SKILLS_USED**:
  - `competition-reverse-pwn` → "把协议 framing / 可控字节 / crash edge / leak edge 分开记录"，据此先建每跳 opcode 表再动手（避免了盲 fuzz）。
  - `ctf-pwn` → "signed integer bypass" 判据：`char` 与 `'8'` 比较（0xc0: `< 0x38`）等价于有符号比较，负数索引因此合法 → 直接定位到 0x22 的 OOB 写。`ctf-pwn` 的"parser stack overflow via unchecked memcpy" 经核对**不存在**（各 hop 长度都严格校验），及时止损转向。

## 1. 题目结构（真机 + 反向双向确认）

```
nc 16587 → RESP (redis-server 7.2.16, config /home/ctf/redis.conf, 命令面 231 条)
  └─ loadmodule redisrelay.so  (uid=redis)
       │  unix socket /run/redisrelay/front/relaybroker.sock
       ├─ relaybroker   (RB4)  hello→attestor: "RA4/BROKER"
       │    └─ /run/redisrelay/attestor/routeattestor.sock
       ├─ routeattestor (RA4)  hello→vault:    "RV4/ATTEST"
       │    └─ /run/redisrelay/vault/routevault.sock
       ├─ routevault    (RV4)  hello→ledger:   "RL5/VAULT/LEDGER"
       │    └─ /run/redisrelay/ledger/routeledger.sock
       ├─ routeledger   (RL5)  hello→council:  "RC5/LEDGER/COUNC"
       │    └─ /run/redisrelay/council/routecouncil.sock
       └─ routecouncil  (RC5)  open("/home/ctf/council.flag") 只读 fd（每会话 worker）
```
六个进程六个 UID；socket 模式 0660，只能"上一跳"连"下一跳"。
全部二进制：**PIE + Full RELRO + canary + CET(SHSTK/IBT note)**，stripped。
每跳 server 都是 `fork()` → `dup2(conn,0/1)` → `execve("/home/ctf/<name>","--serve")`，
子进程装 seccomp（白名单：read/write/…/exit，含 `0x142` execveat）后进入帧循环。

## 2. 两套"令牌"机制（每跳自带随机 secret，故不能跳级）

| 机制 | 位置 | 内容 |
|---|---|---|
| 状态机门控 | 模块 / broker / attestor … | 对象上带 `magic + 本连接 secret^ptr + checksum`，必须自洽 |
| token 校验 `FUN_00102410`(broker) | opcode `0x14`(写) + `0x15`(验) | `p[1]==8`；`p[0]+0x20000 <= 0x40000`（**64 位无符号**）；`p[3]==mix(p[2]^p[4]^0x6a09…9889)`；通过则返回 `*(u64*)(fn+p[0])` |

第二条是**任意 8 字节代码段相对读**：偏移允许 `[-0x20000,+0x20000]`，覆盖整个
`base-.bss`（broker `.bss` 0x7000 距 `fn` 0x2410 只有 +0x4c10）→ 直接读走
`DAT_00107050 / DAT_00107048`（连接 secret）与 4 张表里的堆指针。
**校验量全由攻击者自选**（p2/p4 任意），所以这个"能力令牌"没有保密性。

## 3. 已打通的三跳（`scripts/12074-solve.py`，真机可复现）

### S1 Redis 模块（纯逻辑题，无内存破坏）
命令序列：`relay.begin <0x80B seed>` → `bind` → `snapshot`(泄露 route 头 0x50)
→ `retire`(释放 route，**alias 指针不清**= UAF 前提) → `ledger`(0x200 Alloc 复用同一块 →
把 route 内存换成 `RLEDGER3`) → 再 `snapshot`(泄露 ledger 头)。

泄漏解算：
- `DAT_00111018 = ledger[2]`（明文存放）
- `DAT_00111020`：ledger 里只能拿到 `seed3^const^rand`（**常量与实现不一致，不可直接解**），
  改用 **stamp 校验式的逆运算**：`stampinfo` 给 `stamp[0..5]`，
  `stamp[5] = mix(stamp[0]^stamp[4]^seed3^stamp[1]^stamp[2]^stamp[3]^0xa409…31d0)`，
  mix 是双射 → 逆出 `seed3`。真机自检：解出的 `route[5]` 指向 `…e300`（页内偏移 0x300 =
  `FUN_00108300` 的 0x8300）→ 证明正确。
- `route_ptr = route[2]^seed2`，`stamp_ptr[i] = stamp[i][2]^seed2`。

随后 4 次 `relay.fragment i <hash> <0x80B>` 用**完全伪造的 0x200 route 镜像**覆盖 UAF 块：
`p6=fold`、`p7=1`、`p8=mix(...)`、`p5=rotl17(seed3^ptr^(fn8300+0x100))`
（把校验目标从 `FUN_00108300` 改指 `FUN_00108400`，返回值 0x52563341="RV3A"）
→ `relay.commit` = **relay armed**，`relay.tunnel` 变成到 relaybroker 的双工通道。

### S2 relaybroker（真正的 pwn 点）
帧格式：`[u32 total][u64 hdr1: "RBK3"|op<<32|idx<<40|cnt<<48][u64 hdr2: len|seq<<32][payload]`，
`total=0x10+len ∈[0x10,0x6000]`，`seq` 必须严格递增。
- `0x7f` ping → `RBS3 0x80 "RB4/PONG"`
- `0x10/0x11/0x14/0x15` = 会话/绑表/写令牌/验令牌 ⇒ 任意读（见 §2）
- **漏洞**：`0x22`（route 追加）里 `local_6038[0] < 0x38` 是 **signed char** 比较，
  且写入偏移用 `(long)(signed char)idx * 8`：idx=`0xfc..0xff` ⇒ 偏移 `0x20/0x28/0x30/0x38`
  = 直接改写 route 头的 `[4][5][6][7]`（[6] 必须为 1 而正常路径永远写不到）。
  真机 4 次写入全部 `0xa2`（成功）。
- 补齐 `[4]`（重定向到 `FUN_00104000`）、`[5]`（4 个 ledger 对象的 fold）、
  `[7]`（`mix(route[0]^[6]^secret2^[1..5]^0xbb67…)`）后 `0x23` →
  **broker 主动 connect attestor 并写 16B hello `RA4/BROKER`**，回 `0xa3`。
- `0x40` = 到 attestor 的双工 relay（u32 长度帧，≤0x5000）。

### S3 routeattestor（入口已打开）
同样模板但**独立 magic**：`RAT4`；ping → `RTS4` + `RA4/PONG`（真机确认）。
它的 server 先 `memcmp(16B, "RA4/BROKER")` 再过 seccomp 进帧循环；
其 secret 是 6 个 `getrandom|1`（0x7048..0x7070），对象 0x120/0x40 随机字节。

## 4. 剩余 3 跳的门（已定位，未打通）

| hop | hello(16B) | 帧 magic | 备注 |
|---|---|---|---|
| routeattestor | `RA4/BROKER` | `RAT4` | ping 已通；opcode 多出 `\x20 \x21 \x30 \x31 ' ' '!' '0' '1' '2' '3' '4' '@' 'A' 'P' 'Q'` |
| routevault | `RV4/ATTEST` | `RLV3` | opcode 少（`\x7f` + `\x05 \x06 \x18`）→ 可能是纯 RESP 代理 |
| routeledger | `RL5/VAULT/LEDGER` | `SCR5` 系 | 有 `fcntl` |
| routecouncil | `RC5/LEDGER/COUNC` | `RMT5` 系 | 唯一 `open("/home/ctf/council.flag")`+`lseek` 的进程；最后一段还有 `cVar=='2'` 分支 |

## 5. 坑 / 排除

- ❌ **RESP 解析器漏洞**（brief 提示的方向）：Redis 7.2.16 本身、以及每跳自定义帧
  （u32 长度 + 定长头）**长度全部严格校验**（`total-0x10<=0x5ff0`、`len==0x90`、
  `len==0x10`…），没有 memcpy 溢出；`__memcpy_chk` 只在模块的 32 字节栈缓冲里用，且长度限死 <0x20。
  真正的洞是**有符号索引越界写**。
- ❌ 跳级：每跳 connector 的 socket 路径硬编码，且服务端先校验 16B hello + 独立随机 secret，
  本进程 uid 不在下一跳 socket 的组里 ⇒ 只能逐跳。
- ⚠️ 模块 `relay.ledger` 依赖 jemalloc 把刚 `free` 的 0x200 块**原地址**还给下一次 `Alloc(0x200)`
  （代码里 `if (p != session[2]) → "ERR allocator busy"`）；真机稳定命中，失败可重试。
- ⚠️ 模块 `ledger[4]` 的常量与真值不匹配（0x2106000000000 解不出正确 seed3）——
  必须改用 stamp 逆运算，否则 `route[5]` 解密出垃圾。
- ⚠️ 真机 `CONFIG/MODULE/EVAL` 未测（未需要）；`PING` 无需 AUTH。

## 6. 产出

- `scripts/12074-solve.py` —— 可复现到第 3 跳（module armed + broker committed + attestor ping）
- `work/12074_redisrelay/rl.py` —— 同源开发版（含 `Broker.rd()` 任意读原语）
- `work/12074_redisrelay/{mod.c,broker.c,routeattestor.c,routevault.c,routeledger.c,routecouncil.c}` —— 去符号反编译
- `work/12074_redisrelay/*.asm` —— 关键跳汇编（mod.asm / broker.asm）

## 7. 附：routeattestor 帧内 opcode 表（`RAT4`，逆向所得，未打通）

| op | 作用 | 守卫 |
|---|---|---|
| `0x7f` | ping → `RTS4` + `RA4/PONG` | 已真机验证 |
| `0x10` | 建会话 `malloc(0x120)` + 0x40 随机 | `idx<8,cnt<4,len==0` |
| `0x11` | 绑定 `tbl0x7140[cnt] = sess[idx]` | `idx\|cnt<4` |
| `0x12/0x13` | dump / free 会话 | |
| `'0'` | 建 `malloc(0x180)` + 0x40 随机（`tbl0x7100`） | `idx<4` |
| `'1'` | 绑定 `tbl0x70e0[cnt]` | |
| `'2'` | free `tbl0x7100[idx]` | |
| `'@'` | 建 route 对象 `malloc(0x180)`：magic `0x344c495541545252`="RRTTAUIL4"，`[6]=self`，`[9]=FUN_001023f0`(下一跳 connector)，`[2][3][4]` 用 `DAT_00107058/60/70` 与 `self`、`self+0x10` 编码 | `len==0` |
| `'3'` | 读 `tbl0x70e0[idx]` 前 0x50 字节 | |
| `'4'` | **写 0x180 字节**到 `tbl0x70e0[idx]`（0x180 对象，长度精确 = 无溢出） | `len==0x180` |
| `'A'`/`'P'`/`'Q'` | 校验 route（`[0]==magic`、`[6]==self`、`[4]==mix([1..3]^secrets^0x8f2be7d0c59ef568)`）→ 调 `[9]` 连 vault | `len>3` |

⇒ 第 3 跳的门与 broker 同构（伪造 0x180 route + 四个 secret），但 secret 是 6 个 `getrandom|1`，
且本跳未找到与 broker `0x14/0x15` 等价的"任意读"opcode（`'4'` 只能写已绑定的对象），
需要另外的泄漏点才能补齐 `[2][3][4][7][8]`——这是停下来的确切原因。
