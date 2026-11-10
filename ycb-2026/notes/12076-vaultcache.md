# 12076 · vaultcache（PWN / HARD / 500 / 全平台 0 队解出）

- **flag**: 未解出（NONE）
- **提交**: NOT_ATTEMPTED（无可复现 flag；按纪律不猜写法，额度 0/50 未动）
- **工具**: file / strings / objdump -d -M intel、Ghidra(`fw-decompile`)、pwntools(ELF checksec)、自写 RESP 客户端 + **附件自带的 redis-server 7.2.16**（jemalloc-5.3.0）本地实测
- **SKILLS**: competition-reverse-pwn, ctf-pwn
- **SKILLS_USED**:
  ① `competition-reverse-pwn` 的"先被动 triage（file/checksec/strings/imports/entropy）再决定 reverse-first 还是 exploit-first"——由 strings 里的握手串与对象魔数直接画出四层拓扑，由 imports 分布（`open`/`lseek` 只在 routecouncil、`execve` 只在 routeledger）定位 flag 归属与 relay 机制；
  ② `ctf-pwn` 的 checksec 判据表（PIE + Full RELRO + NX ⇒ 不碰 GOT，改打函数指针 / `setjmp_buf` / 伪造对象图）＋"先看有没有现成工具、别硬写解析器"——于是直接用附件自带 redis-server 做本地验证，并用 redis crc64 复现 DUMP 载荷。
- **BLOCKED**: 4 层链 + 全平台 0 队解出 + 估计 4–6h，超出本轮预算（父代理已决定不分配容器）。
- **产出**: 本文件；`work/12076_vaultcache/FINDINGS.md`；`work/12076_vaultcache/dec*/decompiled/*.c`（四份反编译）；`work/12076_vaultcache/run/{rcli.py,forge.py,rc.conf}`

---

## ★ 可复用要点 1：四层拓扑与三个"预置 relay 死代码"

```
client --TCP 9999--> redis-server 7.2.16 + vaultcache.so   (L1, jemalloc)
                         | connect /tmp/vault-broker.sock
                         v
                     vaultbroker                            (L2, glibc, --session 自 re-exec)
                         | connect /run/redisrelay/ledger/routeledger.sock
                         | 握手 "RL5/VAULT/LEDGER" (0x10B)
                         v
                     routeledger                            (L3, glibc, canary)
                         | connect /run/redisrelay/council/routecouncil.sock
                         | 握手 "RC5/LEDGER/COUNC" (0x10B)
                         v
                     routecouncil                           (L4, glibc, canary)
                         | 启动即 open("/home/council/flag", O_CLOEXEC) => fd 4  ← **路径已修正**，见 `notes/12077-mosaic.md`「第 5/6 段」§1：实为 `/home/council/flag`（原写 `/home/ctf/council.flag`，`strings routecouncil` 只有 `/home/council/flag` 与 `/home/ctf/routecouncil`）
                         | ORACLE FUN_00102c**90**: lseek(4,0,0)+read(4,buf,0x100)+回包  ← 地址已按 12077 复核（原写 2c80）
```

- 四层 **seccomp 同款**：禁 `execve(59)` / `execveat(322)` → EPERM，`|nr|>=0x40000000`(x32) → KILL。**全程没有 shell 路线**，只能读 fd 或直接读文件。
- 四层全 **PIE + NX + Full RELRO**；vaultbroker **无 canary**，routeledger / routecouncil 有 canary。
- **每层都有一颗"直通下一层"的 relay 函数是死代码**（正常控制流不可达，必须靠劫持函数指针/`longjmp` 调进去）——这是本作者的固定设计套路（12078 cacheline 同款）：

| 层 | 预置 relay | 机制 |
|---|---|---|
| L1 `vaultcache.so` | `FUN_00108940`（file off `0x8940`） | `fd = *(u32*)(*(u64*)(rec->data+0x10)+0x10)` → `connect("/tmp/vault-broker.sock")` → `poll` 把该 fd 与 broker socket **双向裸转发** |
| L2 `vaultbroker` | `FUN_0010145a`（`0x145a`） | `write(7,"RL5/VAULT/LEDGER",0x10)` 后 **fd0 ↔ fd7 裸转发** |
| L3 `routeledger` | `main()` 的 `--serve` 分支组合 | bind 模式 accept 后 **fork → connect council → 送 "RC5/LEDGER/COUNC" → dup2(client→0/1, council→3) → execve 自身 "--serve"**（`execve` 出现在 imports 是设计，不是后门） |
| L4 `routecouncil` | 无 relay | 终点是 oracle `FUN_00102c80`，不需要再跳 |

> 判据：`grep -oE 'FUN_[0-9a-f]{8}' x.c | sort | uniq -c` 中**只出现 3 次**（函数索引 1 + `===` 标题 1 + 定义行 1）= 0 个真实调用点 = 死代码。L1/L2 的 relay 都是这么找出来的。

## ★ 可复用要点 2：L1 redis 模块的 jemalloc 8 字节溢出（本地已实测触发）

模块 `VaultRecs` v1 encver=0，记录结构 **0x300**：`{+0 len, +8 cap, +0x10 data_ptr, +0x18 fn=FUN_001081e0, +0x20 self}`。

- `vault.put key data`：len 必须 ∈ `[0x300,0x800]`，`Alloc(0x300)` 结构 + `Alloc(len)` 数据，`cap=len`。
- `vault.get`：回 `min(len,cap)` 字节。`vault.patch key off data`：要求 `off<=cap && n<=cap-off`（**安全**）。
- `vault.render`：`len>0xff` 时把 `ctx`/栈指针/被调用者保存寄存器写进 `data+0x48..+0x88`，再 `call rec->fn(data,len,ctx)`（→ 劫持点）。
- **BUG 在 RESTORE 路径**（`redis.conf` 只 `rename-command` 掉了 CONFIG/MODULE/DEBUG/EVAL/CLIENT/SCRIPT/SAVE/MIGRATE…，**`DUMP`/`RESTORE` 没禁**）：
  `rdb_load = FUN_001082f0`：`cap = LoadUnsigned()`、`data = LoadStringBuffer(&len)`；
  接受条件 `0x300 <= cap < 0x801` 且 `cap <= len <= cap+8`，然后 **`Alloc(cap)` + `memcpy(..., len)`**
  ⇒ **最多 8 字节、内容完全可控的堆溢出**（落在后一个 jemalloc region 起始处）；且 `rec->len = len > cap`。
- **本地实测（未打补丁的原始 .so）**：`cap=0x300 & len=0x300` → OK；**`cap=0x300 & len=0x308` → OK**（= 向 768B region 写 776B）；`cap=0x500 & len=0x504` → OK；之后 redis 存活，`vault.get` 仍只回 `cap` 字节。
- 坑：redis 用 **jemalloc**（`malloc=jemalloc-5.3.0`），不是 glibc malloc ⇒ free 后 region 不写链表（tcache 是数组缓存），投毒面比 glibc 小，L1 的利用难度主要在这里；且 **L1 没有任何泄漏原语**（get/render 都只回数据区），要把 `rec->fn` 改成 `FUN_00108940` 还需一个可预测指针。

### 附：如何自造 DUMP 载荷（省半小时）
```
07 | 81 <8B moduleid> | 02 <SaveLen(cap)> | 05 <SaveRawString(data)> | 00(EOF) | 0b00(rdbver=11) | <crc64 LE>
   ^type MODULE_2      ^RDB_MODULE_OPCODE_UINT=2   ^RDB_MODULE_OPCODE_STRING=5
```
缺 `0b00` 会被判 `ERR DUMP payload version or checksum are wrong`。

## ★ 可复用要点 3：**redis crc64 = 反射多项式 `0x95AC9329AC4BC9B5`，init=0，xorout=0**

- 用真实 `DUMP` 载荷（96B）的末 8 字节**逐字节验证命中**；CRC-64/XZ（`0xC96C5795D7870F42`）与 CRC-64/ISO 均 **不匹配**——这是最容易踩的坑。
- 实现（反射、LSB-first）：
```python
POLY = 0x95AC9329AC4BC9B5
T = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (c >> 1) ^ POLY if c & 1 else c >> 1
    T.append(c)
def crc64(data, c=0):
    for b in data:
        c = T[(c ^ b) & 0xff] ^ (c >> 8)
    return c
```
- 实测代码见 `work/12076_vaultcache/run/forge.py`（含 `rlen()` RDB 长度编码 + 模块操作码封装）。

## ★ 可复用要点 4：L2 vaultbroker 的 S/G UAF → tcache 投毒 → C 任意写 → T 的 `_longjmp`

每连接 fork；`malloc` 7 块固定缓冲：`0x330×3`（'Q'/zero/'R'）、`0x3d0×3`（'a'/zero-slot/'b'）、`0x50`；
`setjmp` 到 **`0x3d0_mid + 0x40`**；seccomp；回 `"VLTB3\n"`；帧 = `cmd(1B) + len(4B BE) + body(≤0x900)`。

- 命令：`C`(slot<12；kind→size `{0:0x3d0,1:0x510,2:0x50,3:0x330}`；readable=kind∈{1,3}，writable=kind==0)、`F`(free，slot<12)、`R`(读 8B @`ptr+off`，要求 `off<=size-8`)、`E`(写 8B @`ptr+off`)、`S`(free 两个 0x330 并启用 UAF slot 12/13)、`G`(free 两个 0x3d0 并启用 slot 14/15)、`T`(门 + `longjmp`)。
- **BUG**：`F`/`S`/`G` **只清 `live`，指针保留，还把 readable/writable 置 1** ⇒ 已释放的 0x340/0x3e0 chunk 上 **UAF 读 + UAF 写（8B @ size 内任意 offset）**。
- **利用链（静态推导）**：UAF 读拿 tcache `key`（= 堆指针）与 safe-link ⇒ UAF 写投毒 tcache ⇒ `C` 的 `malloc` 返回任意地址 + `memcpy(payload, ≤0x900)` ⇒ **任意写** ⇒ 覆盖 `0x3d0_mid+0x20`（门魔法 `ror(read_got ^ 0x101309 ^ buf, 0x17) ^ 0x8b7d51e29ac4630f`）与 `0x3d0_mid+0x40`（fake `jmp_buf`）⇒ `T` 通过门 ⇒ **`_longjmp` 直接控 RIP/RSP** ⇒ 调预置 relay `FUN_0010145a` 进 L3。
- 一开始预设的 4 个"槽"就是 `0x330/0x330/0x3d0/0x3d0` 那几块，`S`/`G` 分别对应 0x340 与 0x3e0 两个 size class。

## ★ 可复用要点 5：L3 / L4 的门结构（唯一剩余缺口：key 泄漏原语）

- **L3 routeledger**（`--serve` 协议）：读 4B len，要求 `len-0x10 <= 0x1800`；`malloc(len)` 读满；前 4B 必须 `"LGD5"`；命令字节 `0x7f / 0x10 / 0x11 / 0x20 / 0x23…`。
  对象魔数：`RLGMANF5 / RLGMODMV5 / RLRELAY5 / RLGRELY5 / RLPERMIT5 / LGR5 / LGNONCE5 / LGEPOCH5 / LGLKEY0-3`。
  启动时 `getrandom` 填 `struct+0x1c0 / +0x1c8 / +0x1d0 / +0x1f0 / +0x200 / +0x220`，并用
  `hash(x) = (x>>30 ^ x)*K1; (x ^ x>>27)*K2; (x ^ x>>31)`（`K1 = -0x40a7b892e31b1a47`，`K2 = -0x6b2fb644ecceee15`）
  预生成全部校验字；通过 relay 命令经 **fd 3** 转给 council。
- **L4 routecouncil**：门 `FUN_00102740` 校验 `(&DAT_00105260)[0..0x1f]` 与 keyed 链相等，并要求对象
  `DAT_00105360` 形如 `{magic "CNCPRMT5", key 副本, self == &DAT_00105360, ptr == &DAT_001050d0, digest == FUN_00102740}`；
  **oracle 调用点（`FUN_00102c80` 的唯一调用处）还要求伪造对象里某个 qword == `&FUN_00102c80`** —— 典型"伪造对象图改函数指针"（12078 同款）。
  对象名：`CCNONCE5 / CCTICKT5 / CNCKEY0-3 / CNCALT0-1 / CORACLE5 / CNCGATE5 / CNCPLAN5 / BALLOT5 / CNCPRMT5`。
- **缺口**：L3/L4 都用了 per-connection 随机 key + 绝对地址（`&DAT_001050d0`、`&FUN_00102c80`，即 PIE base），
  而这两层**尚未找到泄漏原语**，因此无法离线伪造对象图。这是打通全链的唯一硬缺口（工作量 ≈ 12078 cacheline，但多一层）。

---

## 踩到 / 差点踩到的坑

1. **`DUMP`/`RESTORE` 没被 rename 掉** —— 第一眼容易漏掉 L1 唯一 bug 入口（`redis.conf` 列了 19 条 rename，容易以为全封）。
2. DUMP 载荷不是裸 `SaveUnsigned+SaveString`，模块层带 `0x02`/`0x05` 操作码 + 末尾 2B rdbver + 8B crc。
3. redis crc64 是 **Jones 反射**变体，用 XZ/ISO 多项式会一直 `checksum wrong`。
4. redis 是 **jemalloc**，不是 glibc malloc —— 别照 glibc tcache 那一套写 L1。
5. `routeledger` 的 `execve` 是 relay 设计（exec 自身 `--serve`），**不是**可用的攻击面（且被 seccomp 挡）。
6. 进程内 `_longjmp` 的目标 `jmp_buf` 落在**中间那块** 0x3d0 缓冲（不是被 `S`/`G` 直接暴露的两块），必须靠 tcache 投毒才能到达——这是 L2 设计上的"多一步"。

## 下轮建议
- 已确认环境：**不用装 redis**，附件自带 `redis-server` + 全部运行库，`loadmodule` 后即可 `RESTORE` 复现 L1；`work/12076_vaultcache/run/` 是可复用的最小测试床。
- 若要继续：优先写 **L3/L4 的 Python 复现器**（把 `hash` 与 0x20 字链、`CNCPRMT5` 对象校验在本地重算），再从 L3 命令里找 key 泄漏（12078 的 `beacon`/`ledger` 式打印是最可能的形态）。
