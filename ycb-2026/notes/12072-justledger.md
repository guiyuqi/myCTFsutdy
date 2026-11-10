# 12072 · justledger（PWN / MEDIUM / 500）

## ★ FLAG（已提交成功）

```
DASCTF{25095531057106159885093049234276}
```
平台返回：`{"code":"00000","message":"解题成功!","isCorrect":true,"hasCheated":false,"eventId":84513,"correct":true}`
复现：`python3 scripts/12072-solve.py <host> <port>` 一条 TCP 连接跑完全链（真靶机 <target>:30975 实测）。

三关机制（全部实证）：
- **第 1 关 lease 解锁已破**：`SELECT * FROM ledger WHERE seal=ledger_seed();` 之后 `SELECT ledger_bind(ledger_seed(),1);` → `ROW 31`，`leased=1`（真靶机同样成立）！
- **第 1 关任意写已破**：freelist 投毒 → `ledger_make` 把 96 字节写到 `probe.bss+0x5108`，实测 `DAT_00105110` = 目标地址、cookie 校验通过。
- **第 2、3 关 exploit 本地跑通并读出 flag**（`scripts/12072-broker-exploit.py` / `12072-vault-exploit.py`）。
- 最后一步（已解决）：`.bss+0x5118` 的 cookie 依赖 `DAT_001053f0`(rnd2)，`[6]` 里参与混淆的是 **lea 出来的真实地址 &FUN_00101260**（不是常量 0x1260）→ `rnd2 = [6]^[4]^ROR(obj,12)`，详见下文。

## ★ 第 1 关正确解锁序列（关键）

```
SELECT * FROM ledger WHERE seal=ledger_seed();   -- xFilter 捕获 sqlite3_value*(=aMem+0x38)
SELECT ledger_bind(ledger_seed(),1);             -- ROW 31  => leased=1
```
原理：第二条语句的 aMem 块**复用了**第一条语句刚释放的同尺寸块，而 `ledger_seed()` 作为 `ledger_bind` 的第一个实参先被求值，其结果正好落回**被捕获的那个寄存器地址**，于是 `sqlite3_value_pointer` 又看到活的 `MEM_Ptr`；同时 `f_5470 != f_5478` 也满足（跨语句）。

## ★ 第 1 关任意写的正确姿势（踩坑记录）

1. `make(0,1,…)`、`make(1,1,…)` 各建一个 type-1 对象；
2. `mark(0); audit()` → `[4]`=&FUN_00101260 → `probe_bss = [4]-0x1260`；`[5]`=对象地址；`obj0`；`mark(1); audit()` → `obj1`；
3. **freelist 是栈且受计数门控**：`drop(0); drop(1)`（count=2，head=obj1→obj0）→ `mark(1); touch((obj1>>12)^T)`；
4. `make(2,0,…)` 弹出 obj1（head 变成 T，count=1）——**必须多弹一次**，否则 count==0 会走 malloc；
5. `make(3,2,blob96)` 才真正落在 T：先把 `[T,T+0x2d8)` 清零，再把 96 字节写进 T。取 `T = probe_bss+0x5108` → blob[8]=`0x5110`(fire 函数指针)、blob[0x10]=`0x5118`(cookie)。
6. `ledger_fire()` 是 `jmp *0x5110`（尾跳），目标取 `probe_bss+0x1c10`（扩展内 relay：poll/read/sendmsg，把 fd0/1 和 fd3 对接）。

**最后一块拼图（已解决）**：cookie = `rol(fp ^ rnd2 ^ 0x91e10da5c79b43f2, 23)`，`rnd2 = DAT_001053f0`。
`ledger_make` 的 kind-1 分支反汇编（0x17e6-0x1823）实际是：
```
[0]=0x524f5554 (dword tag)   [1]=seq   [4]=&FUN_00101260 (lea 出的真实地址!)
[5]=self                     [6]= &FUN_00101260 ^ rnd2 ^ ROR(obj,12)
```
所以 `rnd2 = [6] ^ [4] ^ ROR(obj,12)`（**不是** 用常量 0x1260，也不存在额外的 mangle 项——之前是我把 lea 当成了立即数）。修好后 fire 正常跳进 relay。
另外实测：relay 起来时 broker/vault 的 banner 往往已不在 socket 里，脚本对 banner 做了可选处理；`~` 之后不要再等回包。

## ★ 已跑通的部分（本地实测）

| 关 | 脚本 | 实测输出 |
|---|---|---|
| 2 · ledgerbroker | `scripts/12072-broker-exploit.py` | `[+] patched True` → fire → 收到 `LVL3\x01\0\0\0`（已桥到 vault） |
| 3 · ledgervault | `scripts/12072-vault-exploit.py` | `flag{local_lab_dummy_0123456789abcdef}` |
| 本地 lab | `scripts/12072-lab-setup.py` | chroot-in-userns 起 4 进程真拓扑 |

第 2 关关键点（踩过的坑）：
- op 字母是交叉的：`'Y'`(0x59) 才是建 ROUTE（tag `0x524f555445330000`），`'G'`(0x47) 建 SLICE（tag `0x534c494345330000`）。
- 对象里的“常量”其实是 `lea` 算出的**真实地址**：`[6] = base+0x1760`（→ **PIE 泄露**）、`[5] = (base+0x1760)^rnd^ROR(self,17)`、`[2] = ROL((base+0x1770)^rnd^self,29)`；所以 `rnd = [5] ^ (base+0x1760) ^ ROR(self,17)`，hash = splitmix64(`rnd^enc^seq^0x6f27c4b19a5e38d2`)。
- 窗口读写起点 `window+0x40+off`，off ≤ 0x100；用 a=0x100,b=0x600（8bit 和校验只看低字节）可读到后面 3 个 chunk；越界写 b ≤ 0x220，把越界区先按读到的原始镜像回填（保住 chunk header）再改 ROUTE 的 [2]/[3]。
- fire 目标 = `ROR([2],0x1d) ^ self ^ rnd`，要跳到 `base+0x2120`（relay：poll fd0/fd3 + read/write）。

第 3 关关键点：
- `%p`×78 泄露：canary 在 **slot 77**（不是 19！），PIE 回址在 slot 9（`-0x1b45`）/slot 15（`-0x19b5`）。
- 任意读：把 `p64(addr)` 放进格式串缓冲区偏移 `(k-44)*8`（k=72，本二进制 skew=0），前置 `%p,`×(k-1) 后 `%s`。**注意 %s 之后格式串的尾部（'A' 填充 + 指针字节）会被 printf 当字面文本一并打印**，解析要按已知后缀裁掉。
- flag fd 在 `.bss+0x4430`（先 open flag 再降权），用 `%s` 泄第 1 个字节即 fd（实测 4..10 随机）。
- 溢出：`op 0xA7` 的 `(u8)len < 0x81` 让 len=0x100..0x180 全过；缓冲 264B@rbp-0x120，canary@+0x108，saved rbp@+0x120，ret@+0x128，可用 11 个 qword。
- 链：`pop rdi;1 / pop rsi;flagfd / pop rdx;0;pop rbx;0 / pop rcx;0x200 / sendfile`（vault seccomp 黑名单只挡 execve/open/socket，sendfile 放行）。libc 用 `pop rdx; pop rbx; ret`（0x90469），无单 pop rdx。

第 1 关（卡点）见文末 §5。

## 0. 附件与拓扑（一手证据）

`firmware/12072_justledger/justledger的附件.zip`（双层 zip）解出 5 个 ELF + 自带运行时：

| 文件 | 作用 |
|---|---|
| `listener` | TCP 入口：bind 0.0.0.0:**9999**，accept 后 fork；`connect("/tmp/ledgerbroker.sock")` → **dup2 → fd3**；`chdir("/home/ctf")`；`execve("/home/ctf/ld-linux-x86-64.so.2","--library-path","/home/ctf","/home/ctf/justledger")` |
| `justledger` | SQLite `:memory:` 前端；`load_extension(%LEDGER_MODULE%, "sqlite3_ledgerprobe_init")`；`dlsym("ledger_statement_done")`；每行一条 SQL，`SELECT` 才有输出（hex 编码）；`alarm(180)` |
| `ledgerprobe.so` | SQLite 虚拟表扩展：8 个 SQL 函数 + 虚表 `ledger(record, seal HIDDEN)`；init 里装 seccomp |
| `ledgerbroker` | `/tmp/ledgerbroker.sock` 监听；accept → fork → connect `/tmp/ledgervault.sock` → fd3 → `execve(- --serve)`；`--serve` 里实现 `{op,idx,len}` 记录协议 + 8 个对象槽 |
| `ledgervault` | `/tmp/ledgervault.sock`；`--serve` 里 **先 `open("/home/ctf/flag")` 保留 fd**，再 `setuid(1002)` + seccomp；实现 `op 0xA7` 读记录 和 `op 0x91` 格式化串 |

全部 `PIE + NX + Canary + Full RELRO`，自带 `libc.so.6`（**glibc 2.35 / Ubuntu 22.04**）、`ld-linux-x86-64.so.2`、`libsqlite3.so.0`、`libm.so.6`。

seccomp 均为 **黑名单**（命中→`SECCOMP_RET_ERRNO|EPERM`，其余 ALLOW）：
- probe：禁 `execve/execveat, write/writev/pwrite*/sendto/sendmmsg/sendfile/splice/tee/vmsplice/copy_file_range, io_uring_setup, process_vm_writev, socket/connect/socketpair, open/openat/openat2/creat, shmctl`。→ 只留 `read/poll/sendmsg/mmap/...`，恰好够 `FUN_00101c10` 的中继。
- broker / vault：禁 `execve/execveat, open/openat/openat2/creat, socket/connect/socketpair`（read/write/splice 都允许）。

## 1. 本地复现 lab（`lab_setup.py`）

`unshare -r` + `chroot`（`/home` 是只读挂载，只能 chroot）：`root/home/ctf/*` + `/dev/null` 用普通文件代替 + `root/tmp`。
**仅本地补丁（等长，代码偏移不变）**：`listener/ledgerbroker/ledgervault` 的 `setgid/setuid` 调用改成 `xor eax,eax;nop;nop;nop`（userns 里 uid 1000/1001/1002 未映射）；listener 端口 9999 → 31337。
启动：
```bash
python3 lab_setup.py
# 三个后台 job：
unshare -r bash -c 'chroot '"$PWD"'/root /home/ctf/ledgervault'
unshare -r bash -c 'chroot '"$PWD"'/root /home/ctf/ledgerbroker'
unshare -r bash -c 'chroot '"$PWD"'/root /home/ctf/listener'
```
`python3 lab1.py` 直接单跑 justledger（socketpair 做 fd0/1/3），可从 `/proc/<pid>/mem` 读扩展的 .bss 观察内部状态。

## 2. ledgerprobe.so 全局状态图（.bss）

| 偏移 | 含义 |
|---|---|
| 0x5100 | `sqlite3_api` 指针 |
| 0x5110 / 0x5118 | **fire 目标函数指针** / 其 cookie（init 里 `=5` / `rol(5^rnd2^0x91e10da5c79b43f2,23)`） |
| 0x53f0 / 0x53f8 | rnd2（`getrandom()|1`）/ 对象序号计数 |
| 0x5400 / 0x5408 | free 计数 / freelist 头（safe-linking：`next=(p>>12)^*p`） |
| 0x5410 | `ledger_mark` 记下的“当前对象”指针（**drop 后不清空 → 悬垂**） |
| 0x5420..0x5458 | 8 槽对象指针数组 |
| 0x5460 / 0x5464 | lease token 地址 / **leased 标志** |
| 0x5468 / 0x5470 / 0x5478 | cursor 打开标志 / xFilter 时的语句计数 / 语句计数 |
| 0x5480 / 0x5488 | 值指针混淆 mask / xFilter 捕获的 `sqlite3_value*^mask` |

对象 0x2d8 字节，`ledger_make(idx<8, kind<3, blob96)`：
- kind0：`[0]=0x4e4f5445`，`[1..0xb]=blob[1..0xb]`
- kind1：`[0]=0x524f5554`，`[1]=++seq`，`[4]=FUN_00101260`，`[5]=self`，`[6]=rnd2^0x101260^ror(self)`
- kind2：`[0..0xb]=blob[0..0xb]`（**完全可控**）
`ledger_mark(idx)` → `0x5410=slot`；`ledger_touch(blob8)` → `*(u64*)0x5410 = blob`（**8 字节写**）；`ledger_audit()` → `result_blob(0x5410+0x20, 32)`（**32 字节读**）；`ledger_drop(idx)` → 入 freelist。
`ledger_fire()` → 校验 cookie 后 `(*(code*)0x5110)()`。

**漏洞（设计意图）**：`mark(i)` → `drop(i)` 后 `0x5410` 仍指向已释放块 → `touch()` 改写 freelist 首块首 8 字节 → `make(j,2,blob96)` 时 `next=(p>>12)^*p` 变成任意地址 T → 对象落到 T，**先把 T..T+0x2d8 清零再写 96 字节可控** → 篡改 `0x5110/0x5118`，`ledger_fire()` 跳到 `.so` 内 `FUN_00101c10`（poll/read/sendmsg 中继 fd0/1 ↔ fd3），即把客户端 socket 与 **broker 的 socket 打通**。

## 3. broker 协议（`--serve`）

4 字节头 `{u8 op, u8 idx(0..7), u16 len(≤0x704)}`，payload 前 4 字节 `{u16 a, u16 b}`；回包 `{u8 status(0=ok), u8 op, u16 len}+data`；banner `"$$5 3\0\0\0"`（`0x33352424c`）。
- `'1'` 建 WINDOW(idx)；`'j'`(len==4) 读 `window+0x40+a` 共 b 字节；`'k'`(len==b+4) 写同样位置
- `'G'` 建 ROUTE(idx)：`[1]=seq,[2]=rol(rnd^0x101770^self,29)`,`[3]=hash(...)`,`[4]=self`,`[5]=rnd^0x101760^ror(self)`,`[6]=FUN_00101760`
- `'Y'` 建 SLICE(idx)：`[2]=(self+0x10)^ror(rnd)`,`[0x1c]=cap=0x80`；`'r'`/`'s'` 读/写 slice
- `'~'` 触发 ROUTE：校验 `[4]==self` 且 hash 正确后 `(*(([2]>>0x1d)|([2]<<0x23)) ^ self ^ rnd)()`

**漏洞**：窗口/切片边界检查用 **8 位和**（`(u8)(a+b) > 0x70` / `(u8)(a+b)` 也出现在 slice），`a=0x100,b=0x600` 之类可绕过 → `'k'` 起始 `window+0x140`、写入最多 0x220 字节 → **相邻 chunk 越界写**。
利用：`'j'` 读 0x600 字节越过自己的 chunk 读到相邻 ROUTE 的 `[1][2][3][4][5]` → 反推 `rnd = [5]^0x101760^ror([4])`；再用 `'k'` 改目标 ROUTE 的 `[2]`(编码后的目标地址) 与 `[3]`(重算 hash) → `'~'` 跳到 `FUN_00102120`（poll/read/write 中继 fd0/1 ↔ fd3），打通 **vault**。

## 4. vault 协议（`--serve`）

banner `"LVL3\x01\0\0\0"`；头 `{u8 op, ?, u16 len}`：
- `op 0xA7`：`if ((u8)len < 0x81 && len < 0x401) read(len, local_128[264])` → **(u8) 检查漏洞**：len=0x100..0x180（或 0x200-0x280/0x300-0x380）都能过 → **栈溢出**（buffer 264 = 0x108，canary 在 +0x108）
- `op 0x91`（1≤len≤0xf0）：读入 264B 缓冲后**直接当 `__dprintf_chk(1,1,user_str)` 的格式串**（无变参）；只拦截 `%...n`（沿 `"0123456789$#+-. *hljztL"` 跳过修饰符后若转换符是 'n' 就退出）→ `%p/%s/N$s` 全可用 → 泄露 canary / PIE / libc
- 其余 op：len≤0x800，分块读丢弃后回 `"ERR\n"`

目标：`open("/home/ctf/flag")` 的 fd 保存在 .bss `0x4430`（**先开 flag 再降权**），`dlsym(0,"read")` 存在 `0x4438`。vault 的 seccomp 允许 `read/write`，所以 ROP：`read(flag_fd, bss, n)` + `write(1, bss, n)`；flag fd 由 `1+random()%7` 次 `/dev/null` 拉开为 **4..10**，可直接依次试。
需要先做**栈溢出 + 保留 canary**：第一段 ROP `read(0, bss, 0x1000)` + 栈迁移到 bss，第二段任意长度 ROP。

## 5. 卡点：第一关 lease 解锁

`ledger_bind` 的全部条件（0x13b0 反汇编）：
`argc==2` && `0x5464==0` && `0x5488!=0` && `0x5468!=0` && **`0x5470 != 0x5478`** && `sqlite3_value_pointer(0x5488^0x5480,"ledger.lease") == &0x5460`

- `xFilter` 只在 `idxNum==3 && argc==1` 时把 `argv[0]^mask` 存 0x5488（即 `SELECT ... FROM ledger WHERE seal=<expr>`）。
- 已确认可用调用链：`SELECT * FROM ledger WHERE seal=ledger_seed();` → xFilter 捕获到**有效** `MEM_Ptr`（ptrace 实测 mid-statement：flags=0x8601, z="ledger.lease", pPtr=&0x5460）。
- 但 **SQLite 在该语句结束时清空寄存器**：ptrace 硬件断点抓到两处写 — `libsqlite3+0xe39b2`（`sqlite3VdbeMemRelease`，flags=MEM_Null，调用 noop destructor）与 `libsqlite3+0xe3f44`（逐寄存器 `mov WORD [rbx-0x30],0x80`，即 `MEM_Undefined`，步长 0x38）。→ 于是 `0x5470 != 0x5478` 要求 bind 必须在**后一条语句**，而那条语句里捕获地址的 flags 已是 0x0080，`value_pointer` 直接返回 NULL。
- 已排除：直接/子查询/聚合/EXISTS/ORDER BY/LIMIT/UNION/字符串形式、语句内运行期报错（都不保留 flags）；`aMem` 地址复用的朴素组合（`search_lease.py` / `search_lease3.py` / `search_lease4.py`）未命中。

NEXT 候选：让 `M` 语句的 `aMem` 恰好复用 N 的块（同 size class、无中间同 size 分配），并在被捕获的那个寄存器下标放一个新的 `ledger_seed()` 指针值，随后同一条语句里调 `ledger_bind`。
