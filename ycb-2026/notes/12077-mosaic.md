# 12077 · mosaic（PWN / HARD / 500 分 / 已答出 0 次）

> 2026 羊城杯 DASCTF `ycb-bk.dasctf.com`，第二批新题。
> 状态：**第一层（worker）本地 exploit 全通**；全链 6 段需继续（见 §7）。
> 结论先说：**不是交付缺陷** —— 远程前端帧协议、PNG 校验、堆状态机、tcache 泄漏在真实靶机上全部照常工作（§3 有原始字节）。

---

## 1. 附件与拓扑（八字段见 §9）

```
firmware/12077_mosaic/mosaic的附件.zip
  └ tempdir/PWN附件/mosaic-附件.zip
      description.txt  listener  mosaic  mosaic-broker  mosaic-keeper
      mosaic-seal  routecouncil  routeledger  libc.so.6  libm.so.6  ld-linux-x86-64.so.2
```

全部 stripped、PIE + Full RELRO + NX + canary；libc = `Ubuntu GLIBC 2.35-0ubuntu3.15`（**注意：tcache key 已随机化**，
且 `tcache_get`/`free` 有对 key 的硬化检查，见 §5 的坑）。

进程链（每段独立 PIE、独立 ASLR、独立状态；靠 unix socket 串起来，每段都留了一个**无 caller 的 relay 死函数**）：

```
TCP :3879  listener(0x0f27=3879)
   │  fork → connect /tmp/mosaic-broker.sock → dup2(fd,3) → execve /home/ctf/mosaic
   ▼
mosaic (worker, dlopen libpng16)   fd3 = broker link, 但主循环从不读写 fd3 ← 必须拿控制流自己调 relay
   ▼  /tmp/mosaic-broker.sock
mosaic-broker (banner "MBRK2\n")   connect /run/mosaic/keeper.sock → dup2(fd,3)
   ▼  /run/mosaic/keeper.sock
mosaic-keeper (HELLO → "K4 %016lx")   connect /run/mosaic/seal.sock（ledger_handler 是死代码）
   ▼  /run/mosaic/seal.sock
mosaic-seal (HELLO → "O5 %016lx")   字节码解释器；relay=0x16f6
   ▼  /run/redisrelay/ledger/routeledger.sock（发裸 16B "RL5/VAULT/LEDGER"）
routeledger  ── connect /run/redisrelay/council/routecouncil.sock（发 "RC5/LEDGER/COUNC"）
   ▼
routecouncil --serve   open("/home/council/flag") → dup2 → fd 4；命令 0x40 GATE → 读 fd4 → 回 flag
```

flag 只在容器启动时生成；worker 与前四个 backend 读不到；只有 routecouncil 开了 flag 文件。

---

## 2. 各层协议速查表（层 → 帧格式 → 命令）

| 层 | 帧格式 | 命令 / 关键行为 | relay（无 caller 的死函数） |
|---|---|---|---|
| listener | 无 | 纯 TCP → fork → execve worker（把 broker 连接放 fd3） | — |
| **mosaic (worker)** | `op(1) + len(4,BE) + payload`，len≤0x10000 | `L`载入PNG(一次) `V`读3B `C`写3B `P`读18B `T`写6×3B+0x2b8B `D`free×2 `F`free×7 `K`malloc×7 `E`malloc2+写18B `R`free E对 `Q`受窗读8B `U`free3；回 `OK\n`/`ERR\n`，V/P/Q 回原始字节 | **0x13e9** = fd0↔fd3 泵（本层已打通，§5） |
| **mosaic-broker** | `op(1)+len(4,BE)+payload`，len>0x800 → _exit(1)；建会话先发 banner `MBRK2\n` | `A`alloc(slot≤0xb,kind) `X`free `P`读8B `W`写8B `Z`/`Y`free 预置槽 `J`longjmp；kind→size 0→0x3f0 / 1→0x4f0 / 2→0x30 / 3→0x2f0 | **0x1549** = fd0↔fd3 泵（无 caller，需劫持后 call） |
| **mosaic-keeper** | `2B BE len + payload`（1..0x1000，文本命令） | `HELLO\n`→`K4 %016lx\n`(secret) `AUDIT <fmt>`(格式化字符串) `COMMIT`(需 audit×2)→栈溢出 | 0x178b / 0x19b2（ledger 泵，死代码，需 ROP call） |
| **mosaic-seal** | `2B BE len + payload`（1..0x310） | `HELLO\n`→`O5 %016lx`(=secret) `PROGRAM`+16N→存字节码 `RUN\n`→VM 解释；字节码 16B/条 `[op][idx1][idx2][pad5][imm8]`，op4=门 | **0x16f6**：写裸 16B `RL5/VAULT/LEDGER` 给 ledger + 发 `LEDGER\n` + select 双向泵 |
| **routeledger** | （见 rev/ledger.md 待补；redis 风格） | `LUNLOCK/RLGMANF/LGMODMV/RLRELAY/LGRELAY/PERMIT/LGR/LGNONCE`… | 待确认 |
| **routecouncil** | `4B LE 总长(0x10..0x1810) + 16B 头`：magic `RNC5`/cmd/b5/b6/0/payload_len/ticket(u32 单调) | `0x7f`ORACLE `0x10`REVEAL(行号有符号→越界读) `0x20`BALLOT(512B 写 0x5260..0x545f) `0x30`/`0x31`SEAL(free→悬垂) `0x32`泄 40B 堆 `0x33`UAF 8B 写 `0x34`COMMIT `0x40`GATE→读 fd4 回 flag | — |

---

## 3. 远程可调用性实测（靶机 <target>:32690，容器已被主代理销毁）

原始字节（`nc` 无 banner 是正常，前端等客户端先发帧）：

| 发送 | 回应 | 含义 |
|---|---|---|
| `4c 00000005 68656c6c6f`（`L`+假 PNG） | `4552520a` = `ERR\n` | 帧协议在跑，PNG 校验生效 |
| 合法 3x2 indexed PNG（256 色 PLTE） | `4f4b0a` = `OK\n` | worker 正常完成 libpng 解析 |
| `56 00000001 00`×6（`V` 0..5） | `000000`×6 | palette 已被 free+memset 清零（与本地一致） |
| `44 00000000`（`D`）→ 6×`V` | `8f73252193550000 a1fc91c6339a5703 0000` | **服务端堆指针泄漏成功**；用 §5 的方程反解 `B=0x55967842fab0`（自检通过） |

→ 真实靶机上协议/状态机/tcache 安全链接泄漏与本地完全一致；本题是**真难但可打**。

---

## 4. 各层漏洞清单（“六权限域”各一个可利用原语）

- **worker**：`L` 之后 palette 被 free 而 0x8000 全局仍指向它（UAF，且该页被 mprotect 成只读，逼你用堆路径）；
  palette 大小 768=0x300，与 worker 自己的 malloc(0x300) 同 bin → `T`/`C` = 对已释放 chunk 的受控写 = tcache 毒化；
  `D` 的三段 free 有重复释放（配合 `F`/`K` 让 chunk 先被取走再 free，绕过 tcache 双free检测）；
  `E` = malloc 两次 + 在第二次返回地址写 18 字节 = **任意 18B 写**；`Q` = 受窗 8B 读（`[*(0x9010), +0x178]` + `*(C+0x50)+i16`）。
- **broker**：`X` free 后不清 ptr、还把 readable/writable 都置 1 → `P`/`W` 悬垂 8B 读/写；索引上限 0xf 而 `A`/`X` 只到 0xb。
  → safe-link 反解堆址 → 0x300 链+kind3 毒化=任意读，0x400 链+kind0=任意写 → .got.plt → libc → environ → 写返回地址 → ROP call 0x1549。
- **keeper**：`AUDIT` 格式化字符串泄 canary（`%2$p`=PIE，`%3$p`=hash(secret)^canary）；`COMMIT` 栈溢出
  （canary 偏移 264 / saved rbp 272 / 返回地址 280，最大可写 0x300）→ ROP call 0x178b/0x19b2 桥到 seal。
- **seal**：字节码槽位寻址只查 `idx>7`（有符号）→ `idx∈[-128,7]`、`addr=B+8*(idx+4)`；
  `idx=-2` 泄 PIE（fn 指针）、`idx=-4`=secret、`panic` 不在可达范围（canary idx 211 / ret idx 213）→ 无 RIP 控制；
  但门（op4）可**伪造**：HELLO 白给 secret + 泄 base → 改写 `B+0x10=base+0x16f6`、`B+0x18=rol(secret^ptr,21)^B+8` → **op4 直接打通 routeledger**。
- **routecouncil**：`0x10 REVEAL` 行号有符号（前置逼你先做 -4..-1）→ calloc 块头前 0x80 越界堆读；
  `0x31→0x33` UAF 8B 写（值被钉死）；`0x32` 泄 40B 堆；`0x20 BALLOT` 覆盖服务端校验全局区（0x5260..0x545f）。
  ⚠️ 未确认项：`0x40 GATE` 依赖 .bss 0x50d0..0x5128 的 6 个量，子代理枚举 RIP 相对 store 未找到写入方 → 可能需 ledger 侧或其它写入路径（详见 `rev/seal_council.md` §5）。
- seccomp：worker 只封 execve/execveat+x32；broker 封 execve/execveat（**不禁 open**）；keeper 另封 open*；
  seal 封 execve/execveat/open/openat/openat2；routecouncil 封 open/openat/execve（**漏 openat2(437)/execveat(322)**）。
  所有程序都走 `_exit`（导入表无 exit）→ 没有 atexit/FSOP 路径。

---

## 5. worker 段 exploit（**本地已全通**，`scripts/12077-solve.py` + `work/12077_mosaic/solve_worker.py`）

### 5.1 关键判据（都是本地实测，不是推测）

- `L` 之后：`A=*(0x9000)`、`B=*(0x9008)`、`B = A+0x310`（相邻）；`0x8000`（**只读页**）与 `0x9028` 都指向 B。
- `D` 依次 `free(A); free(B)`，此时 0x310 tcache bin 是空的 → `B.next = (B>>12) ^ A`，而 `A = B-0x310`：
  - `V`（读 palette 前 8B）得到 `X = (B>>12) ^ (B-0x310)`；
  - 反解：`Q = inv(q → q ^ (q>>12))(X>>12)`，`r = ((X&0xfff) ^ (Q&0xfff)) + 0x310`，`B = (Q<<12)|r` —— **一次读数精确恢复 B**（本地/远程都验证过）。
- 状态机（全部条件都要满足）：
  `D`: sealed0→1 | `E`: sealed1→0 | `F`: dstate==1 && sealed==0 | `K`: dstate==2 && sealed!=0 | 第2次`D`: dstate1→2 |
  第3次`D`: dstate2→3 | `Q`: dstate==3 && sealed==0 && `*(0x9020) ∈ [C, C+0x5b]`。
  实际序列：`L, D, [leak], E, F, D, K, E, D, ...`。
- **Q 的读地址**：`*(long*)(9020+0x20) + i16`，区间必须是 `[*(0x9010), +0x178]` —— 即 png_struct 拷贝那块堆内存。
- **Q 只能配 C 内的 target**，而 tcache 要求 16 字节对齐：`target=C+0x50` 同时满足
  （在 `[C, C+0x5b]` 内、16 对齐、`target+0x20 = C+0x70` 由 `T` 控制、且 `mem2chunk(target)=C+0x40` 的 size 字段 = `C+0x48` 也由 `T` 控制 → 这个 fake chunk 之后能被合法 `free`）。
- **两次 18B 写**：`E` 的第二次 malloc 来自被 `T` 毒化的 tcache → 第一次 `E` 把 `*(0x9020)` 放到 C 里做 Q 的闸门；
  Q 泄完 `S = *(pngcopy+0x108)`（= `io_ptr`，栈地址）后，用 `R` 把 fake chunk `C+0x50` 和 B 合法归链 → 再毒化 B.next=栈地址 → 第二次 `E` 就是**对任意栈地址的 18 字节写**。
- 栈偏移（本地实测）：`pngcopy+0x108` = `io_ptr` = `S`；`main` 的 rsp `R = S+0x130`；
  当前 handler 的 saved RIP 在 `R-8 = S+0x128`（**≡8 mod 16，tcache 打不了**），
  所以写 **`S+0x120`**（16 对齐）：`[S+0x120]=rbp_main=S+0x150`（必须保留，否则 main 收尾 `mov rax,[rbp-8]` 直接段错误）、`[S+0x128]=base+0x13e9`、后 2 字节随意。
- `FUN_001013e9`（PIE+0x13e9，无 caller 的 relay）被 `ret` 进去后：fd0↔fd3 双向泵。

### 5.2 实测结果（本地，supplied libc 2.35 + libpng16）

```
B=0x5555568d5ad0  pngcopy=0x5555568dfa90  S=0x7ffc53b96a40
E4 无回包（main 没回来）  alive=True
fd3 received: b'PINGPING'      ← 我写 stdin 的字节被转发进 broker 连接
stdout:       b'PONG'          ← fd3 侧写的字节被转发回客户端
RELAY OK
```

复现：`cd work/12077_mosaic && source ~/re-tools/fw-env.sh && python3 solve_worker.py`

### 5.3 坑（都已验证，写进交付物免得后人再踩）

1. **tcache_get 有对齐检查** → 不能直接毒到 `R-8`（saved RIP 恒 ≡8 mod 16）；打 `R-0x10` 再顺带写 RIP。
2. **不能把 saved rbp 写 0**：`main` 的 canary 检查是 `[rbp-8]`，rbp=0 立刻段错误 → 必须写回真 `rbp_main`。
3. **Q 的 `9020[4]` 是 `*(9020+0x20)`**（不是 `*(C+0x50)`，除非 target=C+0x30/C+0x50）；用 C 当 target 会读到 C 里的 cookie → 闸门必失败。
4. `free(C+0x30)` 是**无效 free**（chunk 头在 C+0x20，size 字段 C+0x28 写不到）；要选 `C+0x50`（size 字段 C+0x48 可写）。
5. 远程 libpng 版本（容器 Ubuntu 22.04 → 1.6.37）与本地 1.6.57 不同 → `C-B`、`pngcopy-B` 的常量不可跨环境硬编码：
   `pngcopy` 可以**扫**（Q 幂等，T+Q 逐步试）、`C` 只能**逐连接爆破**（`C_guess` 必须精确落在 `C` 上，
   范围约 `[-0x2000,-0x310]` 的 16 字节倍数，~450 个连接，每个连接约 12 帧，成本可接受）。
6. 我的第一版驱动用 `subprocess(preexec_fn=dup2(fd,3))` —— **fd3 会被 subprocess 的 close_fds 关掉**，
   子进程里 socketpair 落在 fd4，relay 写 fd3 直接 `_exit(1)`。必须 `fork+execve` 自己 dup（现在 `drive.py` 就是）。

---

## 6. 目前缺什么（全链）

| 段 | 缺的东西 | 判断 |
|---|---|---|
| worker | **已通**（只差远程把 C 扫出来；纯工程量） | ✅ |
| broker | 按 `rev/broker_keeper.md` 的 UAF 链走：safe-link 反解堆 → 任意读写 → `.got.plt` → libc → `environ` → 写返回地址 → ROP call 0x1549 | 1–2h |
| keeper | AUDIT 泄 canary + COMMIT 264 字节栈溢出 → ROP call 0x178b | 1h |
| seal | 字节码负索引泄 PIE + 伪造门（**不需要 ROP**，纯协议） | 0.5h |
| routeledger | **尚未逆向**（派出去的子代理空转，笔记没写） | 需重派 |
| routecouncil | `0x40 GATE` 的 6 个 .bss 量来源未确认（可能不可达 → 需要 RCE 换路，seccomp 漏 openat2 可用） | 需复核 |

**flag 获取点**：routecouncil `0x40 GATE`（读 fd4）或 routecouncil 内 RCE 后 `openat2("/home/council/flag")`。

---

## 7. 交付物

- `scripts/12077-solve.py` —— worker 段可复现 exploit（含 §5 全部常量与注释，本地跑 `python3 scripts/12077-solve.py --local` 需要工作区内的 local/ 副本）
- `work/12077_mosaic/` —— `solve_worker.py`（exploit）、`drive.py`（fork/exec 驱动，fd3=broker link）、`probe.py`（/proc/PID/mem 实时读堆，标定用）、`pngtool.py`（3x2 indexed PNG 生成）、`exp_worker.py`（早期版本，保留）
- `work/12077_mosaic/decomp/*.c` —— 7 个二进制的 Ghidra 反编译
- `work/12077_mosaic/rev/broker_keeper.md` / `rev/seal_council.md`（各 300–520 行，含协议表/偏移/漏洞）
- `firmware/12077_mosaic/` —— 原始附件（只读）

## 8. 技能

SKILLS: `competition-reverse-pwn`, `ctf-pwn`（另：子代理用过 `reverse-engineering` / `ctf-reverse`）
SKILLS_USED: `competition-reverse-pwn` 的「先被动 triage（file/readelf/strings/scripts）、把结论绑到可观察边界（crash/leak/decode edge）」——
本题据此先建 `/proc/PID/mem` 活体探针（`probe.py`）标定堆布局，才有了 §5.1 的 `B=A+0x310`/`Q 的 9020+0x20` 这些硬事实；
`ctf-pwn` 的 checksec 决策树（Full RELRO ⇒ 不打 GOT，改打返回地址/内存对象）+「heap tcache 毒化 + safe-linking 公式」是 §5 的主线。

---

## 9. 最终报告（RULES §4 八字段）

```
FLAG: NONE
SUBMIT: NOT_ATTEMPTED
CONFIDENCE: high（对"第一层可打通"）/ low（对"全链可在剩余时间内完成"）
EVIDENCE: 远程原始帧与回包 evidence/12077-remote-probe.txt；本地 worker 段全通
          work/12077_mosaic/solve_worker.py（输出 "RELAY OK"）、scripts/12077-solve.py、
          work/12077_mosaic/rev/{broker_keeper,seal_council}.md、work/12077_mosaic/decomp/*.c
SKILLS: competition-reverse-pwn, ctf-pwn
SKILLS_USED: competition-reverse-pwn 的"先被动 triage + 结论绑可观察边界"→ 据此先写 /proc/PID/mem
          活体探针（probe.py）标定堆，得到 B=A+0x310、Q 的 *(9020+0x20)、pngcopy+0x108=io_ptr 等硬事实；
          ctf-pwn 的 checksec 决策树（Full RELRO ⇒ 不打 GOT，改打返回地址）+ tcache 毒化/safe-linking 公式
          是 worker 段 exploit 的主线。
NOTES: notes/12077-mosaic.md
BLOCKED: 第 2–6 段（broker/keeper/seal/routeledger/routecouncil）需要各自的 leak+劫持/RCE，仍需 4–6h 工程量；
         其中 routeledger 尚未逆向（派出的子代理空转），routecouncil 的 `0x40 GATE` 六个 .bss 量的写入方未确认。
         需要：① 重新分到 12077 容器（远程 C 偏移需逐连接爆破标定）；② 一个专攻 routeledger 的代理。
```

---

## 第 5/6 段（routedledger + routecouncil）交叉核对

核对对象：代理 `35736d15`（"12077 ledger+council layer"）的产出
`work/12077_mosaic/layers/ledger_council.md`（25KB）、`layers/lg.py`（hash 逆函数 + 20 轮闭环自测）、
`work/12077_mosaic/layers_rl.asm` / `layers_rc.asm`（反汇编）。以下"我的核对"全部直接落在 asm 地址上。

| # | 35736d15 的结论 | 我的核对 | 依据（asm 地址 / 我的实测） |
|---|---|---|---|
| 1 | L5 routeledger `op 0x7f` 白送 4 个 key qword | **未独立核对**（时间盒内只做 L6 交叉） | 我在 `layers_rl.asm` 只做了存在性检查；此条记为"采信但未复核" |
| 2 | L5 `op 0x10` 的 6 指令小 VM 里**推进 arg 是 signed char** ⇒ 负下标覆盖 0x230 key 结构体 | **方向一致，未逐指令核对** | 与其笔记 §2.1/§2.4 的行号一致；这类"signed/unsigned 混用"与本仓库其它层（seal 的 `idx>7`、council 的 `(char)(cnt-4)`）是同一套出题手法，**可信度高** |
| 3 | L6 `op 0x10` 门判据 = `cVar22 == (char)((char)0x5074 - 4)` ⇒ 初值 0 时用 `sub = 0xfc..0xff` 四次拿全部 8 组 pair（16 qword） | **一致** | 我独立读过同一段：`0x10` 的行号确认为 **signed char** 参与寻址，`u64*` 下标 `cVar22*4+idx+0x10` → `sub=0xfc` 越界到 calloc 块头前 0x80；与我原派代理 `cced8fa8` 的结论（"行号有符号 → 前置逼你打 -4..-1 四次"）**互相独立地吻合** |
| 4 | L6 `op 0x20` BALLOT：0x200 组 `(u8 n,u8 c)` RLE 展开成 0x200 字节**整块拷到 .bss 0x5260**，`0x5070 = FUN_00102740()` | **一致（我原代理也已指出）** | 与我 `rev/seal_council.md` §二 的 "0x20 覆盖 0x5260..0x545f（含 0x5360 CNCPLAN5）" 同址；`FUN_00102740` = plan 校验器 |
| 5 | **L6 `op 0x40` GATE 可达**（不是恒 0）：前置 `0x5048!=0`、`0x5044==2`(`op 0x34`)、`0x5070!=0` 且 plan 再通过，然后校验 `CNCGATE5` 对象 @0x50d0（`0x50d0=="CNCGATE5"`、`0x50e8==&0x5360` 等）并用 `FUN_00102d40` 的互逆式 + 四段 `H10` 解出 `0x50f8` 与 `+0x28` | **我改判：同意方向**，并撤回我原代理"`0x50d0..0x5128` 无写入 ⇒ GATE 协议上不可达"的绝对化推论 | ① `0x2813..0x284a` 是在比对 **`[0x5378]==&0x5360`、`[0x5380]==&0x50d0`、`[0x5388]==FUN_00102740`** 三个指针 —— 说明"被伪造的对象"是 **0x5360 的 plan 对象**（BALLOT 0x5260..0x545f 正好覆盖 0x5360，**可写**），0x50d0 只是启动时初始化的**参考门对象**；② `0x2d40` 实测是一个 mixer：`rol(0x50b0^0x50c0^0x1050d0^p, 0x17) + 0x50a0`，与它描述的互逆式一致；③ `0x210a` 处 `lea rdi,[0x50d0]` + `cmp rsi, (0x5050>>12)^(PIE+0x50d0)` 印证 `op 0x33` 的校验式 |
| 6 | 终点：GATE 通过 ⇒ `FUN_00102c90` 读 fd4 ⇒ 回 `0xc0` + flag | **同意**（与我 `rev/seal_council.md` 里 "0x40 GATE→FUN_00102c90 读 fd4" 一致） | 其笔记 §3.7；我的反编译同一函数 |
| 7 | 唯一未完成细节：`h0` 的 4 个寄存器实参（`call` 前未重装填、复用残留 `rsi/rdx/rcx/r8`）尚未钉死 | **认同这是 L6 的最后一公里**，且**必须动态取**（`1f31` 之前 loader 的残留寄存器值） | 它自己已标注；我无异议 |

**结论**：L5/L6 的"负下标/signed char"路线与我的独立结论一致；**GATE 可达性的判断我改判为"可达"**——
我原代理的否定只基于"`.bss` 无直接写入指令"，漏了"0x5360 的 plan 对象本来就在 BALLOT 可写区"这一层，
所以**不要把终点改成 routecouncil 内 RCE + openat2**，除非后续动态验证发现 `0x50d0` 的初始 magic 不是 `CNCGATE5`。
（`openat2` 可作为备用分支保留：它的 seccomp 确实漏了 `openat2`/`execveat`。）

**决定性的下一步实验**（需要容器）：`op 0x7f`+四次 `op 0x10` 拿 key → 用 `lg.py::cc_plan_bytes()` 经 `op 0x20` 写 plan →
`op 0x34` → `op 0x40`；在 `0x40` 之前 dump `.bss` 0x50d0 的 16 字节，确认 magic == `CNCGATE5`。

---

## 第 5/6 段（routeledger + routecouncil）离线闭环 —— 13:10 更新

> 子代理（L5/L6 专项）产出。**全部离线**，未起容器、未连靶机、未提交 flag（额度 0/50）。
> 代码：`scripts/12077-l5l6.py`（独立文件，不改 L1 的 `scripts/12077-solve.py`）
> 文档：`work/12077_mosaic/layers/ledger_council.md`
> asm：`work/12077_mosaic/layers_rl.asm` / `layers_rc.asm`

### 可复现三件套

| 命令 | 预期输出 | 实测 |
|---|---|---|
| `python3 scripts/12077-l5l6.py --selftest` | `OK 6/6` | ✅ exit 0 |
| `python3 scripts/12077-l5l6.py --selftest-l5w` | `L5 写原语打通（11 请求，无 poke）` | ✅ exit 0 |
| `python3 scripts/12077-l5l6.py --selftest-full` | `oracle 回包 = b'DASCTF{offline_mock_L6_oracle_ok}\n'` | ✅ exit 0 |
| `python3 scripts/12077-l5l6.py --dump-cgate` | `b0^K2^&gate^ror(f8-a0,23) ... == &oracle ? True` | ✅ exit 0 |

### 四条硬结论

1. **flag 路径是 `/home/council/flag`**（`strings` 只有它和 `/home/ctf/routecouncil`），不是
   `/home/ctf/council.flag`。`open` 后 `dup2(fd,4)`，fd 4 这点旧笔记是对的。
   ORACLE = `FUN_00102c90`：`lseek(4,0,0)+read(4,buf,0x100)+reply(0xC0)`；**全程序唯一 call 点 `0x1f34`**。

2. **两层的 key 泄漏原语都找到了**（12076 笔记 L3/L4 的硬缺口）：
   - L5：`op 0x7f`(len=0) 送 4 个 key qword；`op 0x10` 是 6 指令小 VM，`sub=2` 的推进操作数
     按 **signed char** 检查（`(char)iVar7 <= 0x1f`）⇒ 自由负下标，可读 `sk+0xc0+i*8`
     覆盖整个 0x230 key 结构体 ⇒ 反出 `c0,c8,d0,d8,e0,e8,f0,f8,s220` 与 PIE。
     **`s220` 的唯一出处是 `LRANSCR5` 那组 pair**（解锁 `op 0x11` 要用）。
   - L6：`op 0x10` 的门是 `cVar22 == (char)((char)cnt - 4)`，**signed char 比较**；
     计数器初值 0 ⇒ `sub = 0xfc..0xff` 四次，靠 `cVar22*4` 的负下标把
     `DAT_00105460[+0x00..0x7f]` 全读出来 ⇒ 一次拿全 8 组 pair ⇒ 全部 9 个 key + PIE。

3. **"缺失的任意写原语"其实是 tcache safe-linking 投毒**（这是本轮最大修正）：
   libc 是 **glibc 2.35**，safe-linking 开启，`chunk->fd = (chunk>>12) ^ next`。
   所以 `op 0x23`/`op 0x33` 让写的"固定值" `(chunk>>12) ^ (PIE+固定)` **就是**把 tcache 的 next
   指向 `.bss` 对象（`0x6270` = LPERMIT5 / `0x6070` = RLRELAY5 / `0x50d0` = CNCGATE5）的合法编码。
   配合 `op 0x24`/`op 0x34` 的「2×malloc + memcpy」即得任意写。
   堆 chunk 从 UAF 泄漏反出：`chunk = obj[0x10] ^ hh(key ^ idx ^ magic)`（key 已知）。

4. **L6 全链离线跑通**：12 个请求（握手除外）从"连接"走到"oracle 回 flag"，
   mock 用真 safe-linking 堆模型，**无任何 poke**。

### 与旧笔记不一致 / 需要纠正的地方

- `12076` 里写 L3/L4 用 `/home/ctf/council.flag` → 实为 **`/home/council/flag`**。
- `12076` 说 "L3/L4 尚未找到泄漏原语" → 现在两条都给了（见上）。
- Ghidra 的 C 在 L5/L6 有 **4 处**会直接算错（本文件与 `ledger_council.md` 已按 asm 修正）：
  ① `FUN_00102ab0`/`FUN_00102600` 少报实参（4 个/1 个）；
  ② L6 门末 XOR 里 `rol(·,0xf)` 的操作数是 **f8** 不是 h1；
  ③ L5 解锁第二个 hash 的域常量是 `"LUNLOCK5"-0x100 = 0x354b434f4c4e544c`；
  ④ `op 0x7f`/`op 0x10` 的回包长度都是 **0x20**（L5 是 0x30），asm `r9d` 写死。
- 这两层各只有 **10 / 11 个函数**，所以 12076 那条"`FUN_xxx` 只出现 3 次 = 死代码"判据**不适用**；
  relay 若存在只能是 `main` 的分支（`--serve` 的 bind 分支 + `op 0x60`）。

### 剩余（只是联调，不是原语）

- ~~L5 `LPERMIT5`/`RLRELAY5` 字段公式未 asm 复核~~ → **13:35 已全部按 asm 复核并端到端验通**
  （见下节 §「13:35 追加」）。
- 真机上 `op 0x60` 把帧转发给 council 的端到端联调（需要容器，主代理调度后再做）。

---

---

## 判据修正：从"缺失原语"到"投毒编码"

### 我上一轮的判据（原文）
> ⚠️ **未闭合的一点**：`0x6070` 与 `0x6270` 都在 `.bss`（`readelf`: `.bss @0x6010 size 0x300`，
> `0x6070/0x6270` 全零），而**代码里没有任何一条路径写它们**。所以它们必须靠 malloc 返回值劫持写进去：
> 候选是 `0x21→0x23→0x24` 三连 …… **但 `0x23` 允许写的值被门限制成固定值
> `(chunk>>12) ^ (PIE+0x6270)`，不是任意值**，所以「怎么把 fd 变成 0x6270/0x6070」还没解开。
> **这是打通 L5 的唯一缺口。**

来源：子代理 12:55 回报；落盘位置 `work/12077_mosaic/layers/ledger_council.md` §2.6 末
（该段已在 13:00 被替换，原文即上面这段，逐字保留在此）。**推理链在两处出错**：
① 把"门要求我给一个值"读成了"门限制我只能写这个值"（其实那个值就是我必须算出来的编码，门是**鉴权**不是**约束**）；
② 把 `(chunk>>12) ^ X` 当成"作者的混淆花样"，没认出它是 glibc 的 `PROTECT_PTR` 形状。

### 推翻它的证据
1. **版本面**：`strings -a libc.so.6 | grep -i 'unaligned tcache'` →
   `malloc(): unaligned tcache chunk detected`，且 `GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.15)`
   ⇒ **glibc ≥ 2.32，safe-linking 开启**（`tcache_entry->next` 存的是 `PROTECT_PTR(pos,next) = (pos>>12) ^ next`）。
2. **代码面**：`layers_rl.asm` `0x20c0..0x20cd`
   ```
   mov rax,r14 ; shr rax,0xc ; xor rax,rcx ; cmp r13,rax     ; body[0] ?= (chunk>>12) ^ target
   ```
   —— 拿 **chunk 自身右移 12 位** 再异或目标地址，正是 `PROTECT_PTR` 的构造式；`rcx` 就是 `lea rdx,#6270` 来的目标地址。
   phase-2 的 `0x211f: mov [r14],r13` 把它写回 chunk 的头 8 字节 = 写 tcache 的 `next`。
3. **行为面**：把上面认下来之后，`scripts/12077-l5l6.py --selftest-l5w` 用**真 safe-linking 堆模型**
   （`alloc` 里 `head = rd64(h) ^ (h>>12)`、`free` 里 `wr64(p, (p>>12)^head)`）从连接一路跑到 `op 0x40`
   ⇒ `0xB0 + "RL5/COUNCIL"`；L6 同构，`--selftest-full` 12 个请求一路到 oracle 回包。
   如果是"越界/巧合"，这两条链不可能在多组随机 key 上稳定复现。

### 修正后的判据（一句话）
> **当门要求 `body[0] == (ptr>>12) ^ 目标地址` 时，那不是"门在限制写入值"，
> 而是"门在要求你把 tcache 的 next 编码成目标地址" —— 它就是投毒原语本身，ptr 从 UAF 泄漏里反出即可。**

泛化写法：**看到 `(x >> 12) ^ y` 这种形状，先问"这是不是 safe-linking 的 PROTECT_PTR"**，
而不是先假设作者自创了混淆；一旦命中，所有"门钉死的固定值"都要重新读成"合法编码"。

### 适用范围边界（这条判据什么时候会失效）
- **只对启用 safe-linking 的 glibc ≥ 2.32 成立。** 判定方法：`strings libc.so.6 | grep 'unaligned tcache chunk detected'`
  （有这条串 = 有 safe-linking 分支）＋ `strings libc.so.6 | grep 'GNU C Library'` 看版本。
- **glibc < 2.32（无 safe-linking）**：`tcache->next` 是**裸指针**，`(chunk>>12) ^ target` 就不是合法 next，
  投毒会以 `unaligned tcache chunk` 或 SIGSEGV 结束 —— 同样的代码、同样的门，结论要**反过来**：
  那时门要求的 `(ptr>>12)^target` 才真的是个"无法用任意值填"的约束，得另找出路。
- **tcache 被关掉**（`glibc.malloc.tcache_count=0` / 早期版本走 fastbin）：fd 是裸指针且只看低 4 字节，
  `>>12` 这一项完全没有意义。
- **不是"能写就是赢"**：这条判据只给「把 malloc 骗到定址」的能力。能不能用还取决于
  ① 目标地址 16 字节对齐（`tcache_get` 有 `aligned_OK` 检查；`0x6270/0x6070/0x50d0` 都满足）；
  ② 目标在 2×malloc 的**第二次**才被返回（所以 `0x24/0x34` 的 body 必须前段填充、后段才是 payload）；
  ③ 写入长度别踩坏相邻全局（L5 `0x6270+0x98 = 0x6308` 正好是 key 结构体指针，差 8 字节就炸）。
- 本场同作者的 12078 cacheline 用的是 musl（无 tcache），这条判据**不适用**——不要跨题照搬。

---

## ⚠️ 给后来人的警告：这两层**不要**用"FUN_xxx 只出现 3 次"找 relay

12076 笔记给出的死代码判据是「`grep -oE 'FUN_[0-9a-f]{8}' file.c | sort | uniq -c` 里**只出现 3 次**
（函数索引 1 + `===` 标题 1 + 定义行 1）= 0 个真实调用点」，它在 L1/L2 确有战果
（`FUN_00108940` / `FUN_0010145a` 就是这么找到的）。**但搬到 routeledger / routecouncil 会翻车**，实测：

**(a) 这条路在 asm 上根本走不通**——两个二进制都是 **stripped**，objdump 里没有任何函数符号：
```
$ grep -oE 'FUN_[0-9a-f]{8}' layers_rl.asm | wc -l   → 0
$ grep -oE 'FUN_[0-9a-f]{8}' layers_rc.asm | wc -l   → 0
```
`FUN_` 前缀只存在于 **Ghidra 的自动命名**里，拿到 asm 上验就会得到"全是死代码"的荒谬结论。

**(b) 在 .c 上跑，会产生明确的假阳性**——`rev/clean/routecouncil.c` 里记号数（实测）：
```
1 FUN_00101020   1 FUN_00102d40   2 FUN_001013a0   2 FUN_00102540   2 FUN_00102570
3 FUN_00102c90   4 FUN_00102a40   5 FUN_00102740   6 FUN_00102a00  11 FUN_00102a90  17 FUN_00102600
```
其中 `FUN_00102d40` **只出现 1 次**、且 `grep 'call +2d40' layers_rc.asm` **无任何调用点**，
是教科书式的"候选 relay"。但它实际只有 6 条指令：
```
mov rax,[50b0] ; lea rdx,[50d0] ; xor rax,[50c0] ; xor rax,rdx ; xor rax,rdi ; rol rax,0x17 ; add rax,[50a0] ; ret
```
—— **它是作者给门里那个指针自校验写的逆运算辅助函数**
（`f8 = rol(&oracle ^ b0 ^ K2 ^ &gate,23) + a0`），不是通道。
真按死代码判据把它当 relay 劫持进去，RIP 只会掉进它 `ret` 之后的垃圾。
同理 `FUN_00101020`（只出现 1 次）是 `push [0x5ef0]; jmp [0x5ef8]` 的机器生成 thunk。

**(c) 真正的 relay 在这个设计里压根不是"函数"**：
routeledger 的通路是 `main` 的 `--serve` bind 分支（`accept → fork → connect 下一层 → 送握手 →
dup2(client→0/1, next→3) → execve 自身 "--serve"`，见 `layers_rl.asm 0x1485..0x1520`）
和 `op 0x60`（把 `u32 len`+body 原样 `write(3)` 再读回，`0x28d1..0x29b6`）。
整题没有一个"只被定义不被调用"的转发函数 —— 判据的**前提**（存在独立 relay 函数）在这里不成立。

**结论**：死代码判据只在「作者留了独立 relay 函数」的层（12076 的 L1/L2）有效。
用之前先做两件事：① `wc -l` 看函数总数（这两层只有 10 / 11 个，一眼就知道没空间藏 relay）；
② 先找 `main` 里的 bind/exec 分支和 `write(next_fd)` 的 op（比 grep 更赚）。

---

## 13:35 追加：L5 的 0x40 门也按 asm 钉死并跑通

新增 `--selftest-l5w`（**17 个请求，无 poke**）：泄漏 → 解锁 → 造对象/free/UAF 泄 chunk →
投毒 → 写 `LPERMIT5`@`PIE+0x6270` → `op 0x30` ⇒ `0xA0`（permit 门过）→
free 2×0x1f8 / UAF 泄 chunk / 投毒 → 写 `RLERALY5`@`PIE+0x6070` → `op 0x40` ⇒ `0xB0` + `"RL5/COUNCIL"`。

两个门都在 mock 里**按 asm 独立重写**（`_permit_gate` = `0x2bc0..0x2d8e`、
`_relay_gate` = `0x1df0..0x1ff4`），逐字段比对，所以公式不是"客户端怎么写就怎么算"。

三条只有读 asm 才能对的东西：

1. `LPERMIT5` 的 `+0x38/+0x40/+0x48/+0x50` 是四段 H8，实参顺序为
   `(c0,c8,&permit,&relay)` / `(s220,h1,sk1f0,sk1f8)` / `(h1,h2,&permit,s220)` / `(h2,h3,&relay,c8)`，
   末项 `sk1f8 ^ sk1f0 ^ h1 ^ rol(h2,0xb) ^ rol(h3,0x1d) ^ ror(h4,0x11)`。
2. `RLERALY5` 的 magic 常量是 **`0x3559414c45524c52` = `"RLERALY5"`**（作者的字面串，
   不是 `RLRELAY5`；`strings` 里另有 `BLRELAY5` 容易看混）。
3. `RLERALY5` 的 `h4'` 第 5 个实参在 Ghidra 的 C 里**根本不出现**：
   它是 `[rbp-0x170]`，那个栈槽平时存 seq，但在 **asm `0x1e2d`** 被
   `mov [rbp-0x170], rax`（`rax = sk[0x1c0]`）覆盖成 **`c0`**。漏这一行 `h4'` 永远算不对。

### 判据复用（写给下一个人）

这一轮两次都是靠同一条方法救回来的：**"反编译器少显示的实参，去 asm 里找那个寄存器是谁写的"**。
L6 的 `h0`（4 个隐式实参，复用上一段残留）与 L5 的 `h4'`（被一个不相干的栈槽覆盖）都是这个形态。
配套的可执行判据：**mock 里按 asm 重写成门 → 让客户端的伪造对象去过 → 过不了就是某个实参错了**，
比"读 C 猜参数"快一个数量级（本轮两次定位都在 1~2 次运行内完成）。
