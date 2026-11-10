# 12067 · Goodbye!shell（2026 羊城杯 · PWN · MEDIUM）

- **flag**: `DASCTF{59889675273415859764617608126761}`
- **提交**: `{"code":"00000","message":"解题成功!","result":true,"data":{"isCorrect":true,"hasCheated":false,"eventId":83828,"correct":true}}`（1 次提交，退出码 0；`ycb.py` 自动把 `DASCTF{...}` 剥壳成内层串提交）
- **工具**: python3 / pwntools / ROPgadget / objdump / readelf / strace / gcc（自造 SROP 验证 harness）
- **SKILLS**: `competition-reverse-pwn`、`ctf-pwn`
- **SKILLS_USED**:
  - `ctf-pwn`「**Protection Implications**」表：Partial RELRO + No PIE → GOT 可写，直接给出「改 GOT」这条路；
  - `ctf-pwn`「**Advanced Exploit Primitives / SROP**」：有 `syscall` 且能控 `rax=15` 就是 SROP，是本题的终点（免 libc base 的关键）；
  - `competition-reverse-pwn`「Map mitigations, loader behavior, leak source, **最终 artifact 分开记录**」：先 `file`/`checksec` 再反汇编，把「任意写原语」与「泄露/输入原语」分开建模，才看出 GOT 重定向是唯一出口。

---

## 1. 附件与保护

`attachment.zip` → `pwn` / `libc.so.6`(2.35-0ubuntu3.15) / `ld-linux-x86-64.so.2` / `libseccomp.so.2`。

```
pwn: ELF 64-bit LSB executable, x86-64, not stripped
RELRO: Partial   Stack: No canary   NX: enabled   PIE: No PIE (0x400000)
GNU_PROPERTY: SHSTK + IBT 位（本机/远端均未实际启用 CET，ROP 可用）
```

`nm` 给出 `main / vuln / sandbox` 三个函数，全二进制 .text 只有 0x1c9 字节。

## 2. 逻辑（3 个函数，2 分钟看完）

```c
sandbox(): seccomp_init(SCMP_ACT_ALLOW);
           seccomp_rule_add(ctx, SCMP_ACT_KILL, __NR_execve=59,  0);
           seccomp_rule_add(ctx, SCMP_ACT_KILL, __NR_execveat=322,0);
           seccomp_load(ctx);           // 只杀 execve/execveat，其余全放行

main():    sandbox(); write(1,"Give me your name: ",19); vuln();

vuln():    char buf[0x20]; read(0, buf, 0x30);   // ★ 溢出 0x10
           write(1, "Goodbye!shell.", 9); leave; ret
```

判据：`buf` 在 `rbp-0x20`，读 `0x30` → **只控 saved rbp + saved rip 各 8 字节**；无 canary、无 PIE、NX 打开 → 不能 ret2shellcode，只能 ROP。seccomp 杀 `execve` 正是题名「shell 不会回应你」的含义 ⇒ 必须 ORW，而 ORW 需要 `open`=libc，需要 gadget 与 base。

## 3. 关键原语

### 3.1 输送带：任意地址写 0x30 字节

`0x40122b`：

```asm
lea rax,[rbp-0x20]; mov edx,0x30; mov rsi,rax; mov edi,0
call read@plt
mov edx,9; ... ; call write@plt ; nop ; leave ; ret
```

`rbp` 完全由溢出控制 ⇒ `read(0, rbp-0x20, 0x30)` = **任意地址写 0x30 字节**；末尾 `leave;ret` 又用
`[X+0x20]/[X+0x28]` 重新装载 `rbp/rip`（X=rbp-0x20）⇒ 可无限串联，把整个 .bss 按 0x30 一块块铺满。

`0x401227` 是同一段，只多了开头的 `sub rsp,0x20` —— 这决定了 `call read@plt` 压栈的返回地址落在
**前一个窗口 +0x08**（0x401227）还是 **+0x28**（0x40122b）。这个差别是后面保全 sigframe 的关键。

### 3.2 泄露/输入：1 字节改 GOT 低字节（**不需要 libc base**）

`read@got`(0x404038) 里是 `libc.read = base+0x114920`。**短读**（`read` 只写入实际收到的字节）可以只改它的最低字节：

- 写 `0x30` → `base+0x114930` = `syscall; cmp rax,-0x1000; ja err; ret`（libc 页对齐 ⇒ 高 7 字节不变，无需 base）
- 写 `0xc0` → `base+0x1149c0` = `write`（fd0 输出）
- 写 `0x20` → 回到 `read`

### 3.3 SROP：`rbp=0x2f` ⇒ `rax=15`

读站点 `lea rax,[rbp-0x20]`。取 `rbp=0x2f` ⇒ `rax=0xf=__NR_rt_sigreturn`，紧接着的 `call read@plt`
被 3.2 改成 `syscall` ⇒ **直接进入 rt_sigreturn**，`rsp` 处的 sigframe 全寄存器可控。
这一步绕开了本二进制最大的短板：**没有任何 `pop rdi/rsi/rdx`**，`rdi` 只能取 0/1，
`open`/`openat` 的 `AT_FDCWD=-100` 需要完整 64 位寄存器，只有 SROP 能给。

## 4. 利用链

```
vuln 溢出: saved_rbp = F1+0x20, saved_rip = 0x401227
  ↓ 输送带（0x401227/0x40122b 交替）铺 4 个 sigframe + 3 条触发链 + 路径串
最后一窗: [0x404058]=0x2f, [0x404060]=read_site, 枢轴 (rbp=0x404058, rip=0x401227)
  ↓ read(0, 0x404038, 0x30) 只发 1 字节 0x30  → read@got = libc+0x114930
  ↓ leave;ret: rbp=[0x404058]=0x2f → rax=15，rip=read_site → call read@plt → syscall
rt_sigreturn(frame#1): openat(AT_FDCWD, "/flag", 0)
  → ret 到 C2 触发链: pop rbp; 0x2f; read_site → 又一次 rax=15 → rt_sigreturn(frame#2)
sendfile(1, 3, NULL, 0x200)       ← 一次系统调用直接把文件内容怼到 stdout
  → frame#3 / frame#4 再试 fd 4/5（远/近环境 fd 可能不是 3）
```

远端 `/flag` 一次命中，输出 `DASCTF{59889...}`。

## 5. 坑（都是实测踩出来的，写下来给复盘）

1. **★ `call read@plt` 的返回地址会污染前一个传送窗口**：`read@plt` 压栈位置 = `entry_rsp-0x28`，
   而 `entry_rsp` 由上一步 `leave;ret` 决定 ⇒ 每铺一块 0x30，**前一块的 +0x08（或 +0x28）被写成 0x40125a**。
   直接按 0x20 步长铺 sigframe ⇒ `rip`/`rdi` 被毁。解法：sigframe 只按
   `{0x00, 0xd0, 0x38, 0x50, 0x70, 0x90, 0xb0}` 这 7 个偏移写，让所有必需字段落在窗口的
   `0 / +0x10 / +0x18`（安全位），被毁的那一个 qword 只落在 `uc_link / r11 / r14 / rbp / rcx / cr2`
   这些 `rt_sigreturn` 不读的字段上；再让「帧最后一个窗口之后的那一步」用 0x40122b 入口，
   把唯一的漏网点从 `cs/ss` 挪到 `cr2`。
2. **★ `sigcontext.fpstate`（frame+0xe0）必须为 0**：这一页在 `ld-linux-x86-64.so.2` 引导下
   **残留 loader 数据**（实测 0x404140 处是 `0x0015000100000054`、0x404148 是 `&_DYNAMIC` 之类），
   非 0 会让内核去 `fpu__restore_sig(0x0015...)` → `badframe` → `SIGSEGV / SI_KERNEL`
   （`strace` 里表现为 `rt_sigreturn(...) = 0` 之后立刻 SIGSEGV，极易误判成 CET/IBT 问题）。
   解法：加一个偏移 0xd0 的窗口把 `oldmask/cr2/fpstate/reserved` 显式清零。
3. **★ cs/ss 必须是 `0x33/0x2b`**：x86-64 内核**不会**替你强制 `__USER_CS/__USER_DS`
   （那是 32 位路径/`UC_STRICT_RESTORE_SS` 的事），`cs=0x40125a` 会让 iret 直接
   `SIGSEGV(SI_KERNEL, si_addr=NULL)`。frame+0xb8 的 qword 要写成 `0x002b000000000033`。
4. **sigframe 偏移用独立 harness 定**：`work/12067_goodbye/srop_harness.c` 用
   `mov rsp,frame; mov rax,15; syscall` 直接验证「`bytes(SigReturnFrame())` 放在 `rsp` 处」是对的、
   且 `uc_flags` 取值（含被 push 覆盖成 0x401241）不影响；比在靶子上盲试省得多。
5. `ycb.py download 12067` 拿到的是 94 字节的 `{"code":"40403"...}` 兜底 JSON；
   真附件要用 `detail.json` 里的 `attachment.url` 直接 `curl`（1.1 MB zip）。
6. 平台 flag 前缀是 **`DASCTF{}`** 而非 `flag{}`；`ycb.py submit` 会自动剥壳，别手改。

## 6. 产出

- `scripts/12067-solve.py` —— 可复现成品。`--host/--port` 打远端；`CHAL_DIR=… --path=flag` 本地训练；
  `--ls` 走 `openat("/") + getdents64 + write` 列目录；不带 `--path` 时按
  `/flag → flag → /flag.txt → /home/ctf/flag → /app/flag → ./flag …` 顺序自动试。
- `work/12067_goodbye/exp_final.py`（同源草稿）、`srop_harness.c`（sigframe 校验）、
  `strace2.txt`（`rt_sigreturn(...) = 0` + 后续 openat/sendfile 证据）。
- 本地自测 flag：`work/12067_goodbye/flag` = `flag{LOCAL_SROP_TEST_12067}`（3/3 稳定复现）。
