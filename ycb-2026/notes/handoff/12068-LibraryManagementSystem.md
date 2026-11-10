# 12068 · LibraryManagementSystem（2026 羊城杯 · DASCTF 平台）

> PWN / Windows x64 / `endpointType: monopoly`（无平台靶机，flag 由运维发放）
> 附件：`win_server.exe`(80 KB)、`main.exe`(89 KB)、`README.md`
> 工作目录：`work/12068_lms/` · 证据：`evidence/12068-*`

---

## 0. 结论摘要

| 项目 | 结果 |
|---|---|
| flag | **未获取**（本题 `endpointType=monopoly`：平台不给靶机，`endpoints=[]`；按 README §四，flag 只能由运维在**校验 EXP + 录屏**后发放） |
| 提交 | `NOT_ATTEMPTED`（无可提交对象；附件/二进制内**不存在** flag 字面量，全文件 grep 无 `flag{}`/`ctf{}`/`ycb{}`） |
| 认证绕过 | **已突破并验证**：patron slot 16 的 password 落点 = admin passphrase 缓冲区，17 次 enroll 即可接管管理台 |
| 内存破坏原语 | **已验证**（Unicorn 跑真实机器码）：`Delete` 不清指针 → UAF 读/UAF 写/二次 free；`Add` 不写内容 → 堆残留泄露 |
| RCE | **已推导未实测**：ASLR(HighEntropyVA)+DEP 下需先标定堆是否 LFH / `heap+0x88` 字段语义 / catalog 表偏移；本机 `wine` 不可用，无法离线标定，**没有编造偏移** |
| 交付物 | 单文件 EXP（`work/12068_lms/exploit_12068.py` → `scripts/12068-solve.py`）+ 两个 Unicorn 验证脚本 + 本笔记 |

---

## 1. 环境与协议（已确认）

- `win_server.exe`：**纯转发器**。导入只有 `WS2_32`（`WSASocketA/bind/listen/WSAAccept/WSASend`）+ `CreateProcessA` + Job Object；
  没有任何 `recv/WSARecv`。它把**客户端 socket 直接当子进程的 stdio**，子进程 `main.exe` 自己读 socket。
  → **协议 = 裸字节流**，pwntools `remote(host, 9999)` 即可；不需要 HTTP 包装。
- `main.exe`：MinGW-w64 **GCC 15.2.0** 编译的 C 程序，PE32+ x64，
  `DllCharacteristics=0x160` → **ASLR(DYNAMIC_BASE+HighEntropyVA)=on、DEP(NX_COMPAT)=on、CFG=off**，
  有 `.reloc`（约 100 项，ASLR 真实生效）。主函数 `0x140002682`，`setvbuf(_IONBF)` → 输出**无缓冲**，可以按提示串同步。
- 输入模型（很关键）：`FUN_140001440(ptr, n)` = `_read(0, ptr, n-1)` + `ptr[len]=0` + `strcspn(ptr,"\r\n")` 截断 + `strlen`。
  也就是说**每次"读一行"只调用一次 `_read`**，所以 `内容+"\n"` 必须在同一个 TCP 段里到达（脚本用 `send` + 30 ms 间隔）。

---

## 2. ★ 第一亮点：认证绕过（可复现、可写 WP 的硬结论）

### 2.1 布局

`main.exe` 的 `.bss`（`0x140019000` 起）是**手工排布**的全局数组，互相重叠：

| 符号 | 地址 | 说明 |
|---|---|---|
| `DAT_140019048` | `0x140019048` | `HeapCreate(0,0,0x10000)` 返回的私堆 handle |
| `DAT_140019050` | `0x140019050` | `*(QWORD*)(heap + 0x88)`，作 SSO 口令的 XOR 盐 |
| `ids[i]` | `0x140019060 + i*0x20` | patron 用户名，`i = 0..16` |
| `pwds[i]` | `0x140019060 + (i+0x11)*0x20` = `0x140019280 + i*0x20` | patron 口令 |
| **`admin passphrase`** | **`0x140019480`** | 16 位十六进制串 + `\0`（`CryptGenRandom` → `%02x`） |
| `flags[i]` | `0x1400194a0 + i` | patron 槽占用标志 |
| `keys[i]` | `0x140019608 + i*8` | `*(heap+0x88) ^ pwd[0:8]` |
| `DAT_140019690` | `0x140019690` | catalog 描述符表指针（私堆 `0x1c0` 字节） |

**`pwds[16] = 0x140019280 + 16*0x20 = 0x140019480`** —— 正好是 admin passphrase 的缓冲区。

### 2.2 为什么能写到 slot 16

反汇编 `FUN_1400021bb`（`0x1400021bb`，enroll）确认：

```
0x14000233a:  cmp  dword [rbp-0x5c], 0x10     ; i <= 16  -> 共 17 个槽
0x14000233e:  jle  0x1400021df
0x14000228b:  add  rax, 0x11                  ; (i + 0x11)
0x14000228f:  shl  rax, 5                     ; * 0x20
0x140002296:  lea  rax, [0x140019060]         ; pwd 落点
0x1400022a8:  call strcpy
```

而认证循环 `FUN_140002377` 的边界是 `i < 0x10`（只认 0..15），所以 **slot 16 只能写、不能登录** —— 作者显然是故意把它当"越界槽"留给 admin 缓冲区。

### 2.3 利用

1. `patron gateway → 1. Enroll` 连续 16 次，填满 slot 0..15；
2. 第 17 次 enroll 自动选中 slot 16，口令填 `C`（8..31 字符，无 CR/LF）；
   `strcpy` 把 `C` 写进 `0x140019480` —— admin passphrase 被覆盖；
3. 回主菜单 `1. Staff & Administration`，口令输入 `C`，`strcmp(input, 0x140019480)==0` → 进入
   `ARCHIVES ADMINISTRATION CONSOLE`（`FUN_140001af5`）。

### 2.4 验证方式（本机 wine 不可用，故用 Unicorn 跑真机机器码）

`work/12068_lms/emulate_auth_bypass.py`：把 `main.exe` 按 imagebase 映射进 Unicorn，
所有 PE 导入改指向 trampoline 页由 Python 实现；**被测函数是二进制里的原始机器码**。

```
[1] enroll 17 个 patron ... slot 16 全部 flags=1                      PASS
[2] *0x140019480 = b'deadbeefcafe1234'（期望一致）                     PASS
[3] 0x140001df1 用该口令 -> 打印 "Elevated access granted"
    且控制流进入 0x140001af5                                          PASS
[4] 对照：错误口令 -> "Access denied"，未进入管理台                     PASS
[5] SSO 泄露公式 got=0x4242424241414141 == want                        PASS
```

日志：`evidence/12068-emulate-auth-bypass.log`（`SUMMARY: all checks PASS`）。

---

## 3. 第二组结论：管理台堆原语（Unicorn 验证）

catalog 描述符表（私堆，`HeapAlloc(heap, HEAP_ZERO_MEMORY, 0x1c0)`）：

```
+0x000  announcement[0x100]
+0x100  sizes[16]   (int,  每槽 +4)
+0x140  ptrs[16]    (void*, 每槽 +8)
```

四个真实函数的缺陷（`work/12068_lms/decompiled/main.exe_.c`）：

| 功能 | 地址 | 缺陷 |
|---|---|---|
| 1 Add | `0x140001568` | 校验 index∈[0,15]、size∈[1,0x400]、`ptrs[i]==0`，然后 `HeapAlloc(size+1)` —— **从不读取内容**（不调 `FUN_140001440`）。块内容 = 堆残留 |
| 2 Delete | `0x1400016cc` | `HeapFree` 后 **不清 `ptrs[i]`、不清 `sizes[i]`** → dangling pointer；同槽再删 = **double free** |
| 3 Edit | `0x1400017ab` | 上限是 **旧的 `sizes[i]`**（删除后不清），写进 `ptrs[i]` → 对已释放块 = **UAF 写**（freelist 的 Flink/Blink 就在用户区前 16 字节） |
| 4 Show | `0x14000190c` | `printf(">>> %s", ptrs[i])`，无长度限制 → 对 dangling 块 = **UAF 读** |
| 5 Broadcast | `0x140001a12` | `_read(catalog, 0x100)`，写 announcement，边界正常 |

`work/12068_lms/emulate_heap_uaf.py`（同样跑真机机器码 + NT-heap 语义模型：free 写 Flink/Blink、alloc 不校零）：

```
[D1] Add 从不写内容                                            PASS
[D2] Delete 后 ptrs[0]/sizes[0] 均未清零                        PASS
[D3] Show 读出 freelist 指针（Flink=0x30001010 -> 打印 '\x10\x10'）PASS
[D4] Edit 覆盖已释放块的 Flink/Blink                            PASS
[D5] 再 Add 同 class -> 复用该块，内容 == 我们写的               PASS
[D6] 第二次 Delete 同槽 -> huge 报错（真机 STATUS_HEAP_CORRUPTION）PASS
[D7] Broadcast 写 catalog+0                                     PASS
```

日志：`evidence/12068-emulate-heap-uaf.log`（`SUMMARY: all checks PASS`）。

> 说明诚实边界：`Show` 是 `printf("%s")`，遇第一个 `0x00` 停止。堆用户指针低字节通常非 0
> （段基址 64 KB 对齐 + 0x10 头 + 8 字节对齐槽），所以真机上一般能拿到**前 6 字节**堆地址。
> 这一点无法在本机确认到字节级，须在目标机看一眼。

---

## 4. RCE 路线（已推导，**未实测**）

`main.exe` = ASLR + DEP，且**没有任何现成 win 函数**（无 `system`/`CreateProcess`/`WinExec`；
有 `VirtualProtect`）。所以必须：地址泄露 → 堆写原语 → 劫持控制流。

必须先在目标 Windows 上标定三件事（**本机 wine 不可用，故这些数字一个都没编**）：

1. **私堆是否 LFH**：`HeapCreate(0, 0, 0x10000)` 是定长堆。注意程序调的是 `HeapAlloc(size+1)`，
   所以"size=0x20 的槽"实际是 `0x21 → class 0x30`。若走 LFH，跨 class 复用不成立，必须同 class。
2. **`heap+0x88` 到底是什么**：`SSO Authorization Key = *(QWORD*)(heap+0x88) ^ pwd[0:8]`，
   我们已知 `pwd` → 直接反推该字段。常见 Win10/11 x64 上 `_HEAP.Encoding` 在 `0x7c` 附近（16 B），
   所以 `0x88` 很可能是**堆编码 key（随机）而不是地址** —— 若是这样，作者只是拿它当 SSO 口令的 XOR 盐，
   地址泄露要靠第 3 节的 `Show`。
3. **catalog 表相对堆基址的偏移**：catalog 是 `HeapCreate` 后第 1 个分配（`0x1c0`），偏移按版本恒定。

拿到 3 之后：篡改 `ptrs[i]`/`sizes[i]` → `Show(i)` = 任意地址读、`Edit(i)` = 任意地址写（可含 `\x00`），
再按 R1/R2/R3 上 RCE：

- **R1 IAT 劫持**：把 IAT 里 `HeapAlloc`/`puts` 换成 `VirtualProtect`（已导入），堆上放 shellcode，
  先 `VirtualProtect(堆页, RWX)` 再跳过去。
- **R2 freelist 投毒**：free 侧 Vista+ 有 safe-unlink 校验（`Flink->Blink == entry`），
  优先用"分配侧取出"完成写，或先在自己可控区伪造合法 chunk 撑过校验。
- **R3 栈迁移**：若能经 `_HEAP.Lock.DebugInfo` → 进程锁链 / `PEB->Ldr` 走到模块基址，
  再 pivot 到堆上 ROP（DEP 需 `VirtualProtect` 前置）。

`exploit_12068.py --doc` 会打印同一份推导。

---

## 5. 复现步骤

```bash
cd ~/ctf-2026 && source ~/re-tools/fw-env.sh
cd work/12068_lms

# ① 本机可跑的验证（不需要 Windows）
python3 emulate_auth_bypass.py     # 认证绕过（真实机器码 + Unicorn）
python3 emulate_heap_uaf.py        # UAF 读写 / freelist 泄露

# ② 脚本自检（提示串与 main.exe 逐条比对）
python3 exploit_12068.py --selftest

# ③ 对靶机（Windows VM 里先跑：win_server.exe -p 9999 main.exe）
python3 exploit_12068.py --host <靶机IP> --port 9999 --verify
python3 exploit_12068.py --doc
```

`--verify` 自带**回滚**：任一段失败 → 断开、重连、重试（`--retries`，默认 2）。

---

## 6. 给运维的校验说明模板（可直接粘贴给 QQ 2238811670）

> 题目：12068 LibraryManagementSystem（PWN，Windows）
> 靶机启动方式：`win_server.exe -p 9999 main.exe`（按 README §二）
>
> **漏洞点 1（认证绕过，核心）**
> `main.exe` `.bss` 中 patron 口令数组与管理员口令缓冲区重叠：
> `pwds[i] = 0x140019060 + (i+0x11)*0x20`，当 `i = 16` 时 `pwds[16] = 0x140019480`，
> 而 `0x140019480` 正是管理员 passphrase（`CryptGenRandom` 生成的 16 位十六进制串）的存放处。
> enroll 循环的上界是 `i <= 0x10`（17 个槽），因此连续 enroll 16 个 patron 后，
> 第 17 个 patron 的口令会被 `strcpy` 写进管理员口令缓冲区，从而**用自己设定的口令登录
> ARCHIVES ADMINISTRATION CONSOLE**（`ARCHIVES ADMINISTRATION CONSOLE` 菜单 / 提示符
> `admin@lib-core-srv:~$`）。
>
> **漏洞点 2（内存破坏，用于 RCE）**
> 管理台 `Deaccession` 调用 `HeapFree` 后不清空 `ptrs[i]` 与 `sizes[i]`：
> - `Inspect` 变成 UAF 读（`printf(">>> %s")` 打印已释放块的 freelist 指针）；
> - `Amend` 变成 UAF 写（写回已释放块的 Flink/Blink）；
> - 同一槽重复 `Deaccession` = double free；
> 另 `Catalog Ingestion` 只 `HeapAlloc(size+1)` 却从不写入内容，`Inspect` 直接泄露堆残留。
>
> **复现步骤**
> 1. 在题目 Windows 虚拟机内执行 `win_server.exe -p 9999 main.exe`，确认 9999 监听；
> 2. 攻击机执行
>    `python3 exploit_12068.py --host <靶机IP> --port 9999 --verify`
>    —— 期望输出 `stage1 成功：认证绕过 -> ARCHIVES ADMINISTRATION CONSOLE`，
>    随后打印 `UAF 写 + 复用` 原语标定结果；
> 3. 拿到 shell 后脚本执行 `whoami` / `ipconfig`，期望输出形如
>    `desktop-xxxx\administrator`（或 `...\ctfer`）与 `Windows IP 配置 / IPv4 地址: 192.168.x.x`。
>
> **当前进度（如实说明）**
> 认证绕过与堆原语已在本地用 Unicorn **对真实机器码**验证通过（日志随附）；
> 最终 RCE 需要在贵方 Windows 环境里标定 3 个与 Windows 版本相关的量
> （私堆是否 LFH、`_HEAP+0x88` 字段语义、catalog 表堆内偏移），我们会在拿到靶机后补齐。
> 我们不会用占位 flag（如 `flag{test_flag}`）提交。

---

## 7. 坑 / 差点踩的坑

1. **`main.exe` 的 `%s` 泄露不能直接读模块基址**：`main.exe` 基址 `0x140000000`，代码地址形如
   `0x14000xxxx`，小端第 3 字节就是 `0x00`，`printf("%s")` 会立刻停 —— 只有堆/栈值的"非零前缀"能漏。
   所以判据是 **`heap+0x88` 那行十六进制**才是设计好的泄露点，而 `Show` 的 `%s` 是附带泄露。
2. **`Add` 不读内容**这一条必须靠反汇编确认（Ghidra 伪代码里 `HeapAlloc` 之后没有任何 `FUN_140001440`
   调用）；一度怀疑是 Ghidra 漏了，用 `objdump` 复核 `0x1400015ea..0x140001699` 才确认。
3. **`Edit` 的 size 上限是"旧 stored size"而不是新分配大小** —— 因为 `Delete` 不清 size。
   由此得出"不能靠它做堆块溢出"（写量始终 ≤ 原块可用字节数），真正的原语是 UAF/freelist，不是 overflow。
   这条排除了"heap overflow 打相邻 chunk header"的路线，避免了几小时空转。
4. **协议同步**：两个主菜单都用 `printf("> ")` 当提示符，而 `Show` 的输出前缀是 `">>> "`（含 `"> "`），
   所以管理台内**不能**用 `recvuntil(b"> ")` 同步，必须用 `admin@lib-core-srv:~$ `。
5. **Unicorn 复现踩的坑**（都修了，留档）：`cstr()` 一次读 512 字节越过栈顶导致 `UAF_READ_UNMAPPED`；
   `printf` 的 `%02d` 用 `struct.pack("<Q")` 后 `unpack("<i")` 抛 `struct.error`；
   `main.exe` 里 HeapAlloc 是 `call qword [IAT]`（不是 `call thunk`），必须把 IAT 改指向 trampoline 页才能拦住。
6. **平台边界**：`ycb.py env status 12068` → `{"data": false}`，`detail.json` 里 `endpoints=[]`、
   `endpointType=monopoly`。**没有靶机可打**，也没有可提交对象；附件与二进制中不存在 flag 字面量。

---

## 8. 产出

| 文件 | 说明 |
|---|---|
| `work/12068_lms/exploit_12068.py`（→ `scripts/12068-solve.py`） | 单文件 EXP：认证绕过 + 堆原语 + 回滚重试 + `--selftest`/`--doc`/`--shell-proof` |
| `work/12068_lms/emulate_auth_bypass.py` | Unicorn 跑真实机器码验证认证绕过（5 项断言） |
| `work/12068_lms/emulate_heap_uaf.py` | Unicorn 跑真实机器码验证 Add/Delete/Edit/Show/UAF（7 项断言） |
| `work/12068_lms/decompiled/main.exe_.c` | Ghidra 伪代码（前 60 个函数；应用层全在 `0x140001568`–`0x140002870`） |
| `evidence/12068-emulate-auth-bypass.log` | `SUMMARY: all checks PASS` |
| `evidence/12068-emulate-heap-uaf.log` | `SUMMARY: all checks PASS` |

## 9. 技能

- `SKILLS`: `competition-reverse-pwn`, `ctf-pwn`
- `SKILLS_USED`:
  - `competition-reverse-pwn` → 「先被动三分类（类型/节/导入/字符串），再决定 reverse-first 还是 exploit-first；
    每条结论绑定一个可观察边界（崩溃边界 / 泄露边界 / 解码边界）」：先判 `win_server`=纯转发、`main.exe`=菜单程序，
    才决定走"协议直连 + 静态逆向 + Unicorn 真码验证"，并把每个缺陷绑定到具体地址与断言。
  - `ctf-pwn` → 保护矩阵（`DYNAMIC_BASE`/`NX_COMPAT`）决定打法：ASLR+DEP 且无 win 函数 → 必须"泄露 + 写原语 + ROP/IAT"；
    Windows 部分按其 `advanced-exploits-4`（Windows SEH/ROP、IAT 相对解析）与 `field-notes` 的 Windows heap 笔记
    决定"优先 freelist 投毒而非 overflow"；`checksec` 缺失时用 `pefile` 读 `DllCharacteristics` 等价实现。
