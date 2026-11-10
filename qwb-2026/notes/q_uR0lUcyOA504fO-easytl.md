# q_uR0lUcyOA504fO · easytl (PWN, 强网杯 2026 线上赛)

状态：**未解出**（静态+本地动态逆向已完成，缺"可达的内存破坏原语"）
远程：`nc <target> 1443`（TLS 1.3，实测 1 次读探 + 1 次复连，均 50–60 ms，正常）

---

## 1. 附件与保护

```
easytl.zip -> easytl/easytl  (5,708,848 B, x86-64 ELF, 全静态, stripped, GCC 13.3.0 Ubuntu 24.04)
              easytl/server.crt  easytl/server.key
```

`checksec`：Partial RELRO / **No PIE** / NX / （动态段看不到 canary，但反汇编里几乎每个函数都有
`fs:0x28` + `__stack_chk_fail@0x795ec0` ⇒ **有 canary**）。静态链接 OpenSSL（内嵌
`TLS_AES_256_GCM_SHA384`、AES/MD5/CFB、`../ssl/ssl_cert.c`、`myserver.c` 等字符串）。

`main = 0x40445a`：`socket/bind(1443)/listen` → `SSL_CTX_new(TLS_server_method())` →
`SSL_CTX_set_ciphersuites("TLS_AES_256_GCM_SHA384")` → 装 3 个回调（见 §4）→
`SSL_CTX_use_certificate_file("server.crt")` → `SSL_CTX_use_PrivateKey_file("server.key")` →
`accept` + **三重 fork**（每连接一个子进程，处理完即退）→ SSL_accept → 0x404347 命令循环。

> 关键结构性事实：**状态是每连接独立的**（fork 出来的子进程）。列表/注释/全局缓冲都不跨连接，
> 但 canary、ASLR 布局（父进程 fork）**跨连接完全相同**。

## 2. 命令协议（已本地跑通，见 scripts/q_uR0lUcyOA504fO-solve.py）

4 字节小端 opcode，随后 payload 由"逐字节读到 0x0a 为止"的函数读取；未知 opcode → 回 5 字节 `error`。

| opcode (LE bytes) | 语义 | 载荷 |
|---|---|---|
| `0x38432a87` (`87 2a 43 38`) | **add** | `name[16] ‖ key[16] ‖ u32 size(1..0x380) ‖ data[size]`，最多 0x40 条 |
| `0x6c5a5850` (`50 58 5a 6c`) | **enc** | `md5[16]`：对 node->data 原地 CFB-128 加密（AES-128 key=name，IV=key域） |
| `0x363bbed5` (`d5 be 3b 36`) | **dec** | 同上，解密 |
| `0x89954d3e` (`3e 4d 95 89`) | **get** | `md5[16]` → 回 `data[size]` |
| `0xdc375626` (`26 56 37 dc`) | **edit** | `md5[16]`，**另一条 TLS 记录**再发 `u32 newsize ‖ newdata` |
| `0xd21fef03` (`03 ef 1d d2`) | **del** | `md5[16]` → 摘链 + free(data) + free(node) |

节点结构 `calloc(1,0x60)`：`md5(data)[0x0..0xf]`、pad、`name[0x20]`、`key[0x38]`、`data*[0x50]`、`u32 size[0x58]`。
**查找键 = md5(data) 前 16 字节**（gdb 实测：`md5("hello-world-1234")=adfb2717d909dbfaad4f93abc14f14dc`，与节点完全一致）。
`add` 里 `data = calloc(1, size+0x10)`；`get/enc/dec/del` 的 digest 读是**单次 SSL_read，必须恰好 16 字节**，
所以 opcode+digest 和后续载荷必须分两条 TLS 记录发（否则 `n != 0x10` → exit(1)）。

本地端到端已验证：`add → get → edit → get` 全通（`evidence/q_uR0lUcyOA504fO-local-demo.log`）。

## 3. 应用层安全性结论

- 所有读长度都受 `0x400` 缓冲与 `memset(0x408)` 保护；`size ≤ 0x380`（`0x24+0x380=0x3a4 < 0x400`、`4+0x380=0x384 < 0x400`）。**没有直接溢出**。
- 唯一两条危险分支被 **md5 魔数** 把守（`.rodata`）：
  - `get`：`md5(data) == M1 = 66 55 8c 3d e5 6c 1d 3e dd b3 e8 c3 ec 59 e6 d1`（0x825109）
    → `0x403d0b`：`strcat("data: ", node->data)` 写入 **0x58 字节栈缓冲**（canary 保护）。
  - `edit`：`md5(data) == M2 = 66 44 8c 3d e5 6c 4d 3e 11 b3 e8 c4 ec 59 e6 d1`（0x82511a）
    → `free(node->data)` **不清指针** ⇒ 悬垂指针（get 可 UAF 读，edit 可 double free）。
- **M1 与 M2 只差 4 个字节**（byte1/6/8/11）；两个不同数据的 md5 不可能共 12 字节 ⇒
  至少一个不是 md5 输出。已穷举验证：不是二进制里任何可打印字符串的 md5/sha1/sha256，
  不是 0x825038/0x825060/0x8250a0 那几个 hex 常量及其拼接的 md5，也不是 ≤3 字符短串（70 字符表）。
  **结论：这两条分支目前看是死代码/作者后门，缺 preimage ⇒ 走不通。**

## 4. 隐藏的 TLS 回调子系统（真正可疑的地方）

`0x4032bb` 在 SSL_CTX 上装了：

1. **SNI 回调 `0x40320a`**：`SSL_get_servername(ssl,0)` → 全局 `G970f50 = calloc(strlen+0x10)`，
   `G970f58 = strlen`。servername 完全由客户端控制（TLS 上限 255 字节）。
2. **info 回调 `0x4030d5`**：`type & 0x2002`（accept 握手中）时把 `G970f60/68` 指向
   SNI 缓冲或 PSK 缓冲且 `G970f68 = G970f58`（SNI 长度，**无上限检查**）；
   `type & 0x4004`（收到 read alert）时可能调用 `0x40304d`。
3. **`0x40304d`**：`char buf[0x50]; memcpy(buf, G970f60, G970f68); fprintf(stdout,"%s error\n",buf);`
   ⇒ 若 `G970f40` 已被 PSK 回调设置，则走无上限分支，`G970f68 = strlen(SNI) ≤ 255` →
   **0x50 栈缓冲溢出（canary 保护）**。
4. **PSK find-session 回调 `0x402dbb`**（存在 SSL_CTX+0x308，实测确认就是它）：
   要求 TLS1.3 external-PSK identity **恰好** `1401518dc5d7641ccd41593a5d812410`
   （32 字符，`0x825038`），否则 `*out=0` 返回 0；
   符合后用 `.rodata` 的 hex 常量 `c8ad2a35c51b87a466e22bc337696f08`
   + `07ff73500ee154ee71bee86d0b6bc358`（0x825060/0x825080，共 64 hex）做密钥派生
   （`0x4e0290` → `0x4d8e60(…, identity, 0x20, …)`），`SSL_SESSION_new` 后填好后返回 1。

本地实测（gdb 断点）：`openssl s_client -psk_identity 1401518dc5d7641ccd41593a5d812410 -psk <hex> -tls1_3`
**能命中 0x402dbb**（rsi 就是那 32 字符），回调返回 1，但随后 OpenSSL 报
`tls_parse_ctos_psk: bad extension`（statem/extensions_srvr.c:1199）→ SSL_accept 失败 → exit(1)。
即"伪造 session"还不被接受（缺 hash/cipher/master_key/binder 一致）。

## 5. 为什么卡住

- 应用层两条危险分支要求 md5 preimage，**不可达**；
- 隐藏层唯一的内存破坏是 `0x40304d` 的栈溢出，但复制的**源**是 0x30 字节的 identity 堆块
  （`calloc(0x20+0x10)`，内容只有固定 32 字节 + 0x10 零），越界部分来自相邻堆块
  （session/BN 等，内容不可控） ⇒ 即使能用 fork-server 的相同 canary 做逐字节爆破，
  **覆盖 canary 的那几个字节也不是我们写的**。
  除非能把"下一个堆块"变成可控数据（例如让 SNI 缓冲落在 identity 块之后），目前没找到办法。
- 本地无法确定 flag 落点（二进制里没有任何 flag/文件读取），推测需要 RCE 后读 `/flag*`。

## 6. 下一步最值得试的两个方向

1. **把 PSK 握手下通**：弄清 `0x4e0290`/`0x4d8e60`/`0x41ae80`/`0x413330`/`0x41c080`/`0x41c060`
   分别是哪些 OpenSSL API（session 需要 hash/cipher/master_key/id 与客户端 binder 匹配），
   然后**手写 ClientHello**（自己算 binder：HKDF-Extract/Expand，SHA-256，psk_ke 模式）
   把 identity `1401518dc5d7641ccd41593a5d812410` 的 PSK 会话跑通。
   跑通后才有机会碰"认证后的隐藏行为"，也可能是本题真正的入口。
2. **让 `0x40304d` 的源可控**：构造堆风水 —— 先发超长 SNI（占一块 `strlen+0x10`），
   再发 PSK identity（0x30 块），确认 identity 块之后紧跟的是 SNI 块（glibc 顺序/尺寸配合），
   这样溢出内容 = `A(0x20)+零(0x10)+chunk头(0x10)+SNI字符串` → 从偏移 0x30 起完全可控；
   再配合 fork-server 相同 canary（每连接一次，串行、间隔 300–400 ms、最多 ~1800 次）
   做 canary 逐字节爆破 → 栈 ROP（No PIE，`0x402000` 起；需要先找 `pop rdi; ret` 等 gadget）。

## 7. 工具与证据

- 客户端/协议实现：`scripts/q_uR0lUcyOA504fO-solve.py`（`probe` / `demo`）
- 本地验证日志：`evidence/q_uR0lUcyOA504fO-local-demo.log`
- 远程探活：`evidence/q_uR0lUcyOA504fO-remote-probe.log`
- gdb 回调追踪（0x402dbb / 0x40304d 命中记录）：`evidence/q_uR0lUcyOA504fO-gdb-callbacks.log`
- 草稿：`work/q_uR0lUcyOA504fO_easytl/`（`full.asm` 全量反汇编、`probe.py`、`tr2.gdb`、
  端口改 1443/2443 的补丁副本）

## 8. 连接纪律执行情况

只连了远程 **2 次**（同一脚本内串行，间隔约 1 s），每次一个 TLS 握手 + 1 个未知 opcode 读回包，
实测 52–60 ms，正常；未并发、未扫描、未爆破。

---

# 9. 追加（第二轮）：PSK 握手已打通 ✅

## 9.1 结论速览

| 项 | 值 |
|---|---|
| PSK identity | `1401518dc5d7641ccd41593a5d812410`（0x825038，32 字符，`strlen==0x20` 硬校验） |
| 硬编码 hex 键 | 0x825060 起**96 个 hex 字符**（=48 B）：`c8ad2a35c51b87a466e22bc337696f08` + `07ff73500ee154ee71bee86d0b6bc358` + `422a0e90fca2ac1be5929a7be06fd428`（三串连成一条 NUL 结尾字符串，**不是**两串） |
| **PSK（= session master_key，64 B）** | `HMAC-SHA512(key=hex2buf(上面48B), msg=identity)`<br>`8bd3d02f8ac2e2a063735779b0a2ea980d0baa0831ed9fce8b8125d79af598b51382d3231b15634dc4e5c51aa1e57afc038bbdf11217b402887ad744f737e952` |
| session cipher | `TLS_AES_256_GCM_SHA384`（0x1302）→ **binder hash=SHA-384，binder 48 B** |
| session protocol version | `SSL_version()`（0x412b80 = `return *(int*)ssl`） |

回调 0x402dbb 的反编译要点（全部 gdb 实测确认）：
`strlen(identity)==0x20 && memcmp(identity, A, 0x20)==0` → `G970f40 = calloc(identity_len+0x10)`，`G970f48=0x20`；
`0x4e0290` = `OPENSSL_hexstr2buf(str,&len)` 的 3 参 thunk（`mov $0x3a,%edx` = sep `':'`）；
`0x4d8e60` = `EVP_Q_mac(libctx=0, name="HMAC", propq=0, subalg=md, params=0,
key, keylen, data, datalen, out, outsize, outlen)` 的封装（`0x4c35f0=EVP_MD_get_size`；
`0x4c9900` 返回静态 digest 表项；`0x4c34d0` 取 EVP_MD）；digest=SHA-512 → outlen=64；
`0x41ae80`=`SSL_SESSION_new`，`0x413330`=`SSL_SESSION_set1_master_key`，
`0x41c080`=`SSL_SESSION_set_cipher`，`0x41c060`=`SSL_SESSION_set_protocol_version`。

## 9.2 服务端 `tls_parse_ctos_psk` 的校验顺序（0x439e..–0x43a3..）

1. 调用 `s->psk_find_session_cb`（SSL+0x998）→ 我们的回调；
2. `SSL_CIPHER_find`(0x40c720，走 method+0x90 的派发) 由硬编码字节 `13 01 13 02 13 06` 取 cipher → 实得 **TLS_AES_256_GCM_SHA384**；
3. `SSL_SESSION_set_cipher / set_protocol_version`；
4. **digest 相等性检查**（0x43a01b，实测 `eax=1` 相等）；
5. `EVP_MD_get_size` → **binder 长度必须 48**（0x43a313：`rdi=0x30 rdx=0x30` 才过）；
6. `tls_psk_do_binder`（0x431f50）验证 binder —— 失败即 `binder does not verify`
   （extensions.c:1630，alert illegal_parameter 47）。

## 9.3 binder 计算公式（踩坑点）

```
early_secret = HKDF-Extract(salt = 0^hlen, IKM = PSK)
binder_key   = HKDF-Expand-Label(early_secret, "ext binder",
                                 Transcript-Hash("") , hlen)      # ← context 是 Hash("") 不是空!
finished_key = HKDF-Expand-Label(binder_key, "finished", "", hlen)
binder       = HMAC(finished_key, Hash( Truncate(ClientHello) ))  # 截断到 identities 之后
```
自检方法：用抓到的 `openssl s_client` ClientHello（`evidence/q_uR0lUcyOA504fO-sclient-clienthello.bin`），
把它的 binder（SHA-256 版）复算出来 → **完全一致** `deedfcce...f5ba85954`，证明公式与截断位置都对。

## 9.4 结果

用 `scripts/q_uR0lUcyOA504fO-psk.py`（以真实 ClientHello 为模板，替换 pre_shared_key 段、
按 SHA-384 重算 48 B binder）请求：

```
resp 241B: 16 03 03 00 80 | 02 00 00 7c | 03 03 <random> | sid(32)
           1302                              <- TLS_AES_256_GCM_SHA384
           ext 002b supported_versions 0304
           ext 0033 key_share x25519
           ext 0029 pre_shared_key 0000      <- PSK 被接受
```
完整字节：`evidence/q_uR0lUcyOA504fO-serverhello.bin`。
**`tls_parse_ctos_psk: bad extension` 已彻底消失，PSK 认证通道建立。**

## 9.5 对手上原有两条卡点的影响

- `G970f40`（identity 缓冲）现在**确定可被置上**（只要发对 identity），
  这是 info 回调分支 B 走"无长度上限"`0x40304d` 溢出的前提条件 —— 该前提已成立。
  但溢出源仍是 0x30 B 的 identity 块，canary 那 8 字节仍不来自我们的输入。
- 应用层那两条 md5 魔数分支依旧不可达（preimage）。
- 下一步（未做）：① 用自带私钥的 key_share（x25519 自算）把 TLS1.3 握手**跑完**，
  得到一条完整的 PSK 会话并观察应用层是否有新分支；② 堆风水让 `0x40304d`
  的源可控后再谈 canary。

---

# 10. 追加（第三轮）：(a) 全会话打通 ✅ / (b) 判定为死路 ❌

## 10.1 (a) TLS1.3 PSK 全会话 —— 已完成

用 C 客户端 + `SSL_CTX_set_psk_use_session_callback`（`scripts/q_uR0lUcyOA504fO-psk-client.c`，
本机无 openssl 头文件，全部手写声明 + 直接链 `libssl.so.3`/`libcrypto.so.3`）：

```
HANDSHAKE OK: version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384
sent add (56 bytes) / sent get (20 bytes)
get -> n=16 "hello-world-1234"
unknown-op -> "error"
```
（`scripts/q_uR0lUcyOA504fO-psk.py` 的自写 ClientHello 只到 ServerHello；
C 客户端走完 key schedule，得到可读写的 `SSL*`。）

**认证后 vs 未认证路径的行为差异：无。** `add/get/del/edit/enc/dec` 与 `error` 回包完全一致
（见 `evidence/q_uR0lUcyOA504fO-psk-full-session.log`）。SO PSK 只是把"握手"这层难度解决掉，
应用层逻辑没有新分支。

## 10.2 关键映射（判据）

| 观察 | 结论 |
|---|---|
| 回调里 dump 出 64B master_key 逐字节 == `HMAC-SHA512(hex2buf(0x825060..96hex), identity)` | PSK 确认 |
| `0x43a313` 处 `rdi=0x30 / rdx=0x20` | 服务端要 48B binder（SHA384），s_client 发 32B ⇒ 原 bad extension |
| 复算 s_client 的 SHA256 binder == `deedfcce…f5ba85954` | binder 公式与截断位置正确 |
| PSK 会话下 `add/get/error` 与未认证完全一致 | 应用层无认证分支 |

## 10.3 (b) `0x40304d` 溢出 —— 可达但**不可利用**（本地已验证后关闭）

本地（端口改写副本）PSK + 255 字节 SNI + 原始 close_notify：

```
server stdout:
140151 error
1401518dc5d7641ccd41593a5d812410 error
*** stack smashing detected ***: terminated
```

即：`memcpy(buf[0x50], G970f40, G970f68=strlen(SNI)=255)` 确实触发、canary 确实被打坏。
但**源内容不可控**（详见 `evidence/q_uR0lUcyOA504fO-heap-shape.md`）：

```
G970f40 = calloc(1, identity_len+0x10) = calloc(1,0x30)
  [0x00..0x1f] identity（固定 32 字符，服务端强制）
  [0x20..0x2f] calloc 清零
  [0x30..0x3f] == 下一个堆块的 prev_size/size
  [0x40..    ] == 下一个堆块的负载（SSL_SESSION / EVP_MAC，非攻击者数据）
canary 在 buf+0x58 ⇒ 命中堆上我们不控制的字节
```
分配顺序（SNI 扩展先于 pre_shared_key）也堵住了"让 SNI 块紧跟 identity 块"的风水手法。
⇒ **只能造成 DoS（子进程 abort），无法控制返回地址**。此路线关闭。

## 10.4 当前唯一未排除的方向：静态二进制与 OpenSSL 3.5.5 的 **patch-diff**

应用层经逐函数复核是内存安全的（所有读长度受 0x400 缓冲与 `size ≤ 0x380` 约束），
两条 md5 魔数分支要 preimage（且 M1/M2 共 12 字节 ⇒ 不可能同时是 md5 输出），
隐藏 TLS 层唯一的溢出也不可利用 ⇒ **剩下最可能的假设是作者改过内嵌的 OpenSSL 代码**。

可行做法（本轮未做）：拿本机 `libssl.so.3` / `libcrypto.so.3`（同为 3.5.5，Ubuntu 24.04，2026-09-30 构建）
与本静态二进制做函数级 diff —— `work/q_uR0lUcyOA504fO_easytl/ident.py` 已经能按归一化指令序列
匹配同名函数（已验证 `SSL_SESSION_set_cipher` 13/14、`SSL_SESSION_set_protocol_version` 14/14、
`EVP_MD_get_size` 13/14 精确命中），把它改成"报不一致"即可定位被改写的函数。

---

# 11. 追加（第四轮）：MD5 假设被证否 + **找到真正的漏洞（可控栈溢出）**

## 11.1 MD5 patch-diff = 阴性（三重硬证据，详见 evidence/…-MD5-and-real-bug.md）
- K 表 64 常量（从 0x636ed0 的 `lea imm32` 提取，OpenSSL 汇编实现的常量内嵌在代码里）、
  位移表 64 项（`rol $imm`）：**0 处差异**。
- **行为级 oracle**（服务端 md5 即节点键）：200 例（覆盖 1..0x380 全部 MD5 padding 边界 × 5 种填充）
  **全部与标准 MD5 一致**。
- AES-128-CFB（enc/dec）行为级 oracle：14 长度全部与标准一致。
⇒ M1/M2 是**真 preimage 不可达的死常量**；两条 md5 魔数分支彻底排除。

## 11.2 真漏洞：PSK identity 长度未受约束 ⇒ 0x40304d 完全可控栈溢出
回调 0x402dbb 用 **`strlen(identity)==0x20` + `memcmp(identity,A,0x20)`** 校验，但随后
`calloc(1, identity_len+0x10)` + `memcpy(…, identity, identity_len)` 用的是**真实长度**。
identity 第 33 字节放 `\x00` 即可通过 strlen 检查，而 identity 本身可任意长、任意内容。

gdb 实证（identity = A + NUL + "ABCDEF…"，共 256B）：
```
G970f40=0x9d6020 G970f48=32
chunk = "1401518dc5d7641ccd41593a5d812410\0ABCDEFGHIJ…"   ← 攻击者数据铺满整个堆块
```
于是 0x40304d 的 `memcpy(buf[0x50], G970f40, strlen(SNI))` 变成
**源可控（identity 内容）+ 长度可控（SNI 长度 ≤255）** 的栈溢出（canary 在 buf+0x58）。
实测 identity 256B + SNI 96B + close_notify → `*** stack smashing detected ***`。

利用路线（未完成）：fork-per-connection ⇒ canary 跨连接相同 ⇒ 逐字节爆破；
No PIE + 溢出区就在当前栈上 ⇒ 返回地址之后的链项天然连续，不需要栈泄漏。
唯一缺口 = canary 值（需爆破）与 ROP 落地。

---

# 12. 追加（第五轮）：canary + gadget 齐备，卡在 255 字节长度上限

- 本地 canary（fork 后所有子进程相同）= `0xe453eaffaef45000`（gdb @0x403091，buf=rbp-0x60）。
- gadget 全部 objdump 核实：`pop rax`=0x5f6c9a、`pop rdi`=0x4251bd、`pop rsi`=0x5e9a79、
  `pop rdx`=0x52f0d2、`syscall;ret`=0x792859；可写 .bss 0x970ee0–0x97a3d8。
- 载荷布局：identity[0:32]=A、[32]=0x00（过 strlen 校验）、[0x58]=canary、
  [0x60]=saved rbp、[0x68:]=ROP；SNI 长度 = 0x68+链长。
- **硬约束**：`G970f68 = strlen(SNI) ≤ 255`（TLSEXT_MAXLEN_host_name）⇒ 链空间仅 55 字节 = 6 qword，
  read+execve 的常规链（~18 qword）装不下。下一步需 4 条路线之一（详见
  `evidence/q_uR0lUcyOA504fO-rip-control-conditions.md` §4）：
  ①`xor esi,esi;xor edx,edx` 合并零化 gadget + .bss/堆内已有 "/bin/sh"；②用 0x970f40 里保存的
  identity 堆指针做 load-gadget 指到我们的数据；③leave/ret 部分覆盖；④确认 libc 是否链接了
  `system`/`posix_spawn` 之类可直接 `pop rdi; call` 的目标。

---

# 13. 追加（第六轮）：**本地 RIP 控制成功（拿到 id 回显）**

## 13.1 结果
```
$ python3 scripts/q_uR0lUcyOA504fO-exploit.py 127.0.0.1 3443 267928338d294d00 4
identity=248 sni=248 CH=2019 fd=4
ServerHello? 160303008002 (245 B)
=== RAW OUTPUT (202 B) ===
uid=1000(fragranstea) gid=1000(fragranstea) groups=1000(fragranstea),65534(nogroup),...
PWNED-MARKER
```
证据：`evidence/q_uR0lUcyOA504fO-local-RIP-control.log`

## 13.2 链路（全部实测）
1. TLS1.3 外部 PSK 握手（PSK = HMAC-SHA512(hex2buf(0x825060..96hex), identity)，48B SHA-384 binder）；
2. PSK identity 前 32 字节 = `1401518dc5d7641ccd41593a5d812410`、第 33 字节 `\x00`
   ⇒ `strlen()==0x20` 通过，但 `calloc(1, identity_len+0x10)` + `memcpy(…, identity_len)`
   把 **248 字节攻击者数据**放进 `G970f40`；
3. 发原始 close_notify ⇒ info 回调 `0x4004` ⇒ `0x40304d` 执行
   `memcpy(buf, G970f40, strlen(SNI))`，SNI=248 ⇒ 覆盖 buf[0..247]：
   `[0x58]=canary`、`[0x60]=saved rbp`、`[0x68:]=ROP(144B, 18 qword)`；
4. ROP：`read(fd=4, 0x97a000, 0x100)` → `execve(0x97a000, argv=0x97a040, 0)`
   其中 `.bss` 里放 `/bin/sh\0` / `-c\0` / `sh -c ...` 命令串与绝对地址 argv
   （.bss 是固定地址，argv 的绝对指针可预先算好）；
5. 命令写成 `<cmd> >&4`，shell 把输出直接写到我们的连接 fd（绕过 TLS 层，客户端收原始字节）。

## 13.3 关键数字
| 项 | 值 |
|---|---|
| 溢出长度上限 | `strlen(SNI) ≤ 255`（TLSEXT_MAXLEN_host_name）⇒ 链空间 255-0x68 = **151 B = 18 qword**（正好装下 read+execve 18 qword）|
| canary 位置 | `buf+0x58`（buf=rbp-0x60）；低字节 0x00 |
| 连接 fd | **4** |
| gadget | pop rax 0x5f6c9a / pop rdi 0x4251bd / pop rsi 0x5e9a79 / pop rdx 0x52f0d2 / syscall;ret 0x792859 |
| 暂存区 | .bss 0x97a000（可写区间 0x970ee0–0x97a3d8）|

## 13.4 尚未做（需批准）
远程 only：canary 逐字节爆破（fork ⇒ 跨连接相同）。每个候选把 SNI 长度设为 0x58+i，
若该字节正确则 canary 校验通过、连接**不 abort**（可观测），否则子进程 abort。
除 canary 外，chain/payload 已在本地全通，远端二进制与本地同一构建 ⇒ 可直接复用。
