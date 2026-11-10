# 12078 · cacheline（PWN / MEDIUM / 500）

- **flag**: `DASCTF{98938704929480850631344062720644}`（平台只收 `{}` 内：`98938704929480850631344062720644`）
- **提交**: `{"code":"00000","message":"解题成功!","result":true,...}`（1/50，exit=0）
- **工具**: objdump / Ghidra(fw-decompile) / pwntools(ELF checksec) / python3 + musl ld 本地重放
- **SKILLS**: competition-reverse-pwn, ctf-pwn
- **SKILLS_USED**: ① `competition-reverse-pwn` 的“先被动 triage（file/checksec/strings/imports）再决定 reverse-first 还是 exploit-first”——
  由此发现 seccomp 禁 execve，从而否掉“拿 shell”路线、转向“文件 fd 7 + 作者预留 ROP gadget”；
  ② `ctf-pwn` 的 checksec 判据（Full RELRO/PIE/NX，musl）→ 不碰 GOT，改打函数指针 + rsp 迁移。

## 结构（三层同一套 keyed-hash 对象图）

```
client --HTTP--> nginx worker(cacheline.so)
                   | connect /run/cacheline-broker.sock
                   v
                cachebroker (uid1001, fork/conn, seccomp 禁 execve/execveat)
                   | connect /run/cacheline-vault.sock + 握手 "CLV4/VAULT"
                   v
                cachevault (uid1002, seccomp, 启动即 open("/home/vault/flag") -> fd 7)
```

三层都用同一个自定义 hash（splitmix64/siphash13 变体，`H(k1,k2,buf,n)`），
并且**每层都有自带的 key 泄漏原语**：拿到 key 后就能伪造该层全部"已认证对象"。

## 三层各自要点

### L1 nginx 模块（cacheline.so）
op/data 两个 query 参数，11 个操作 + 全局 stage(DAT_00106600)：
create(0x180 CLTACKT) → resize(复用同一 freed chunk→CBEACON 0x128) → ledgeropen(CLLEDGR 0xf8)
→ beacon(泄漏) → ledger(泄漏) → route(CLLROUT 0x1a8) → seal(CLLSEAL 0xd8) → grant(CLGRANT 0x218)
→ voucher(CVOUCH 0x108) → commit(激活) → broker(把 hex 转发给 broker socket)。
对象 malloc 后由 request-pool cleanup free，全局指针跨请求悬垂 —— 题名"缓存行跨对象生命周期"即此。
泄漏：`beacon` 打印 nonce、rol(nonce,0x11)^handler_addr、hash^key2、hash^key1；
`ledger` 打印 ledger nonce、hash^conn、hash ⇒ 反出 handler 地址/两把 key/req->connection。

### L2 broker
命令 'V'（probe/aperture 同名 index 时）直接回 8 字节：index0→base+0x4000(FUN_00104000)、
index1→key1、index2→key2。随后伪造 CLCPERMIT/CLMANDATE + 4×(CLSHARD,CLSTAMP)，
'C' commit 算出 pc = PERMIT[1]^MANDATE^key2^ror(MANDATE[5],0x13)；合法链=base+0x2580(空函数)，
改成 base+0x4000 ⇒ broker 变成到 vault 的 raw 双向代理（先发握手）。

### L3 vault
16 字节头 `CLV4 | cmd | idxA | idxB | 0 | len(u32) | seq(u32)`（seq 必须单调增）。
cmd 1 是一个 16 字节指令的小 VM（0x41 加偏移 / 0x53 读 keys[i+3] / 0x67 xor / 0x79 校验 / 0x8b break），
可泄漏 vault key struct 的 keys[0..2]（种子、自指针、代码指针=base+0x17f0）⇒ 推出 4 把 hash key。
cmd 0x40 装配 CONTEXT+0x40..0x440（来自 4 个 CLCHUNK 的 0x400 字节）后调用
pc = CONTEXT[1]^CLVPLAN^key2^ror(CLVPLAN[5],0x15)；作者在 .text 尾部留了 gadget 表：
+0x44e0 `lea rsp,[rdi+0x40];ret`、+0x44f0 `pop rdi;ret`、+0x4500 `pop rsi;ret`、+0x4510 `pop rdx;ret`。
rdi=CONTEXT ⇒ rsp=CONTEXT+0x40 正好是我们可控的 0x400 字节 ⇒ 标准 ROP：
`read(7,buf,0x100)` + `write(1,buf,0x100)`，fd 7 就是 flag。

## 坑
1. **import 只是"置标记位"**：cmd 1 / broker 'V' 都要求对象先被"导入"过（标记位），
   但 import 会整体覆盖对象从而毁掉 hash ⇒ 正确顺序是 create→link(vault 自己算 hash)→dump→**原样 import**。
2. **key 是 per-connection 的**：三层都要"同一连接内先泄漏再伪造"。用不同连接拿到的 key 去算会全错（我在此浪费了一轮）。
3. `CLVPLAN[5]` 里的常量是 **运行时地址 base+0x17f0**（`lea`），不是 0x17f0；用 rol 不是 ror。
4. CONTEXT[1] 同时被 VALCRED[5] 与 CLVPLAN[4] 校验；CLVPLAN[4] 必须 == CONTEXT[1]（不是 ticket nonce）。
5. 模块每请求只做一次 read(≤0x400)，响应可能被切 ⇒ 客户端要按字节流累积；空 blob 在 state<9 会毒死 broker。

## 产出
- `scripts/12078-solve.py`（成品，HOST/PORT/PATH 参数化）
- `work/12078_cacheline/{FINDINGS.md,dec,dec2,local/}`（反编译、本地测试床、分步脚本）

## 离线验证（本机，未修改的原始二进制）

1. **L2+L3 全链**：`work/12078_cacheline/local/test_final.py` 用 shim 模拟"模块的读写语义"，
   直接接本地 broker socket，跑 `do_broker` + `do_vault`，输出 `FAKEFLAG{local_test_flag}`。
   本地只改了 ① socket 路径（/run → 相对路径）② setuid/setgid 调用（沙箱非 root）③ flag 路径。
2. **L1 伪造对象**：`work/12078_cacheline/local/mod_sim.py` 是按反汇编独立重写的四个校验器；
   `forge_l1()` 造出的 CLLROUT/CLLSEAL/CLGRANT/CVOUCH 全部通过，commit 的 XOR 也为 1。
3. **L1 泄漏反解**：用模拟的 `beacon`/`ledger` 打印文本反解，handler/key1/key2/conn 全部还原成功。
   （这一步抓到并修掉了两个真 bug：CLGRANT 的第 3 个 hash 缓冲区应从 G[0x40] 起算，
    CVOUCH 的 hash 缓冲区应从 V[0x30] 起算——不是从对象偏移 0x08 起。）

nginx 本身无法离线跑（缺 musl 版 pcre2/ssl/z），L1 的 stage 机只能上真靶机验证。

## 请求预算
单条 keepalive 连接约 166 个 HTTP 请求（L1 11 + L2 71 + L3 84），不新建连接。

## 远程实战（<target>:16611 /cacheline，165 条请求一条 keepalive 连接）

```
create   -> created      resize  -> staged   ledgeropen -> opened
beacon   -> n=.. a=.. e=.. k=..              (泄漏 handler + 两把 key)
ledger   -> n=.. o=.. t=..                   (反出 req->connection)
route    -> routed    seal -> sealed    grant -> granted    voucher -> vouched
commit   -> activated  (stage=8)
broker   : 'V' 三次泄漏 base/key1/key2 → 伪造 PERMIT/MANDATE + 4×(SHARD,STAMP)
           → 'C' commit 把 pc 改指 FUN_00104000 → broker 变成到 vault 的 raw 代理
vault    : cmd 1 三次泄漏 keys[0..2] → 推 4 把 key → 建 8+8 个对象并逐字段伪造
           → cmd 0x40 把 pc 改指 `lea rsp,[rdi+0x40];ret` → ROP: read(7)+write(1)
结果：HTTP 响应体里直接出现 /home/vault/flag 内容 → DASCTF{...}
```

### 实战中靠"远程自校验"抓到的三个 bug
1. `key1 = beacon[0x50] ^ H(handler, nonce, **[key2, nonce]**, 2)` —— 第二段 hash 的缓冲区是
   `[key2, nonce]` 而不是 `[key2, handler]`。定位方法：用 **ledger[0x48] 作单点 oracle**
   （`= H(key1,key2,[conn,handler,bn,ln],4)`，输入全可由打印字段推出）。一次请求即判定，
   避免了盲试 route。判对的旁证：反解出的 `conn = 0x7f73bc663790` 是合法指针。
2. CLGRANT 三处：`G[0x50] == beacon nonce`、`G[0x58] == ledger nonce`、
   `G[0x80]` 的 8 字缓冲区第 3/4 元素是 beacon nonce 与 ledger nonce（不是 route 的 tag）。
3. stage 卡死后的恢复：模块的 stage 一旦停在 4/5/…，只有 **commit 成功 → 连接关闭 → worker
   注册的 cleanup 调 `_exit(0)`** 才能让 nginx 重启 worker（stage 归零）。所以"5 次无新证据就换路线"
   在这题的具体形态是：先把 L1 推到激活（哪怕 grant 的字段还没修好——不，grant 必须过），
   否则宁可等 worker 被重启。实测：一次完整 L1 跑完后连接一关，worker 立刻重启，下次可从 stage 0 重来。
