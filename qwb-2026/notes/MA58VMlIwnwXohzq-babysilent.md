# MA58VMlIwnwXohzq · babysilent（PWN/容器）

- 平台：**532 队解出**（`work/team-board.json` @ 2026-11-01T11:52:09）；我方状态：**已解出**（`solved_by_us=true`，`solved_time=11-01 01:45:39`）。**提交者 = 本队队员，具体是谁「未记录」** —— `team/INDEX.md` 记「队员榜不按题拆开 ⇒ 不猜」；代理侧 `evidence/submit-log.jsonl` 全 749 行**无本题任何一条**，即**非代理解出**。
  > ⚠️ 本题容易照抄的旧数：`team/babysilent/README.md` 头部的「18 队」是 10-31 13:31 赛中快照，勿当终盘。
- flag：**未在本地记录**。本地仅 `idx0='f'`、`idx1='l'` 两字节经 VOTE=3（各 21/21 一致）确证；`idx2..15` 曾拼出的 16 字节串**被平台判「答案错误」**，不构成 flag（`evidence/MA58VMlIwnwXohzq-progress.txt`）。

## 解法要点

**队友未留解法记录** —— `team/babysilent/README.md` 与 `team/babysilent/EVIDENCE.md` 都只有我方叙述，无队友口径。以下机制复原**全部出自我方独立逆向，未与队友解法对照**（来源 `work/babysilent/handoff.md`）：

- `wrapper`（GCC15 ELF）**不是 seccomp**：`pipe()`→`fork()`→子 `dup2(pipe0,0); execl("./pwn")`，父 `poll(60s)` 灌 stdin。
- **`pwn` 一死 ⇒ 父 write 得 EPIPE（SIGPIPE 已忽略）⇒ 父静默退出 ⇒ 连接 FIN** —— 这是唯一可观测信道。
- **seccomp 在 `pwn` 自己里**：`blind()` = `close(1); close(2)` + 默认 `ERRNO(EPERM)`，只 allow `read/exit/exit_group` ⇒ 沙箱后**只能读不能写**（题面 "keep silent" 的真意）；**flag 在 fd 3**。
- 漏洞 `get_input`：不截断、不加 NUL 的栈溢出；`canary@0x58 / savedrbp@0x60 / ret@0x68`，max `0x88`。
- 一条 `%s` 同时泄漏 canary 与 PIE base（`[rbp]` 槽被 main 写成 `&__libc_csu_init`）⇒ `pie = leak-0x2005a0`，**不需要 libc base**。

## 我方独立做到哪

1. **本地全链硬验证**：假 flag `flag{th1s_1s_4_l0c4l_t3st_0nly_0123456789abcdef}`（48 B）**48/48 逐字节还原、脚本自检打印 `MATCH`、耗时 56.7 s**，跑在题目自带 `ld-linux-x86-64.so.2` + glibc 2.27 上（`work/babysilent/recover.log` 末两行）。
2. **远程 oracle 打通**：`probe(0,0x66)=alive` / `probe(0,0x67)=DEAD` ⇒ flag 确在 fd 3、链能跑、`guess>flag` 分支真 SIGSEGV、wrapper 的 EPIPE→FIN 通（`work/babysilent/handoff2.md` §「远程实况」；判据 gadget `0x200388`、`READ_GOT=0x600fa8`、`FLAGFD` 默认 3，见 `work/babysilent/xp2.py`）。
3. **定出 flag 长度 = 42 字节**：`idx=5..41` 全部 `probe(idx,0x20)=alive`，`idx=42` 首次 `DEAD`（该字节为 `\n`/`\0`）⇒ 末行 `LENGTH 42`（`evidence/MA58VMlIwnwXohzq-remote5.log`，38 条 `len-check`）。
4. **原语形态**：4-qword 链 `pop rdi → get_input → leave;ret` 把 bss 变任意写，再用 `__libc_csu_init` gadget 拼任意 `read(fd,addr,len)` ⇒ **1 bit/探测的盲注比较原语**，每字节二分 8 次。
5. **根因（三条，均已定位）**：① oracle **只有负信号**（等 FIN），而 FIN 延迟随连接数增长 ⇒ 约 150 连接后假 alive 变多、自相矛盾（`remote2/3/4.log` 实拍）；② PIE 泄漏在 `byte2==0` 时 `%s` 静默截断（约 1/8）需重连；③ `read(3,SKIP,idx)` 当 `idx=10` 会读到 `0x0a` 致链截断。对策 = **VOTE=3 多数表决 + 先定长度 + 按 12–15 B/台分段跨容器续跑**。

## 能不能复现

- **本地可完整复现**（无需网络）：`PWN=pwn_fast python3 work/babysilent/xp2.py 48`，配合 `work/babysilent/babysilent/flag` 自造假 flag。`xp2.py` 的 `--length` / `--limit` 均为真实参数（已核对源码 338/364 行）。
- **远程需要容器**（`type_id=2`，镜像 `eci_2026_qwb_babysilent`）**且必须限速**；一条命令续跑：
  `REMOTE=<ip:port> EOF_WAIT=2.1 PACE=0.40 VOTE=3 MAXCONN=140 FLAGFD=3 PROGRESS=evidence/MA58VMlIwnwXohzq-progress.txt python3 work/babysilent/xp2.py 42 --limit 12`
- **缺什么**：① 容器（我方名额被人类冻结，收工原因见 `team/babysilent/README.md` 顶部横幅）；② 实测单探测 5–8.5 s ⇒ VOTE=3 ≈ 21 连接/字节 ≈ **3 min/字节**，一台 60 min 容器稳产 **12–15 B** ⇒ 42 B 需 **约 3 台**接力；③ README 所称续跑锚点 `work/babysilent/prog4.txt` **当前工作区不存在**，实际可用锚点是 `evidence/MA58VMlIwnwXohzq-progress.txt`。

## 证据

- `evidence/MA58VMlIwnwXohzq-remote5.log` —— 长度判据（38 条 `len-check`，末行 `LENGTH 42`）
- `evidence/MA58VMlIwnwXohzq-progress.txt` —— 机读字节台账（`#length=42` + 2 个 VOTE=3 确认字节 + 未确认段显式标注）
- `evidence/MA58VMlIwnwXohzq-remote{2,3,4}.log` —— 漂移/自相矛盾的实拍（不可信段）
- `evidence/MA58VMlIwnwXohzq-triage.txt` —— 附件 triage（4 项；zip sha256 `523daab87d67…`）
- `work/babysilent/handoff.md`、`work/babysilent/handoff2.md`、`work/babysilent/recover.log`、`work/babysilent/xp2.py`
- `team/babysilent/README.md`、`team/babysilent/EVIDENCE.md`
