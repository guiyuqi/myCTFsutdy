# IWMvlQv9iQK8Lh-M · oldsvr（PWN/静态）

- 平台：**603 队解出**（`work/team-board.json` @ 2026-11-01T11:52:09）；我方状态：**已解出**（`solved_by_us=true`，`solved_time=10-31 14:42:28`）。**提交者 = 本队队员，具体是谁「未记录」** —— `team/INDEX.md` 该行写「本队队员提交（**提交者待补**）」并明确「平台未按题拆开 ⇒ **不猜**」；同文件亦载明「frozen 与 oldsvr 是本队队员解出，**不是代理**（代理在这两题上零提交）」；代理侧 `evidence/submit-log.jsonl` 749 行**无本题任何一条**。
  > ⚠️ 旧数勿抄：`team/oldsvr/README.md` 头部「49 队」是 10-31 13:20 赛中快照，`INDEX.md` 另有一版「318 队」；终盘以 603 为准。
- flag：**未在本地记录**（无任何本地文件保存本题 flag；队友提交内容本地无副本）。

## 解法要点

**队友未留解法记录** —— `team/oldsvr/README.md` 与 `给队友-现状说明.md` 都是我方的排除过程，无队友口径；`EVIDENCE.md` 人工段仍是「待补」。以下为可核查的机制复原，**出自我方独立逆向，未与队友解法对照**：

- 二进制：**ELF64 MIPS big-endian (n64)、PIE、stripped**，uClibc-1.0.32（malloc 是真 dlmalloc 2.7.2）；canary 无 / NX 有 / RELRO 只覆盖 `0x1ffe0..0x20000`；`alarm(80)`；**inetd 形态**（stdin/stdout 即 socket）。
- 协议：简化 MQTT，clientid `QWB_Client` / user `QWB2026_Admin` / topic `QWB2026_News`（`.rodata` 只有 8 个常量）。
- 门禁：每个 handler 首三条都是「`state->byte1==0` 就静默 `return 1`」⇒ 未认证时发包**根本没执行**。

## 我方独立做到哪

1. **认证绕过（本地 + 远端双验证）**：`strncmp(md5_out, expected, 0x10)` 而 `expected` XOR `0x59` 后第 3 字节即 NUL ⇒ **只比 24 bit**；clientid 用 `memcmp(n=我们给的)`、username 用 `strncmp(n=我们给的)` ⇒ **各发 1 字节 `"Q"` 即可**。口令 **`1540124`**（`md5=522a005b…`）。远端实证 `evidence/IWMvlQv9iQK8Lh-M-remote-authprobe.bin`（**TX 306 B / RX 9 B**）：`CONNECT → 20 02 00 00`、`SUBSCRIBE topic_len=0xffff → 90 03 00 01 01`（连接未断）。
2. **两个全受控堆溢出（都是合法包）**：① `SUBSCRIBE len=0xffff` ⇒ `malloc((ushort)(0x10000)+1)=malloc(1)`，clamp 后 `memcpy(chunk,name,0x110)`；② `notify` 的 `sVar6=(payload_len+16)&0xffff` 当长度、`memcpy` 用未截断值 ⇒ **最大约 64 KB**（`0xFFF0→0`、`0xFFFF→0xF`，实测不崩）。
3. **已验证写原语：checked unlink → 任意改 topic 表项指针**（判据 `table[3].name` 由 `0x4000022100` → `0x4000022160`，配方即 `work/oldsvr/exp/exp3.py` 的 `full()` 默认参数 `N_user=0x4000022100 / BK=0x4000022160`）。
4. **写原语逐类机械排除 9 类**（每类都给出「为什么写不到」的判据，不是"试了不行"）：forward unlink / backward+`prev_size` / `set_foot` / bin-insert / top-merge·HoF / 堆推到栈 / notify UAF 回显 / carry-over 栈溢出 / 借合法功能读文件。核心一句：**9 类形态只有"堆内向上"**，而 `.bss/.got` 就在堆正下方、栈被 **4 KB `PROT_NONE` 守卫页 + 8 MB 栈预留**隔开、arena/libc 又在栈上方。
5. **决定性静态判据（本次已亲自复核）**：`.dynsym` 具名 **31 项、自有 19 个**（18 个 I/O/内存符号 + `main`）；`open/openat/fopen/stat/access/readlink/sendfile/execve/system/mmap` 及 **`syscall` 符号全部为 0 个**；`.text` 内**零 `syscall` 指令**（`00 00 00 0c` 全文件仅 2 处、偏移 `0x3e4`/`0x760`，都在 `.text` 起点 `0x1490` **之前**）⇒ 二进制自身不可能读文件，要 RCE 必须 pivot 进 libuClibc；**单包上限 `0x1800c`（98,316 B）< 128 KB mmap 阈值**（`work/oldsvr/decompiled/server_.c:1384`）⇒ malloc 永不触发 mmap。
6. **主题探测 30 local + 7 remote 全字节级相同**（含 `flag`/`#`/`+`/`$SYS/#`/`/flag`），无任何非 `SUBACK` 回应。
7. **边界声明**：以上 9 类是我方 5 个盒子（约 45 分钟）的**枚举边界**；平台 603 队已解出 ⇒ **9 类之外必有路**，不写"不可解"。

## 能不能复现

- **静态题（`type_id=1`），不需要容器**：`qemu-mips64-static -L work/oldsvr/rootfs work/oldsvr/rootfs/server`；远端 `nc <target> 1883`（一次只允许一个活会话，重连需留间隔）。
- **可复现的部分**：认证绕过、两个堆溢出、checked unlink 改表项指针 —— 脚本 `work/oldsvr/exp/{exp3.py,leak.py,maps.py,shape.py,rsp.py}`。
- **缺什么**：① **队友的解法路径**（本地无任何记录）；② **任意读/任意写原语**（我方 9 类内没有）；③ **flag 来源未定** —— 是 `env`/`argv` 里的进程内存、还是必须真 RCE，我方当时无法判定（`给队友-现状说明.md` §三/§五）。
- **工具坑（复核用）**：宿主 `objdump -d` 不认 MIPS64 BE（`architecture UNKNOWN`）⇒ 判"死代码/零调用"必须用 Ghidra 反编译 grep 或 capstone；`gdb-multiarch` 连 `qemu-user -g` 不可用，改 `/proc/<pid>/mem` 直读。

## 证据

- `evidence/IWMvlQv9iQK8Lh-M-remote-authprobe.bin` —— 远端认证绕过 + 溢出未断连（TX 306 B / RX 9 B，明文含 `1540124`）
- `evidence/IWMvlQv9iQK8Lh-M-topics.txt` —— `.rodata` 全 8 常量、XOR 解出的 user/md5、`syscall` 计数 0、30+7 主题全相同
- `evidence/IWMvlQv9iQK8Lh-M-topics-local-enum.log` —— 30 个主题的本地逐包回应
- `evidence/IWMvlQv9iQK8Lh-M-triage.txt` —— 附件 triage（3 文件；zip sha256 `2d2b4492bee7…`）
- `work/oldsvr/decompiled/server_.c`、`work/oldsvr/exp/exp3.py`、`work/IWMvlQv9iQK8Lh-M-handoff{,2,3,4,5}.md`
- `team/oldsvr/README.md`（§6 九类否证表）、`team/oldsvr/给队友-现状说明.md`
