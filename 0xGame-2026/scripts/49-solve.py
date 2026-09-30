#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
0xGame2026 - Reverse 833 - "ez_flower"  (attachment6.zip -> flower.exe)
=======================================================================
Windows x86 console PE with three junk-code ("flower instruction") sites:

    xor eax, eax
    je  <after junk>        ; always taken  -> skips the junk bytes
    <junk>                  ; 11 22 33 / 44 55 66 / 12 34 56
  <after junk>:

so a linear disassembler desyncs.  The junk only ever sits between a
conditional jump and its target, so a linear sweep that *resumes at the
branch target* recovers the true control flow.

Recovered logic (VA 0x401100):

    printf_obf("Input flag: ")                    ; 0x401000, XOR 0x5a
    fgets(buf, 0x80, stdin)
    strip trailing CR/LF, require strlen(buf) == 0x2f (47)
    caesar_shift(buf, tmp, 0x2f)                  ; 0x401060, letters +7
    for (i = 0; i < 47; i++)
        want[i] = g_target[i] ^ 0x80              ; g_target @ VA 0x40f170
    if (!strncmp(tmp, want, 0x2f)) puts("Correct! The flower has bloomed.")
    else                           puts("Wrong flag.")

So:  flag = caesar_shift(g_target[i] ^ 0x80, -7)   over letters only.

Usage:  python3 scripts/49-solve.py [path/to/flower.exe]
"""
import os
import re
import struct
import subprocess
import sys
import zipfile

IMAGE_BASE = 0x400000
TARGET_VA = 0x40F170          # the 47-byte encrypted flag blob (.rdata)
TARGET_LEN = 0x2F             # 47
TARGET_XOR = 0x80             # `xor edx, 0x80` @0x401208
XOR_KEY_VA = 0x40F19F         # single-byte XOR key for the string table

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_ZIP = os.path.join(ROOT, "firmware", "49_ez_flower", "attachment6.zip")


# --------------------------------------------------------------------------
def caesar(data: bytes, k: int) -> bytes:
    """Shift ASCII letters by k positions (mod 26); non-letters untouched."""
    out = bytearray()
    for c in data:
        if 0x41 <= c <= 0x5A:
            out.append((c - 0x41 + k) % 26 + 0x41)
        elif 0x61 <= c <= 0x7A:
            out.append((c - 0x61 + k) % 26 + 0x61)
        else:
            out.append(c)
    return bytes(out)


def parse_pe(path):
    """Minimal PE32 section parser -> (image_base, [(name, virta, vsize, raw, rsize)])."""
    d = open(path, "rb").read()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    assert d[pe:pe + 4] == b"PE\0\0", "not a PE file"
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    optsz = struct.unpack_from("<H", d, pe + 20)[0]
    image_base = struct.unpack_from("<I", d, pe + 24 + 28)[0]
    secs = []
    base = pe + 24 + optsz
    for i in range(nsec):
        o = base + i * 40
        name = d[o:o + 8].rstrip(b"\0").decode("latin-1")
        vsize, vaddr, rsize, raw = struct.unpack_from("<IIII", d, o + 8)
        secs.append((name, vaddr, vsize, raw, rsize))
    return d, image_base, secs


def read_va(d, image_base, secs, va, n):
    for _name, vaddr, vsize, raw, rsize in secs:
        start = image_base + vaddr
        if start <= va < start + max(vsize, rsize):
            off = raw + (va - start)
            return d[off:off + n]
    raise ValueError("VA %#x not mapped" % va)


# --------------------------------------------------------------------------
def solve(path):
    d, ib, secs = parse_pe(path)

    key = read_va(d, ib, secs, XOR_KEY_VA, 1)[0]
    target = read_va(d, ib, secs, TARGET_VA, TARGET_LEN)

    want = bytes(c ^ TARGET_XOR for c in target)   # caesar_shift(input,+7) must equal this
    flag = caesar(want, -7).decode("latin-1")

    # ---- self-check: re-encrypting the flag with +7 must reproduce `want` ----
    assert caesar(flag.encode("latin-1"), 7) == want, "round-trip failed"
    assert len(flag) == TARGET_LEN, "unexpected flag length %d" % len(flag)

    # ---- the decoded string table, as independent corroboration ----
    table = read_va(d, ib, secs, 0x40F1A0, 0x45)      # "Input flag: ..."
    strings = bytes(c ^ key for c in table).split(b"\0")

    # ---- flower sites: confirm all three junk groups really exist in .text ----
    text = read_va(d, ib, secs, 0x401060, 0xC0) + read_va(d, ib, secs, 0x401100, 0x30)
    junk = [b"\x11\x22\x33", b"\x44\x55\x66", b"\x12\x34\x56"]
    found = [j.hex() for j in junk if j in text]

    return flag, want, strings, found, key


def main():
    if len(sys.argv) > 1:
        exe = sys.argv[1]
    else:
        work = os.path.join(ROOT, "work", "49_flower")
        os.makedirs(work, exist_ok=True)
        exe = os.path.join(work, "flower.exe")
        if not os.path.exists(exe):
            with zipfile.ZipFile(DEFAULT_ZIP) as z:
                z.extract("flower.exe", work)

    flag, want, strings, found, key = solve(exe)
    print("XOR key for string table : 0x%02x" % key)
    print("decoded strings          : %s" % [s.decode("latin-1") for s in strings if s])
    print("junk-code groups in fn   : %s" % found)
    print("stored blob ^0x80        : %s" % want.decode("latin-1"))
    print("flag len                 : %d (must be 47)" % len(flag))
    print()
    print("FLAG = %s" % flag)


if __name__ == "__main__":
    main()
