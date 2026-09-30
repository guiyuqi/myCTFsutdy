#!/usr/bin/env python3
"""GEELY CAN keyless-entry rolling token (attachments12.zip)

Constants read from the rework photo + vendor colour/nibble card:
  R1 pale-yellow(4) white(9)   -> K byte0 = 0x49
  R2 peru(A)       navy(F)     -> K byte1 = 0xAF
  R3 orange(3)     red(2)      -> K byte2 = 0x32
  R4 magenta(C)    purple(7)   -> K byte3 = 0xC7
  R5 green(5)      peru(A)     -> M byte0 = 0x5A
  R6 brown(1)      purple(7)   -> M byte1 = 0x17
  R7 magenta(C)    black(0)    -> M byte2 = 0xC0
  R8 cyan(D)       olive(E)    -> M byte3 = 0xDE
  U1 = 9E37 / 79B1             -> S = 0x9E3779B1
  rotation stage               -> R = 7 triangles
"""
import hashlib
import re
import sys

K = 0x49AF32C7
S = 0x9E3779B1
M = 0x5A17C0DE
R = 7
PHASE = 0x7D
MASK = 0xFFFFFFFF


def rol(x, r):
    return ((x << r) | (x >> (32 - r))) & MASK


def token(n):
    x = K ^ ((n * S) & MASK)
    x = rol(x, R)
    x ^= M
    return (x ^ (x >> 13)) & MASK


def frame(n):
    body = bytes([(n >> 8) & 0xFF, n & 0xFF, PHASE]) + token(n).to_bytes(4, "big")
    return body + bytes([__import__("functools").reduce(lambda a, b: a ^ b, body)])


def main(path):
    frames = []
    for line in open(path):
        m = re.search(r"18FF50A5#([0-9A-Fa-f]{16})", line)
        if m:
            frames.append(bytes.fromhex(m.group(1)))

    print(f"[*] recovered records: {len(frames)}")
    ok = True
    for f in frames:
        n = int.from_bytes(f[:2], "big")
        t = int.from_bytes(f[3:7], "big")
        calc = token(n)
        xor_ok = f[7] == __import__("functools").reduce(lambda a, b: a ^ b, f[:7])
        good = (calc == t) and xor_ok
        ok &= good
        print(f"    N=0x{n:04X} wire={t:08X} calc={calc:08X} xor8={xor_ok} -> {'OK' if good else 'FAIL'}")
    if not ok:
        sys.exit("transform mismatch")

    nxt = int.from_bytes(frames[-1][:2], "big") + 1
    payload = frame(nxt)
    print(f"[+] next accepted counter : 0x{nxt:04X}")
    print(f"[+] next rolling token     : {token(nxt):08X}")
    print(f"[+] next frame payload     : {payload.hex().upper()}")
    print(f"[+] next candump line      : can1 18FF50A5#{payload.hex().upper()}")

    variants = {
        "raw payload bytes": payload,
        "payload hex string (lower)": payload.hex().encode(),
        "payload hex string (UPPER)": payload.hex().upper().encode(),
        "token raw bytes": token(nxt).to_bytes(4, "big"),
    }
    for name, data in variants.items():
        h = hashlib.sha256(data).hexdigest()
        print(f"    {name:28s} sha256={h}")
    h = hashlib.sha256(payload).hexdigest()
    print(f"\nFLAG = GEELY{{CAN_{h[:16]}_{h[-16:]}}}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else
         "work/att12/attachments/can_unlock_trace.log")
