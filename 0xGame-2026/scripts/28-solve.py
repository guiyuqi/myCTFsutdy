#!/usr/bin/env python3
# 28 - [深具传统的ECC之诞生]  solver
#
# Service: nc nc1.ctfplus.cn 25121  (non-interactive, fixed params, prints G and Q)
#   p   = 380025560263444925282186340357451425457046895363401263284043   (198-bit prime, p = 3 mod 4)
#   E   : y^2 = x^3 + 3x + 0  mod p      -> j = 1728,  p = 3 mod 4  => SUPERSINGULAR
#   #E(F_p) = p + 1                       (trace t = 0)
#   Q   = bytes_to_long(flag) * G
#
# p + 1 = 2^2 * 116869069 * 172348369 * 261535163 * 345477907
#              * 355841179 * 357636161 * 410202269      -> fully SMOOTH (max factor 29 bits)
# => ECDLP solvable directly by Pohlig-Hellman (prime power q^1) + BSGS in each subgroup.
#
# ord(G) = (p+1)/2 = 190012780131722462641093170178725712728523447681700631642022
#
# FLAG: 0xGame{master's touch}
#
# Usage: python3 scripts/28-solve.py            # offline, uses the hardcoded transcript
#        python3 scripts/28-solve.py --live     # re-fetch G,Q from the service first

import sys
from math import isqrt

HOST, PORT = "nc1.ctfplus.cn", 25121
P = 380025560263444925282186340357451425457046895363401263284043
A = 3
G = (89416635389252243162818482998273067753365476637225933437342,
     246277781258250668709138589808946483685012465285148814183503)
Q = (329460413071651533403262472631632126805896556373758724864455,
     299273891016902567464505544081763716760408274149519169100436)


def ec_add(Pt, Qt, p=P, a=A):
    if Pt is None:
        return Qt
    if Qt is None:
        return Pt
    x1, y1 = Pt
    x2, y2 = Qt
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if Pt == Qt:
        lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return (x3, (lam * (x1 - x3) - y1) % p)


def ec_mul(k, Pt, p=P, a=A):
    if k < 0:
        k, Pt = -k, (Pt[0], (-Pt[1]) % p)
    R = None
    while k:
        if k & 1:
            R = ec_add(R, Pt, p, a)
        Pt = ec_add(Pt, Pt, p, a)
        k >>= 1
    return R


def bsgs(Pt, Tgt, q):
    """solve x with x*Pt == Tgt, ord(Pt) == q (prime)"""
    m = isqrt(q) + 1
    table, cur = {}, None
    for j in range(m):
        table.setdefault(cur, j)
        cur = ec_add(cur, Pt)
    step = ec_mul(-m, Pt)
    gamma = Tgt
    for i in range(m + 1):
        if gamma in table:
            return (i * m + table[gamma]) % q
        gamma = ec_add(gamma, step)
    raise ValueError("bsgs failed")


def factorize(n):
    """trial division + Pollard rho (enough for this 198-bit smooth n)"""
    from sympy import factorint
    return factorint(n)


def main():
    global G, Q
    if "--live" in sys.argv:
        import socket, re
        s = socket.create_connection((HOST, PORT), timeout=15)
        buf = b""
        while True:
            try:
                c = s.recv(4096)
            except Exception:
                break
            if not c:
                break
            buf += c
        s.close()
        txt = buf.decode(errors="replace")
        G = tuple(int(v) for v in re.search(r"G = \((\d+), (\d+)\)", txt).groups())
        Q = tuple(int(v) for v in re.search(r"Q = \((\d+), (\d+)\)", txt).groups())
        print("[*] fetched live transcript")

    n = P + 1
    # order of G
    ordG = n
    for q in factorize(n):
        while ordG % q == 0 and ec_mul(ordG // q, G) is None:
            ordG //= q
    assert ec_mul(ordG, Q) is None, "Q not in <G>"
    print(f"[*] ord(G) = {ordG}")

    residues, mods = [], []
    for q, e in factorize(ordG).items():
        qe = q ** e
        d = 0
        gamma = ec_mul(ordG // q, G)          # point of order q
        for k in range(e):
            Qk = ec_mul(ordG // (q ** (k + 1)),
                        ec_add(Q, ec_mul(-d, G)))
            dk = bsgs(gamma, Qk, q)
            d += dk * (q ** k)
        residues.append(d % qe)
        mods.append(qe)
        print(f"[*] d mod {qe} = {d % qe}")

    from sympy.ntheory.modular import crt
    d, M = crt(mods, residues)
    d, M = int(d), int(M)

    from Crypto.Util.number import long_to_bytes, bytes_to_long
    flag = None
    for k in range(64):
        cand = long_to_bytes(d + k * M)
        if b"0xGame{" in cand or b"flag{" in cand:
            flag = cand
            break
    assert flag is not None, "no flag-shaped candidate found"
    print(f"[+] flag = {flag.decode()}")
    assert ec_mul(bytes_to_long(flag), G) == Q, "verification failed"
    print("[+] verified: bytes_to_long(flag)*G == Q")


if __name__ == "__main__":
    main()
