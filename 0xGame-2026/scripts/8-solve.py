#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
8 · RSA永恒花园 (0xGame2026 Week1, Crypto, 1000, offline) — reproducible solver.

WHAT THE ATTACHMENT ACTUALLY DOES
---------------------------------
firmware/8_RSA永恒花园/week1 Crypto RSA永恒花园 .py

    p,q = [getPrime(256) for _ in range(2)]
    n = p*q ; e = 65537
    m = bytes_to_long(flag)
    c = gmpy2.powmod(m,e,n)
    #n=<154 digits>          <-- BROKEN: 154 digits, and n = 3 * prime(507 bit)
    #c=<155 digits>
    #hint1: assert(len(n)==155)
    #hint2: flag中有待清洗的淤泥

The modulus printed in the attachment is NOT a product of two 256-bit primes:
it is 3 * (507-bit prime) and only 154 digits, while hint1 says it must be
155 digits.  => exactly one decimal digit was lost from n.

INTENDED PATH (the "old flower" of the flavour text = an OLD, already-factored
modulus: "新的花的成长是吸食着旧的花的骨髓 / 过往的遗憾缺陷并没有腐烂"):
enumerate all 1550 single-digit insertions of the 154-digit string, ask
FactorDB for each; exactly ONE candidate is fully factored (status FF) into two
256-bit primes -- the given string with a '7' APPENDED -- which matches
getPrime(256)*getPrime(256).  Then plain RSA decryption.

This script:
  * default          : uses the recovered factorisation (offline, deterministic)
  * --search         : re-runs the FactorDB search (needs network, ~170 queries)

Usage:
    python3 scripts/8-solve.py            # offline: decrypt + analyse
    python3 scripts/8-solve.py --search   # redo the FactorDB modulus search
"""

import argparse
import json
import math
import re
import sys
import time
import urllib.parse
import urllib.request

# --------------------------------------------------------------------------
# data straight out of the attachment (comments)
# --------------------------------------------------------------------------
N_GIVEN = int(
    "109417386415705274218097073220403576120037329454492059909138421314763499842889"
    "3478471799725789126733249762575289978183379707653724402714674353159335433389"
)
C = int(
    "100731376150273771405109812187914150019061179166335515974804086774921830036491"
    "26231396950464383049976806132394959240819342154566927353181638708426838182688"
)
E = 65537

# recovered by the FactorDB sweep (see --search); n_full = N_GIVEN * 10 + 7
P = 102639592829741105772054196573991675900716567808038066803341933521790711307779
Q = 106603488380168454820927220360012878679207958575989291522270608237193062808643
N_FULL = P * Q

# 6 junk ("mud") characters and the 4+4 non-printable padding bytes
MUD_CHARS = "%\uffe5@#&*"          # % U+FFE5(fullwidth yen) @ # & *
MUD_PREFIX = bytes.fromhex("ff001337")
MUD_SUFFIX = bytes.fromhex("80007fee")


def primes_upto(n):
    sieve = bytearray([1]) * (n + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(n ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i:: i] = bytearray(len(range(i * i, n + 1, i)))
    return [i for i in range(2, n + 1) if sieve[i]]


def factor_db_search(verbose=True, delay=0.6):
    """The intended attack: which 155-digit candidate does FactorDB know?"""
    s = str(N_GIVEN)
    small = primes_upto(100000)
    hits = []
    cands = []
    for i in range(len(s) + 1):
        for d in "0123456789":
            if i == 0 and d == "0":
                continue
            n = int(s[:i] + d + s[i:])
            if n <= C or n % 2 == 0:
                continue
            if any(n % p == 0 for p in small):      # a 256x256-bit semiprime is not
                continue                            # divisible by any small prime
            cands.append((i, d, n))
    if verbose:
        print(f"[*] {len(cands)} plausible 155-digit candidates (odd, no factor < 1e5)")
    for k, (i, d, n) in enumerate(cands):
        url = "http://factordb.com/api?query=" + urllib.parse.quote(str(n))
        try:
            with urllib.request.urlopen(url, timeout=25) as r:
                j = json.loads(r.read().decode())
        except Exception as ex:                      # network hiccup: skip
            if verbose:
                print(f"    ! query failed ({ex})")
            time.sleep(2)
            continue
        facs = j.get("factors", [])
        if j.get("status") in ("FF", "P") and len(facs) == 2 and \
           all(int(f[0]).bit_length() > 200 for f in facs):
            print(f"[+] FACTORDB HIT: insert '{d}' at pos {i} "
                  f"(i.e. append/prepend) -> fully factored")
            print("    n =", n)
            print("    p =", facs[0][0])
            print("    q =", facs[1][0])
            hits.append((i, d, n, int(facs[0][0]), int(facs[1][0])))
        if verbose and k % 25 == 0:
            print(f"    ... {k}/{len(cands)}")
        time.sleep(delay)
    return hits


def decrypt(n, p, q, c=C, e=E):
    assert p * q == n, "p*q != n"
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    b = m.to_bytes((m.bit_length() + 7) // 8, "big")
    assert pow(m, e, n) == c, "re-encryption check failed"
    return b


def analyse(pt):
    print("=" * 72)
    print("plaintext  :", pt)
    txt = pt.decode("utf-8", "replace")
    print("utf-8      :", txt)
    core = pt[len(MUD_PREFIX): len(pt) - len(MUD_SUFFIX)]
    print("core       :", core.decode("utf-8", "replace"))
    m = re.search(rb"0xGame\{.*\}", core, re.S)
    muddy = m.group().decode("utf-8") if m else None
    print("muddy flag :", muddy)
    if muddy:
        body = muddy[7:-1]
        print("mud chars  :", [c for c in muddy if c in MUD_CHARS],
              " positions:", [i for i, c in enumerate(muddy) if c in MUD_CHARS])
        print("segments   :", [w for w in re.split("[" + re.escape(MUD_CHARS) + "]", body) if w])
        print("-- candidate 'washings' (ALL REJECTED by the platform, see notes) --")
        print("  delete mud        : 0xGame{" +
              "".join(ch for ch in body if ch not in MUD_CHARS) + "}")
        print("  mud -> '_'        : 0xGame{" + "".join(
            "_" if ch in MUD_CHARS else ch for ch in body) + "}")
        print("  mud -> ' '        : 0xGame{" + "".join(
            " " if ch in MUD_CHARS else ch for ch in body) + "}")
        words = [w for w in re.split("[" + re.escape(MUD_CHARS) + "]", body) if w]
        print("  word-join '_'/' ': 0xGame{" + "_".join(words) + "} / 0xGame{" +
              " ".join(words) + "}")
    print("=" * 72)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--search", action="store_true",
                    help="re-run the FactorDB modulus search (network)")
    a = ap.parse_args()

    print("[*] given n :", N_GIVEN)
    print("    digits  :", len(str(N_GIVEN)), "(hint1 wants 155)")
    print("    gcd(n,3):", math.gcd(N_GIVEN, 3), "-> n = 3 * (507-bit prime): NOT a real modulus")

    if a.search:
        hits = factor_db_search()
        if not hits:
            sys.exit("[!] no FactorDB hit (network?)")
        i, d, n, p, q = hits[0]
        print(f"[*] recovered modulus = given n with '{d}' appended")
    else:
        n, p, q = N_FULL, P, Q
        print("[*] using recovered factorisation (n = given_n*10 + 7)")

    pt = decrypt(n, p, q)
    analyse(pt)
    print("[*] NOTE: step 4 ('washing' the mud) was never disambiguated; "
          "5 candidate flags were rejected by the platform -> see "
          "notes/8-RSA永恒花园.md")


if __name__ == "__main__":
    main()
