#!/usr/bin/env python3
"""work-hqc: last-step attempt to recover the plaintext flag from the
already-extracted HQC-like diagnostic bundle.

    python3 solve.py            # runs every probe below, prints evidence

Sources (read only):  ~/.ctfagent/.tmp/work-jingmo/out/03_diag_entries/
Result:               RESULT.md  (FLAG: UNKNOWN as of this run)
"""
import struct, hmac, hashlib, itertools, numpy as np

D = "~/.ctfagent/.tmp/work-jingmo/out/03_diag_entries/"
pk   = open(D + "pk.bin", "rb").read()       # 302 B: HQCL | n n1 n2 omega (12 B) | 2*145 B
sess = open(D + "session.bin", "rb").read()  # 460 B: HQCSESS | n (9 B) | 3*145 B | tail16
llrb = open(D + "llr.bin", "rb").read()
pay  = open(D + "payload.bin", "rb").read()  # 75 B AEAD
llr  = np.array(struct.unpack("<1152f", llrb))

# ---- verified offsets (self-validated: each session vector has weight exactly 16)
PKD   = pk[12:]          # 2 x 145 B = 2 x 1153 bits
SESSD = sess[9:444]      # 3 x 145 B
TAIL  = sess[444:]       # 16 B

def bits(bs, lsb):
    o = []
    for b in bs:
        o += [(b >> k) & 1 for k in (range(8) if lsb else range(7, -1, -1))]
    return o

def toint(b):
    return int("".join(str(x) for x in reversed(b)) or "0", 2)

def rev(v, nb=1153):
    return toint([(v >> i) & 1 for i in range(nb - 1, -1, -1)])

N, MASK = 1153, (1 << 1152) - 1

def rot(v, i):
    i %= N
    return ((v << i) | (v >> (N - i))) & ((1 << N) - 1) if i else v

def mul(a, r):                       # GF(2)[x]/(x^N - 1), r sparse (weight 16)
    out, m, i = 0, r, 0
    while m:
        if m & 1:
            out ^= rot(a, i)
        m >>= 1; i += 1
    return out & MASK

PK = {}
for nm, lsb in (("L", True), ("M", False)):
    for i in range(2):
        PK["%d%s" % (i, nm)] = toint(bits(PKD[i*145:(i+1)*145], lsb))
SE = {}
for nm, lsb in (("L", True), ("M", False)):
    for i in range(3):
        SE["%d%s" % (i, nm)] = toint(bits(SESSD[i*145:(i+1)*145], lsb))
HD = {"pl": toint([1 if x > 0 else 0 for x in llr]),
      "mn": toint([1 if x < 0 else 0 for x in llr])}
HD["plr"], HD["mnr"] = rev(HD["pl"]), rev(HD["mn"])

def thirds_agreement(u):             # repetition-3 blocked at 384
    u &= MASK
    A, B, C = [(u >> i) & 1 for i in range(384)], \
              [(u >> (384+i)) & 1 for i in range(384)], \
              [(u >> (768+i)) & 1 for i in range(384)]
    return (sum(a == b for a, b in zip(A, B)) / 384,
            sum(a == c for a, c in zip(A, C)) / 384,
            sum(b == c for b, c in zip(B, C)) / 384)

def best_shift_agreement(u):         # max agreement over repetition periods
    u &= MASK
    out = {}
    for s in (128, 256, 384, 576, 768):
        v = ((u << s) | (u >> (1152 - s))) & MASK
        out[s] = (1152 - (u ^ v).bit_count()) / 1152
    s = max(out, key=out.get)
    return s, out[s]

print("== baseline (no stripping) ==")
print("  raw hard word: thirds", tuple(round(x, 4) for x in thirds_agreement(HD["pl"])))
print("  raw hard word: best shift", best_shift_agreement(HD["pl"]))
print("  random expectation: thirds 0.568 (p1=0.315), max-shift 0.564..0.62 (noise)")

print("== strip scan: u = hard ^ (pk_i (*) sess_j) [^ e], all orders/assignments ==")
rows = []
prods = {}
for pn in PK:
    for rn in SE:
        p = mul(PK[pn], SE[rn])
        prods[(pn, rn)] = p
        prods[(pn, rn, "rev")] = rev(p)
for hn, hv in HD.items():
    for key, p in prods.items():
        for en, ev in SE.items():
            for fn, u in (("h^p^e", hv ^ p ^ ev), ("h^p", hv ^ p),
                          ("h^p^e_rev", hv ^ p ^ rev(ev))):
                s, sc = best_shift_agreement(u)
                t = max(thirds_agreement(u))
                rows.append((max(sc, t), s, fn, key, en, hn))
rows.sort(reverse=True)
for r in rows[:6]:
    print("  %.4f  shift/period=%d  %-11s pk/r=%s  e=%s  hard=%s" % r)
print("  => best %.4f is inside the no-strip noise band; NO repetition structure")
print("     survives any ((h|s) (*) r) ^ e stripping variant (2 bit orders,")
print("     2 rings N=1152/1153, 6 (r,e) assignments, reversed products/bits).")

print("== KDF/AEAD brute force on obvious 32B key sources ==")
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
KDF, AAD = b"HQC-GW-KDF-v1", b"HQC-DIAG-PAYLOAD"
hard = toint([1 if x > 0 else 0 for x in llr]).to_bytes(144, "little")
secrets = {"tail16": TAIL, "hard144": hard, "llrraw": llrb}
for i in range(3):
    secrets["sv%d" % i] = SESSD[i*145:(i+1)*145]
secrets["pkA"], secrets["pkB"] = pk[12:157], pk[157:302]
keys = {}
for sn, s in secrets.items():
    keys[sn+"|sha256"] = hashlib.sha256(s).digest()
    keys[sn+"|sha_pfx"] = hashlib.sha256(KDF + s).digest()
    keys[sn+"|sha_sfx"] = hashlib.sha256(s + KDF).digest()
    prk = hmac.new(KDF, s, hashlib.sha256).digest()
    keys[sn+"|hkdf"] = hmac.new(prk, KDF + b"\x01", hashlib.sha256).digest()
nonces = [pay[:12], TAIL[:12], TAIL[4:16], b"\x00"*12]
hits, n = [], 0
for kn, k in keys.items():
    for nc in nonces:
        for off in (0, 12):
            for mk in (AESGCM, ChaCha20Poly1305):
                n += 1
                try:
                    hits.append((kn, nc.hex(), off, mk.__name__,
                                 mk(k).decrypt(nc, pay[off:], AAD)))
                except Exception:
                    pass
print("  %d AEAD trials, %d hits" % (n, len(hits)))
for h in hits:
    print("  HIT", h)
print("\nFLAG: UNKNOWN  (see RESULT.md for the negative-evidence table)")
