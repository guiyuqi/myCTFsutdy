#!/usr/bin/env python3
"""Short-message brute force over AES-GCM AEAD for the HQC/GW diag payload.

Auth tag self-validates: any GCM verify hit is a true key.
Materials are read-only from .tmp/work-jingmo/out/03_diag_entries/.
"""
import hashlib
import hmac
import os
import sys
import time
from multiprocessing import Pool, cpu_count

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

IN = "~/.ctfagent/.tmp/work-jingmo/out/03_diag_entries"
P = open(os.path.join(IN, "payload.bin"), "rb").read()
SESS = open(os.path.join(IN, "session.bin"), "rb").read()
CONF = open(os.path.join(IN, "config.bin"), "rb").read()

PFX = b"HQC-GW-KDF-v1"
AAD0 = b"HQC-DIAG-PAYLOAD"
AAD1 = b"HQC-DIAG-PAYLOAD\x00"
AADS = [("aad", AAD0), ("aadnul", AAD1)]

TAIL16 = SESS[-16:]
NONCES = [
    ("nz12", b"\x00" * 12),
    ("tail12", TAIL16[:12]),
    ("p4z8", P[:4] + b"\x00" * 8),
    ("zero16", b"\x00" * 16),
]

# ---- framings: (label, nonce_in_payload_slice or None, ct_slice, tag_slice)
FRAMINGS = [
    ("F1_n12_ct47_t16", (0, 12), (12, 59), (59, 75)),
    ("F2_n12_tag16_ct47", (0, 12), (28, 75), (12, 28)),
    ("F3_n16_ct43_t16", (0, 16), (16, 59), (59, 75)),
    ("F4_n12_ct48_t15x", None, None, None),  # placeholder, skipped (tag 15 unsupported)
    ("F5_n1_12ct46_t16", (1, 13), (13, 59), (59, 75)),
    ("F6_n12_ct46_t17x", None, None, None),
]


def build_flat(use_external_nonces=True):
    flat = []
    seen = set()
    for fi, (flab, nsl, csl, tsl) in enumerate(FRAMINGS):
        if nsl is None:
            continue
        nonce = P[nsl[0]:nsl[1]]
        data = P[csl[0]:csl[1]] + P[tsl[0]:tsl[1]]
        cands = [(flab + "/emb", nonce)]
        if use_external_nonces:
            for nl, nv in NONCES:
                cands.append((flab + "/" + nl, nv))
        for nl, nv in cands:
            for al, av in AADS:
                k = (nv, av, data)
                if k in seen:
                    continue
                seen.add(k)
                flat.append((nl + "|" + al, nv, av, data))
    return flat


FLAT = build_flat(True)
FLAT_CORE = build_flat(False)


# ---------------- KDF variants ----------------
def hkdf(ikm, salt, info, n=32):
    if salt is None:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    i = 1
    while len(okm) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:n]


def keys_from_m(m):
    """Return list of (name, key) candidates."""
    out = []
    digests = [
        ("sha_m", hashlib.sha256(m).digest()),
        ("sha_pfx_m", hashlib.sha256(PFX + m).digest()),
        ("sha_m_pfx", hashlib.sha256(m + PFX).digest()),
        ("hkdf_info", hkdf(m, None, PFX)),
        ("hkdf_salt", hkdf(m, PFX, b"")),
        ("hkdf_swap", hkdf(PFX, m, b"")),
        ("hmac_pfx_m", hmac.new(PFX, m, hashlib.sha256).digest()),
        ("sha_pfx_m_colon", hashlib.sha256(PFX + b":" + m).digest()),
        ("sha_pfx_m_nul", hashlib.sha256(PFX + b"\x00" + m).digest()),
        ("hkdf_info_salt", hkdf(m, PFX, PFX)),
    ]
    base = hashlib.sha256(PFX).digest()
    # g) SHA256(pfx) xor m expanded
    rep = (m * (32 // max(1, len(m)) + 1))[:32]
    out_xor = bytes(a ^ b for a, b in zip(base, rep))
    digests.append(("sha_pfx_xor_m", out_xor))
    for nm, d in digests:
        out.append((nm + "/k32", d[:32]))
        out.append((nm + "/k16", d[:16]))
        out.append((nm + "/k16tail", d[16:32]))
    return out


def reps_of(mbytes):
    """Representations of the short message m."""
    r = [("raw", mbytes)]
    if len(mbytes) < 48:
        r.append(("pad48", mbytes + b"\x00" * (48 - len(mbytes))))
    if len(mbytes) < 32:
        r.append(("pad32", mbytes + b"\x00" * (32 - len(mbytes))))
    if len(mbytes) > 1:
        r.append(("rev", mbytes[::-1]))
        if len(mbytes) < 48:
            r.append(("revpad48", mbytes[::-1] + b"\x00" * (48 - len(mbytes))))
    return r


# ---------------- worker ----------------
_STATE = {}


def _init(flat):
    _STATE["flat"] = flat


def work(args):
    lo, hi, width, k1 = args
    flat = _STATE["flat"]
    nf = len(flat)
    tries = 0
    t0 = time.time()
    for v in range(lo, hi):
        mb = v.to_bytes(width, "big")
        for rn, rep in reps_of(mb):
            for kn, key in keys_from_m(rep):
                try:
                    aes = AESGCM(key)
                except Exception:
                    continue
                for i in range(nf):
                    lab, nonce, aad, data = flat[i]
                    tries += 1
                    try:
                        pt = aes.decrypt(nonce, data, aad)
                    except Exception:
                        continue
                    return {
                        "hit": True, "m_int": v, "m_bytes": mb.hex(),
                        "rep": rn, "kdf": kn, "key": key.hex(),
                        "combo": lab, "nonce": nonce.hex(),
                        "aad": aad.hex(), "pt": pt.hex(),
                        "pt_ascii": "".join(chr(c) if 32 <= c < 127 else "." for c in pt),
                        "tries": tries, "secs": time.time() - t0,
                    }
    return {"hit": False, "tries": tries, "secs": time.time() - t0, "k1": k1,
            "range": [lo, hi]}


def run_stage(name, values, k1, width, flat, procs):
    """values: list of ints."""
    chunks = []
    n = len(values)
    if n == 0:
        return None
    # split contiguous ranges for low overhead
    per = (n + procs * 4 - 1) // (procs * 4)
    i = 0
    while i < n:
        j = min(i + per, n)
        chunks.append((values[i], values[j - 1] + 1, width, k1))
        i = j
    t0 = time.time()
    total = 0
    hits = []
    with Pool(procs, initializer=_init, initargs=(flat,)) as pool:
        for res in pool.imap_unordered(work, chunks, chunksize=1):
            total += res["tries"]
            if res["hit"]:
                hits.append(res)
                pool.terminate()
                break
    dt = time.time() - t0
    print(f"[{name}] k1={k1} mvals={n} flat={len(flat)} tries={total} "
          f"time={dt:.1f}s rate={total/max(dt,1e-9):.0f}/s", flush=True)
    if hits:
        return hits[0]
    return None


def main():
    t_all = time.time()
    procs = min(8, cpu_count())
    budget = float(sys.argv[1]) if len(sys.argv) > 1 else 900.0
    print(f"payload={len(P)}B flat_all={len(FLAT)} flat_core={len(FLAT_CORE)} "
          f"procs={procs} budget={budget}s", flush=True)

    hit = None

    # ---- Stage A: k1 = 1, full grid ----
    hit = run_stage("A", list(range(256)), 1, 1, FLAT, procs)
    if hit:
        return report(hit, t_all)

    # ---- Stage B: k1 = 2, full grid (core framings first) ----
    if time.time() - t_all < budget:
        hit = run_stage("B-core", list(range(65536)), 2, 2, FLAT_CORE, procs)
        if hit:
            return report(hit, t_all)
    if time.time() - t_all < budget:
        hit = run_stage("B-all", list(range(65536)), 2, 2, FLAT, procs)
        if hit:
            return report(hit, t_all)

    # ---- Stage C: k1 = 3, selected high bytes ----
    prefixes = [0x00, 0x01, 0x66, 0x46, 0xFF, 0x20]
    for pfx in prefixes:
        if time.time() - t_all > budget - 40:
            print(f"[C] out of budget, skipping prefix 0x{pfx:02x}", flush=True)
            break
        vals = [((pfx << 16) | i) for i in range(65536)]
        hit = run_stage(f"C-0x{pfx:02x}", vals, 3, 3, FLAT_CORE, procs)
        if hit:
            return report(hit, t_all)

    return report(None, t_all)


def report(hit, t_all):
    dt = time.time() - t_all
    print("=" * 60)
    if hit:
        print("HIT")
        for k, v in hit.items():
            print(f"  {k}: {v}")
    else:
        print("NO HIT")
    print(f"total {dt:.1f}s")
    return hit


if __name__ == "__main__":
    main()
