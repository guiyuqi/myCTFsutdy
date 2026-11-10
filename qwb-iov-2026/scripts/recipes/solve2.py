#!/usr/bin/env python3
"""
iov-猎隼折翼 (LIEsun / Falcon-with-a-broken-wing) — stage 2: alignment + template
classification + AEAD brute-force.

Reuses the layer parsing of ../work-liesun/solve.py (do NOT re-parse the OTA):
works directly on the extracted diag_*.bin artifacts.

KEY STRUCTURAL FINDINGS (this stage)
  * trace_regions "bank0_b:16384:256:32:2" means 256 windows of 64 samples, and
    the window splits into TWO replicates of 32 samples whose spike-bin sets are
    IDENTICAL in 256/256 cases  ->  replicate=2 is an intra-window duplicate.
  * Therefore bank0_b / bank1_b each hold 256 symbols (region_b projection).
  * bank0_a / bank1_a hold 512 windows; trace_indices=128-255,384-511 selects
    exactly 256 of them  ->  256 symbols per bank. 512 symbols total.
  * Template hot sets are pure binary patterns; (region_a set, region_b set) is
    injective over the actually-used alphabet -7..7, ambiguous only for |v|>=8.
"""
import array, collections, hmac, hashlib, itertools, struct, sys

W = "~/.ctfagent/.tmp/work-liesun/"
DIAG = W

SPIKE_TH = 22.0          # spikes sit at 40 +- 5; noise floor is |x| < 20


# ------------------------------------------------------------------ load layer
def load():
    tr = array.array("f"); tr.frombytes(open(DIAG + "diag_trace.bin", "rb").read())
    prof = open(DIAG + "diag_profiles.bin", "rb").read()
    vals = struct.unpack("<63h", prof[:126])
    o = 126
    ra = struct.unpack("<2016f", prof[o:o + 8064]); o += 8064
    rb = struct.unpack("<2016f", prof[o:o + 8064]); o += 8064
    sa = struct.unpack("<32f", prof[o:o + 128]); o += 128
    sb = struct.unpack("<32f", prof[o:o + 128])
    pay = open(DIAG + "diag_payload.bin", "rb").read()
    return tr, vals, ra, rb, sa, sb, pay


def hot(row):
    return tuple(j for j, v in enumerate(row) if v > 1.0)


def build_templates(vals, ra, rb):
    A = [hot(ra[i * 32:(i + 1) * 32]) for i in range(63)]
    B = [hot(rb[i * 32:(i + 1) * 32]) for i in range(63)]
    tpl = collections.defaultdict(list)
    for i in range(63):
        tpl[(A[i], B[i])].append(vals[i])
    return A, B, tpl


# ---------------------------------------------------------------- observations
def win_bins(tr, base, w, th=SPIKE_TH):
    o = base + w * 32
    return tuple(j for j in range(32) if tr[o + j] > th)


def obs(tr, base, w, th=SPIKE_TH):
    """b-region windows are 64 samples = 2 replicates; average then threshold."""
    o = base + w * 64
    return tuple(j for j in range(32)
                 if (tr[o + j] + tr[o + 32 + j]) / 2.0 > th)


REG = {"a0": (0, 32), "b0": (16384, 64), "a1": (32768, 32), "b1": (49152, 64)}


# ------------------------------------------------------------------- kdf / aead
def kdf_candidates(ikm, prefix, aad):
    """Yield (name, 32-byte key)."""
    P = prefix.encode() if isinstance(prefix, str) else prefix
    Ad = aad.encode() if isinstance(aad, str) else aad
    yield "sha256(P||ikm)", hashlib.sha256(P + ikm).digest()
    yield "sha256(ikm||P)", hashlib.sha256(ikm + P).digest()
    yield "sha256(ikm)", hashlib.sha256(ikm).digest()
    yield "sha256(P||ikm||Ad)", hashlib.sha256(P + ikm + Ad).digest()
    for salt in (b"", P, Ad, P + Ad, Ad + P, None):
        for info in (P, Ad, P + Ad, b"", None):
            try:
                k = hkdf_sha256(ikm, 32, salt, info)
            except Exception:
                continue
            yield f"hkdf(s={salt!r},i={info!r})", k
    # sha512 halves
    h = hashlib.sha512(P + ikm).digest()
    yield "sha512(P||ikm)[:32]", h[:32]
    yield "sha512(ikm||P)[32:]", h[32:]


def hkdf_sha256(ikm, n, salt=None, info=None):
    if salt is None:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < n:
        t = hmac.new(prk, t + (info or b"") + bytes([i]), hashlib.sha256).digest()
        okm += t; i += 1
    return okm[:n]


def aes_gcm_open(key, nonce, ct, tag, aad):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except Exception:
        return None
    try:
        return AESGCM(key).decrypt(nonce, ct + tag, aad)
    except Exception:
        return None


# ---------------------------------------------------------------- the decoding
def decode(tr, tpl, a_base, a_aseq, b_base, b_seq):
    """Return list of (A-set, B-set, candidates) for the 256 symbols."""
    out = []
    for k in range(256):
        aset = win_bins(tr, a_base, a_aseq[k])
        bset = obs(tr, b_base, b_seq[k])
        out.append((aset, bset, tpl.get((aset, bset))))
    return out


def main():
    tr, vals, ra, rb, sa, sb, pay = load()
    A, B, tpl = build_templates(vals, ra, rb)
    PREFIX = "GW-FALCON-KDF-v1"
    AAD = b"GW-DIAG-PAYLOAD"

    print(f"[load] trace={len(tr)} payload={len(pay)} templates=63 pairs={len(tpl)}")
    print(f"[payload] {pay.hex()}")

    # sanity: intra-window replicate agreement
    for nm, base in (("bank0_b", 16384), ("bank1_b", 49152)):
        m = sum(1 for w in range(256)
                if win_bins(tr, base, 2 * w) == win_bins(tr, base, 2 * w + 1))
        print(f"[repl] {nm}: 32-sample replicate agreement {m}/256")

    # ---- alignment hypotheses --------------------------------------------
    a_seqs = {
        "idx_hi_lo": [128 + s for s in range(128)] + [384 + s for s in range(128)],
        "idx_lo_hi": [384 + s for s in range(128)] + [128 + s for s in range(128)],
        "idx_inter": [x for s in range(128) for x in (128 + s, 384 + s)],
        "first256": list(range(256)),
        "last256": list(range(256, 512)),
        "lo_hi_plain": list(range(128)) + list(range(384, 512)),
    }
    b_seqs = {"seq": list(range(256)), "rev": list(range(255, -1, -1)),
              "inter": None}

    # b_seq "inter" = interpret b's 256 windows in 2 half-blocks
    best = []
    payload_ct, payload_tag = pay[12:60], pay[60:76]
    nonce_main = pay[:12]

    for aname, a_seq in a_seqs.items():
        for bname, b_seq in b_seqs.items():
            if b_seq is None:
                continue
            for a_base, b_base, bank in ((0, 16384, "bank0"), (32768, 49152, "bank1")):
                syms = decode(tr, tpl, a_base, a_seq, b_base, b_seq)
                unamb = sum(1 for _, _, c in syms if c and len(c) == 1)
                amb = collections.Counter(len(c) if c else 0 for _, _, c in syms)
                print(f"[align] {aname:11s}/{bname:4s} {bank}: "
                      f"unambiguous={unamb}/256 amb={dict(amb)}")
    print()

    # ---- full brute force over alignment x encoding x kdf ----------------
    hits = []
    for aname, a_seq in a_seqs.items():
        for bname, b_seq in b_seqs.items():
            if b_seq is None:
                continue
            # concatenate bank0 then bank1 (and also bank1 then bank0)
            for order in (("bank0", "bank1"), ("bank1", "bank0")):
                vals_seq = []
                amb_ok = True
                for bank in order:
                    a_base, b_base = ((0, 16384) if bank == "bank0" else (32768, 49152))
                    for aset, bset, cand in decode(tr, tpl, a_base, a_seq, b_base, b_seq):
                        if not cand:
                            amb_ok = False; break
                        vals_seq.append(cand[0] if len(cand) == 1 else None)
                    if not amb_ok:
                        break
                if not amb_ok:
                    continue
                # encodings
                encs = {}
                for off in (0, 0x80):
                    encs[f"u8+{off}"] = bytes(((v if v is not None else 0) + off) & 0xFF
                                              for v in vals_seq)
                # 4-bit two's complement pairs (value in -7..7 fits)
                nib = []
                for v in vals_seq:
                    if v is None: nib.append(0); continue
                    nib.append(v & 0xF)
                encs["nibble"] = bytes((nib[i] << 4) | nib[i + 1]
                                       for i in range(0, len(nib) - 1, 2))
                encs["nibble_lo"] = bytes(nib[i] | (nib[i + 1] << 4)
                                          for i in range(0, len(nib) - 1, 2))
                # magnitude only
                encs["abs"] = bytes((abs(v) if v is not None else 0) & 0xFF
                                    for v in vals_seq)
                for ename, ikm in encs.items():
                    for kname, key in kdf_candidates(ikm, PREFIX, AAD):
                        for nname, nonce in (("head12", pay[:12]), ("zero12", b"\0" * 12)):
                            pt = aes_gcm_open(key, nonce, pay[12:60], pay[60:76], AAD)
                            if pt:
                                hits.append((aname, bname, order, ename, kname,
                                             nname, pt))
                                print("!!! HIT", hits[-1][:6], pt)
    print(f"\n[brute] {len(hits)} hits")
    for h in hits:
        print(h[6])


if __name__ == "__main__":
    main()
