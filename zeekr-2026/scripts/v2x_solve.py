#!/usr/bin/env python3
"""GEELY V2X BSM challenge solver.

Attack: ECDSA nonce reuse across two pseudonym certificates that were issued
for the SAME private key. Frames 1 and 2 share an identical `r`, so
    k = (h1 - h2) / (s1 - s2) mod n
    d = (s1 * k - h1) / r      mod n
Then TOKEN = SHA-256("GEELY-V2X-KEY-RECOVERY" || d_be32 || cidA || cidB ||
                    SHA-256(DER(root CA cert)))
with the two 8-byte certificate IDs in ascending order.
"""
import hashlib
import json
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

BASE = Path(__file__).resolve().parent.parent / "work" / "v2x" / "attachments"

# --- P-256 domain parameters ---
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def inv(a, m):
    return pow(a, -1, m)


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = point_add(r, pt)
        pt = point_add(pt, pt)
        k >>= 1
    return r


G = (GX, GY)


def parse_frames(path):
    frames = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        o = json.loads(line)
        b = bytes.fromhex(o["raw_hex"])
        assert b[:4] == b"GEVX", b[:4]
        cidlen = b[5]
        cid = b[6:6 + cidlen]
        off = 6 + cidlen
        tbslen = int.from_bytes(b[off:off + 2], "big")
        off += 2
        siglen = b[off]
        off += 1
        sig = b[off:off + siglen]
        off += siglen
        tbs = b[off:off + tbslen]
        assert off + tbslen == len(b), (off + tbslen, len(b))
        frames.append({
            "frame": o["frame"],
            "cid": cid,
            "r": int.from_bytes(sig[:32], "big"),
            "s": int.from_bytes(sig[32:], "big"),
            "tbs": tbs,
            "h": int.from_bytes(hashlib.sha256(tbs).digest(), "big"),
        })
    return frames


def main():
    frames = parse_frames(BASE / "evidence" / "v2x_session.jsonl")
    print("[*] parsed frames")
    for f in frames:
        print(f"    frame{f['frame']} cid={f['cid'].hex()} r={f['r']:064x}")
        print(f"                     s={f['s']:064x}")

    # --- 1. find the nonce-reuse pair ---
    pair = None
    for i in range(len(frames)):
        for j in range(i + 1, len(frames)):
            if frames[i]["r"] == frames[j]["r"]:
                pair = (frames[i], frames[j])
    if pair is None:
        sys.exit("[-] no shared-r pair found")
    f1, f2 = pair
    print(f"[+] nonce reuse between frame{f1['frame']} and frame{f2['frame']}")

    r = f1["r"]
    k = (f1["h"] - f2["h"]) * inv(f1["s"] - f2["s"], N) % N
    d = (f1["s"] * k - f1["h"]) * inv(r, N) % N
    print(f"[+] k = {k:064x}")
    print(f"[+] d = {d:064x}")

    # --- 2. verify d against every signature and every cert pubkey ---
    for f in frames:
        kinv = inv(k if f["r"] == r else 0, N) if f["r"] == r else None
        # generic check: recompute s from d, k is only known for the reused pair
        if kinv is not None:
            ok = (kinv * (f["h"] + r * d)) % N == f["s"]
            print(f"[*] frame{f['frame']} signature reproduced with d: {ok}")

    # verify public key d*G equals the cert public keys
    pub = point_mul(d, G)
    pub_comp = b"\x04" + pub[0].to_bytes(32, "big") + pub[1].to_bytes(32, "big")
    print(f"[*] d*G = {pub_comp.hex()}")

    bundle = x509.load_pem_x509_certificates((BASE / "pki" / "pseudonym_bundle.pem").read_bytes())
    matching = []
    for c in bundle:
        spki = c.public_key().public_numbers()
        cert_pub = b"\x04" + spki.x.to_bytes(32, "big") + spki.y.to_bytes(32, "big")
        same = cert_pub == pub_comp
        print(f"[*] cert serial {c.serial_number:08x} pubkey matches d*G: {same}")
        if same:
            matching.append(c)

    # independent crypto-lib verification using the raw scalars
    priv = ec.derive_private_key(d, ec.SECP256R1())
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    for f in frames:
        if f["r"] != r:
            continue
        sig = encode_dss_signature(f["r"], f["s"])
        try:
            priv.public_key().verify(sig, f["tbs"],
                                     ec.ECDSA(__import__("cryptography.hazmat.primitives.hashes",
                                                         fromlist=["SHA256"]).SHA256()))
            print(f"[*] cryptography-lib verify frame{f['frame']}: OK")
        except Exception as e:  # noqa: BLE001
            print(f"[*] cryptography-lib verify frame{f['frame']}: FAIL {e}")

    # --- 3. build the recovery token ---
    ca_der = x509.load_pem_x509_certificate((BASE / "pki" / "ca_cert.pem").read_bytes())
    from cryptography.hazmat.primitives.serialization import Encoding
    ca_der_bytes = ca_der.public_bytes(Encoding.DER)
    ca_hash = hashlib.sha256(ca_der_bytes).digest()
    print(f"[+] SHA-256(DER(root CA)) = {ca_hash.hex()}")

    cids = sorted([f1["cid"], f2["cid"]])
    token = hashlib.sha256(
        b"GEELY-V2X-KEY-RECOVERY" + d.to_bytes(32, "big") + cids[0] + cids[1] + ca_hash
    ).hexdigest()
    print(f"[+] TOKEN = {token}")
    flag = f"GEELY{{V2X_{token[:24]}_{token[-24:]}}}"
    print(f"[+] FLAG  = {flag}")

    out = {
        "k": f"{k:064x}",
        "d": f"{d:064x}",
        "cids": [c.hex() for c in cids],
        "ca_der_sha256": ca_hash.hex(),
        "token": token,
        "flag": flag,
    }
    return out, frames, matching


if __name__ == "__main__":
    out, _, _ = main()
    Path(__file__).resolve().parent.parent.joinpath("work/v2x/solve-result.json").write_text(
        json.dumps(out, indent=2) + "\n")
