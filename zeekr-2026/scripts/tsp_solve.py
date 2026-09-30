#!/usr/bin/env python3
"""GEELY TSP shadow-envelope header-rebinding solver (attachments3.zip).

Vulnerability
-------------
The gateway verifies the P-256 signature over `protected_payload_b64` ONLY.
`policy_epoch` and `merge_mode` live in the *unprotected* header, so an attacker
can rewrite them and the signature still verifies.

March gateway policy (platform_policy_epoch = 20260314):
  * header.policy_epoch == platform_policy_epoch
  * header.merge_mode   in {authoritative, advisory_first}
  * payload.version     >= 250                  <- waived by advisory_first
  * remote_cmd == "unlock" requires maintenance_mode == true
                                and  operator_scope   == "factory"

So: take a captured, validly-signed unlock/factory/maintenance payload whose
version is below 250, and rebind its unprotected header to
policy_epoch=20260314 + merge_mode="advisory_first".

Flag:
  CODE = SHA-256( SHA-256(DER(SPKI)) || SHA-256(signed payload bytes) ||
                  SHA-256(exact new header bytes) || ASCII("TSP-SHADOW-REBIND") )
  FLAG = GEELY{TSP_<first24 hex>_<last24 hex>}
"""
import os
import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.primitives.serialization import (Encoding, PublicFormat,
                                                          load_pem_public_key)

BASE = os.path.expanduser("~/ctf-2026/work/att3/attachments")
TRACE = f"{BASE}/evidence/mqtt_shadow_trace.jsonl"
PEM = f"{BASE}/pki/tsp_vehicle_signer_public.pem"
PLATFORM_EPOCH = 20260314
TAG = b"TSP-SHADOW-REBIND"

pub = load_pem_public_key(open(PEM, "rb").read())
spki = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
spki_sha = hashlib.sha256(spki).digest()
print(f"[+] SPKI DER {len(spki)}B  SHA-256 = {spki_sha.hex()}")


def sig_ok(pay, sig):
    try:
        pub.verify(asym_utils.encode_dss_signature(int.from_bytes(sig[:32], "big"),
                                                   int.from_bytes(sig[32:], "big")),
                   pay, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


frames = []
for line in open(TRACE):
    if not line.strip():
        continue
    rec = json.loads(line)
    env = rec["envelope"]
    hdr = base64.b64decode(env["header_b64"])
    pay = base64.b64decode(env["protected_payload_b64"])
    sig = bytes.fromhex(env["signature_p256_raw_hex"])
    frames.append({"frame": rec["frame"], "topic_vin": rec["topic"].split("/")[2],
                   "hdr": hdr, "hdr_obj": json.loads(hdr), "pay": pay,
                   "pay_obj": json.loads(pay), "sig": sig,
                   "local_sig": sig_ok(pay, sig),
                   "trace_sig": rec["wire_signature_valid"]})

print("\n" + "=" * 96)
print("FRAME TABLE  (local verification is authoritative; trace field is untrusted data)")
print("=" * 96)
for f in frames:
    p = f["pay_obj"]
    print(f"frame {f['frame']:>4}  vin={p.get('vin')} topic={f['topic_vin']} "
          f"ver={p.get('version')} cmd={p.get('remote_cmd')} maint={p.get('maintenance_mode')} "
          f"scope={p.get('operator_scope')} epoch={f['hdr_obj']['policy_epoch']}")
    print(f"          local_sig={f['local_sig']}  trace_sig={f['trace_sig']}")

# ---- gateway acceptance model, BEFORE and AFTER header rebinding -------------
def gateway_ok(f, hdr_obj=None):
    h = hdr_obj or f["hdr_obj"]
    p = f["pay_obj"]
    reasons = []
    if not f["local_sig"]:
        reasons.append("signature")
    if p.get("vin") != f["topic_vin"]:
        reasons.append("topic/vin mismatch")
    if h.get("policy_epoch") != PLATFORM_EPOCH:
        reasons.append("policy_epoch!=platform")
    if h.get("merge_mode") not in ("authoritative", "advisory_first"):
        reasons.append("merge_mode rejected")
    # advisory_first relaxes the version floor for offline repair reconciliation
    if h.get("merge_mode") != "advisory_first" and p.get("version", 0) < 250:
        reasons.append("version<250")
    if p.get("remote_cmd") == "unlock":
        if p.get("maintenance_mode") is not True:
            reasons.append("maintenance_mode!=true")
        if p.get("operator_scope") != "factory":
            reasons.append("operator_scope!=factory")
    return reasons


rebind = {"alg": "ES256", "kid": "TSP-SHADOW-33",
          "policy_epoch": PLATFORM_EPOCH, "merge_mode": "advisory_first"}
hdr_new = json.dumps(rebind, separators=(",", ":")).encode()
print("\n[+] rebound header bytes:")
print(f"    {hdr_new.decode()}")
print(f"    SHA-256 = {hashlib.sha256(hdr_new).hexdigest()}")

# cross-check: byte-level flip of the platform frame (331) header
plat = next(f for f in frames if f["frame"] == 331)["hdr"]
assert plat.replace(b'"authoritative"', b'"advisory_first"') == hdr_new, "header shape mismatch"
print("[+] matches byte-level 'authoritative'->'advisory_first' edit of the platform header")

print("\n" + "=" * 96)
print("REBINDING CANDIDATES (signature valid + VIN match + unlock/factory/maintenance)")
print("=" * 96)


def code_for(f, hdr_bytes):
    pay_sha = hashlib.sha256(f["pay"]).digest()
    h_sha = hashlib.sha256(hdr_bytes).digest()
    return hashlib.sha256(spki_sha + pay_sha + h_sha + TAG).hexdigest(), pay_sha, h_sha


results = []
for f in frames:
    p = f["pay_obj"]
    if not (f["local_sig"] and p.get("vin") == f["topic_vin"]
            and p.get("remote_cmd") == "unlock" and p.get("maintenance_mode") is True
            and p.get("operator_scope") == "factory" and p.get("version", 0) < 250):
        continue
    before = gateway_ok(f)
    after = gateway_ok(f, rebind)
    code, pay_sha, h_sha = code_for(f, hdr_new)
    flag = f"GEELY{{TSP_{code[:24]}_{code[-24:]}}}"
    print(f"\nframe {f['frame']}  (version {p['version']}, trace_sig={f['trace_sig']})")
    print(f"    gateway before rebind : {'ACCEPT' if not before else 'reject -> ' + ', '.join(before)}")
    print(f"    gateway after  rebind : {'ACCEPT' if not after else 'reject -> ' + ', '.join(after)}")
    print(f"    SHA-256(payload) = {pay_sha.hex()}")
    print(f"    SHA-256(header)  = {h_sha.hex()}")
    print(f"    CODE             = {code}")
    print(f"    FLAG             = {flag}")
    results.append({"frame": f["frame"], "version": p["version"],
                    "trace_sig": f["trace_sig"], "code": code, "flag": flag})

# non-canonical header encodings, for completeness on the primary candidate
alt = {}
prim = results[0]
pf = next(f for f in frames if f["frame"] == prim["frame"])
variants = {
    "json_pretty": json.dumps(rebind, indent=2).encode(),
    "json_spaced": json.dumps(rebind).encode(),
    "json_sorted": json.dumps(rebind, sort_keys=True, separators=(",", ":")).encode(),
    "header_b64_text": base64.b64encode(hdr_new),
}
for name, hb in variants.items():
    c, _, _ = code_for(pf, hb)
    alt[name] = f"GEELY{{TSP_{c[:24]}_{c[-24:]}}}"

print("\n" + "=" * 96)
print(f"HEADER-ENCODING VARIANTS (frame {prim['frame']}) — canonical is 'exact JSON bytes'")
print("=" * 96)
for k, v in alt.items():
    print(f"    {k:<16} {v}")

print("\n" + "=" * 96)
print("RESULT")
print("=" * 96)
print(f"  PRIMARY   frame {prim['frame']} -> {prim['flag']}")
for r in results[1:]:
    print(f"  ALTERNATE frame {r['frame']} -> {r['flag']}   (trace_sig={r['trace_sig']})")

json.dump({"spki_sha256": spki_sha.hex(), "rebound_header": hdr_new.decode(),
           "rebound_header_sha256": hashlib.sha256(hdr_new).hexdigest(),
           "candidates": results, "header_encoding_variants": alt},
          open(os.path.expanduser("~/ctf-2026/work/att3/solve-result.json"), "w"), indent=2)
print("\n[+] wrote work/att3/solve-result.json")
