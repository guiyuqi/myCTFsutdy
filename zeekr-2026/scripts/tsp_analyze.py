#!/usr/bin/env python3
"""attachments2.zip / TSP shadow envelope analysis.

Decodes every envelope in the MQTT shadow trace, independently verifies the
P-256 ECDSA signature over the exact protected_payload_b64 bytes, and reports
which envelopes a March-policy gateway would accept.
"""
import base64
import hashlib
import json
import sys

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

TRACE = "work/att2/attachments/evidence/mqtt_shadow_trace.jsonl"
PEM = "work/att2/attachments/pki/tsp_vehicle_signer_public.pem"

pub = load_pem_public_key(open(PEM, "rb").read())
der = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
nums = pub.public_numbers()

print("=" * 100)
print("PUBLIC KEY")
print("=" * 100)
print(f"curve        : {pub.curve.name}")
print(f"DER len      : {len(der)} bytes")
print(f"SHA256(DER)  : {hashlib.sha256(der).hexdigest()}")
print(f"x            : {nums.x:064x}")
print(f"y            : {nums.y:064x}")
print()

rows = []
with open(TRACE) as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        env = rec["envelope"]
        hdr_raw = base64.b64decode(env["header_b64"])
        pay_raw = base64.b64decode(env["protected_payload_b64"])
        sig = bytes.fromhex(env["signature_p256_raw_hex"])
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        try:
            pub.verify(asym_utils.encode_dss_signature(r, s), pay_raw,
                       ec.ECDSA(hashes.SHA256()))
            verdict = "VALID"
        except InvalidSignature:
            verdict = "INVALID"
        hdr = json.loads(hdr_raw)
        pay = json.loads(pay_raw)
        rows.append(dict(frame=rec["frame"], topic=rec["topic"], hdr=hdr, pay=pay,
                         hdr_raw=hdr_raw, pay_raw=pay_raw, sig_ok=verdict,
                         trace_says=rec.get("wire_signature_valid")))

print("=" * 100)
print("ENVELOPE TABLE")
print("=" * 100)
for r in rows:
    print(f"frame {r['frame']:>4}  topic-vin={r['topic'].split('/')[2]}  sig={r['sig_ok']:<7} "
          f"(trace says {r['trace_says']})")
    print(f"    header  : {r['hdr_raw'].decode()}")
    print(f"    payload : {r['pay_raw'].decode()}")
    print()

print("=" * 100)
print("GATEWAY ACCEPTANCE (March policy: epoch=20260314)")
print("=" * 100)
PLATFORM_EPOCH = 20260314
for r in rows:
    h, p = r["hdr"], r["pay"]
    vin = r["topic"].split("/")[2]
    checks = {
        "sig_valid": r["sig_ok"] == "VALID",
        "topic_vin_matches_payload_vin": p.get("vin") == vin,
        "policy_epoch==platform": h.get("policy_epoch") == PLATFORM_EPOCH,
        "merge_mode accepted": h.get("merge_mode") in ("authoritative", "advisory_first"),
        "payload.version>=250": p.get("version", 0) >= 250,
        "remote_cmd==unlock": p.get("remote_cmd") == "unlock",
        "maintenance_mode==true": p.get("maintenance_mode") is True,
        "operator_scope==factory": p.get("operator_scope") == "factory",
    }
    fails = [k for k, v in checks.items() if not v]
    print(f"frame {r['frame']:>4}: {'ACCEPT' if not fails else 'reject'}  "
          f"{'' if not fails else 'fails: ' + ', '.join(fails)}")
print()

print("=" * 100)
print("CANDIDATE UNLOCK PAYLOADS (valid signature, unlock/factory/maintenance)")
print("=" * 100)
for r in rows:
    p = r["pay"]
    if (r["sig_ok"] == "VALID" and p.get("remote_cmd") == "unlock"
            and p.get("maintenance_mode") is True and p.get("operator_scope") == "factory"):
        print(f"frame {r['frame']}: vin={p['vin']} version={p['version']} "
              f"topic_vin={r['topic'].split('/')[2]} "
              f"same_vehicle={p['vin'] == r['topic'].split('/')[2]}")

json.dump(rows, open("work/att2/decoded_envelopes.json", "w"), indent=1)
print("\n[+] decoded dump -> work/att2/decoded_envelopes.json")
