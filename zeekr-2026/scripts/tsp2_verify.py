#!/usr/bin/env python3
"""Independent verification pass for attachments2.zip (GEELY TSP shadow envelope).

This is a from-scratch re-derivation written without reusing scripts/tsp_solve.py:
the new header is produced by a byte-level edit of the platform envelope's header
(downgrading merge_mode), NOT by re-serialising JSON, so the "exact new header
bytes" question is settled by construction.

Run:  python3 scripts/tsp2_verify.py
"""
import base64
import hashlib
import json

from cryptography.hazmat.primitives.serialization import (Encoding, PublicFormat,
                                                          load_pem_public_key)

BASE = "work/att2/attachments"

pub = load_pem_public_key(open(f"{BASE}/pki/tsp_vehicle_signer_public.pem", "rb").read())
der = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

rows = [json.loads(l) for l in open(f"{BASE}/evidence/mqtt_shadow_trace.jsonl") if l.strip()]
by = {r["frame"]: r for r in rows}
b64 = lambda frame, field: base64.b64decode(by[frame]["envelope"][field])

payload_188 = b64(188, "protected_payload_b64")
header_331 = b64(331, "header_b64")
header_188 = b64(188, "header_b64")

# The crafted header: take the platform (frame 331) header verbatim and flip the
# unprotected merge_mode field to the retained advisory_first mode.
new_header = header_331.replace(b'"authoritative"', b'"advisory_first"')

# Three independent constructions must agree byte-for-byte.
build_json = json.dumps({"alg": "ES256", "kid": "TSP-SHADOW-33",
                         "policy_epoch": 20260314, "merge_mode": "advisory_first"},
                        separators=(",", ":")).encode()
build_edit188 = header_188.replace(b"20260201", b"20260314").replace(
    b'"authoritative"', b'"advisory_first"')
assert new_header == build_json == build_edit188, "header construction mismatch"

d_der = hashlib.sha256(der).digest()
d_pay = hashlib.sha256(payload_188).digest()
d_hdr = hashlib.sha256(new_header).digest()
code = hashlib.sha256(d_der + d_pay + d_hdr + b"TSP-SHADOW-REBIND").hexdigest()
flag = f"GEELY{{TSP_{code[:24]}_{code[-24:]}}}"

print("payload 188 :", payload_188.decode())
print("new header  :", new_header.decode(), f"({len(new_header)} bytes)")
print("header builds agree (byte-edit == json.dumps == edit-188): True")
print()
print("SHA256(DER SPKI)    :", d_der.hex())
print("SHA256(payload 188) :", d_pay.hex())
print("SHA256(new header)  :", d_hdr.hex())
print("CODE                :", code)
print()
print("FLAG                :", flag)

payload_209 = b64(209, "protected_payload_b64")
c209 = hashlib.sha256(d_der + hashlib.sha256(payload_209).digest() + d_hdr
                      + b"TSP-SHADOW-REBIND").hexdigest()
print("alt (frame 209)     :", f"GEELY{{TSP_{c209[:24]}_{c209[-24:]}}}")
