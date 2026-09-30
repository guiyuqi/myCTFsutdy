#!/usr/bin/env python3
"""Derive the PnC downgrade flag for the accepted schema-v001 historical record."""
import os
import hashlib
import json
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.exceptions import InvalidSignature

BASE = os.path.expanduser("~/ctf-2026/work/pnc1/attachments")
JSONL = f"{BASE}/evidence/charging_session_archive.jsonl"


def load_cert(name):
    with open(f"{BASE}/pki/{name}.pem", "rb") as fh:
        return x509.load_pem_x509_certificate(fh.read())


root, moca, contract = (load_cert("v2g_root_ca"), load_cert("mobility_operator_ca"),
                        load_cert("ev_contract_cert"))
contract_pub = contract.public_key()
contract_der = contract.public_bytes(serialization.Encoding.DER)
contract_der_sha = hashlib.sha256(contract_der).digest()

CONTRACT_CN = contract.subject.get_attributes_for_oid(
    x509.oid.NameOID.COMMON_NAME)[0].value
vin_key = CONTRACT_CN.replace("PNC-EV-VIN-", "")
print(f"[+] contract cert: {CONTRACT_CN}")
print(f"[+] SHA-256(DER(cert)) = {contract_der_sha.hex()}")


def build_tbs(rec):
    return ("GEELY-PNC-TBS\n" +
            "".join(f"{k}={rec[k]}\n" for k in rec["signed_fields"])).encode()


def sig_ok(rec):
    raw = bytes.fromhex(rec["signature_p256_raw"])
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"),
                               int.from_bytes(raw[32:], "big"))
    try:
        contract_pub.verify(der, build_tbs(rec), ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


records = [json.loads(l) for l in open(JSONL) if l.strip()]

accepted = []
for rec in records:
    at = datetime.datetime.fromisoformat(rec["at"].replace("Z", "+00:00"))
    ok = (rec["action"] == "MIGRATE"
          and rec["vehicle_status"] == "PARKED_CONNECTED"
          and rec["v2g_state"] == "SESSION_ESTABLISHED"
          and sig_ok(rec)
          and hashlib.sha256(build_tbs(rec)).hexdigest() == rec["tbs_sha256"]
          and vin_key in rec["contract_id"]
          and contract.not_valid_before_utc <= at <= contract.not_valid_after_utc)
    if ok:
        accepted.append(rec)

# The vulnerability under test is the schema-v001 compatibility downgrade:
# only a v001 document OMITS the optional constraint fields, so only it is
# evaluated against the fixed compatibility defaults.
downgrade = [r for r in accepted if r["contract_version"] == "v001"]
assert len(downgrade) == 1, [r["record_id"] for r in downgrade]
acc = downgrade[0]

print(f"\n[+] accepted MIGRATE records : {[r['record_id'] for r in accepted]}")
print(f"[+] v001 downgrade record    : {acc['record_id']}  at={acc['at']}  "
      f"station={acc['station']}")
print(f"[+] signed_fields            : {acc['signed_fields']}")
print(f"[+] OMITTED optional fields  : max_current_a, price_plan, "
      f"authorization_scope")
print("    -> compat defaults applied: max_current_a=250, "
      "price_plan=PUBLIC_UNMETERED, authorization_scope=PnC-START-MAINTENANCE")
print(f"\n[+] exact ASCII TBS:\n{'-'*46}")
print(build_tbs(acc).decode(), end="")
print(f"{'-'*46}")

TAG = (b"PNC-DOWNGRADE-ACCEPTED"
       b"max_current_a=250"
       b"authorization_scope=PnC-START-MAINTENANCE")

# canonical: hashes are the 32-byte digests
code_raw = hashlib.sha256(contract_der_sha + bytes.fromhex(acc["tbs_sha256"]) + TAG).hexdigest()
# alt: hex-string concatenation
code_hex = hashlib.sha256(contract_der_sha.hex().encode()
                          + acc["tbs_sha256"].encode() + TAG).hexdigest()

print(f"\nCODE (raw digests) = {code_raw}")
print(f"CODE (hex strings) = {code_hex}")
print(f"\n>>> FLAG(raw) = GEELY{{PNC_{code_raw[:24]}_{code_raw[-24:]}}}")
print(f">>> FLAG(hex) = GEELY{{PNC_{code_hex[:24]}_{code_hex[-24:]}}}")

json.dump({"accepted_record": acc, "tbs": build_tbs(acc).decode(),
           "code_raw": code_raw, "code_hex": code_hex,
           "flag_raw": f"GEELY{{PNC_{code_raw[:24]}_{code_raw[-24:]}}}",
           "flag_hex": f"GEELY{{PNC_{code_hex[:24]}_{code_hex[-24:]}}}"},
          open(os.path.expanduser("~/ctf-2026/work/pnc1/result.json"), "w"), indent=2)
