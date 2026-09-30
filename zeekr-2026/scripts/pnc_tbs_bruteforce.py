#!/usr/bin/env python3
"""Recover the exact ASCII TBS document format used by the PnC station.

Oracle: each JSONL record ships `tbs_sha256`, presumably SHA-256 of the exact
ASCII TBS.  A candidate formatter is correct iff it reproduces tbs_sha256 for
EVERY record simultaneously.
"""
import os
import hashlib
import itertools
import json
import sys

JSONL = os.path.expanduser("~/ctf-2026/work/pnc1/attachments/evidence/charging_session_archive.jsonl")

records = []
with open(JSONL) as fh:
    for line in fh:
        line = line.strip()
        if line:
            records.append(json.loads(line))

print(f"[*] loaded {len(records)} records")

SPEC_ORDER = [
    "contract_id", "action", "contract_version", "vehicle_status",
    "v2g_state", "policy_epoch", "max_current_a", "price_plan",
    "authorization_scope",
]


def orderings(rec):
    sf = rec["signed_fields"]
    yield "signed", sf
    yield "alpha", sorted(sf)
    yield "spec", [k for k in SPEC_ORDER if k in sf]
    yield "spec_rev", [k for k in reversed(SPEC_ORDER) if k in sf]
    yield "alpha_rev", sorted(sf, reverse=True)


def val(rec, k):
    v = rec[k]
    return str(v)


def fmt_kv(rec, keys, kv_sep, line_sep, trail, quote, upper_key, kv_is_json_like=False):
    parts = []
    for k in keys:
        kk = k.upper() if upper_key else k
        vv = val(rec, k)
        if quote:
            vv = f'"{vv}"'
        parts.append(f"{kk}{kv_sep}{vv}")
    s = line_sep.join(parts)
    if trail:
        s += line_sep
    return s


def fmt_json(rec, keys, compact, quote):
    d = {}
    for k in keys:
        d[k] = val(rec, k)
    if compact:
        return json.dumps(d, separators=(",", ":"), ensure_ascii=False)
    return json.dumps(d, ensure_ascii=False)


def fmt_value_only(rec, keys, sep, trail):
    s = sep.join(val(rec, k) for k in keys)
    return s + (sep if trail else "")


def generate(rec):
    """Yield (label, tbs_bytes) candidates."""
    seen = set()

    # --- header/prefix variants ---
    prefixes = [
        "", "TBS\n", "TBS\r\n", "PNC-TBS\n", "PNC-TBS-v001\n",
        "GEELY-PNC-TBS\n", "GEELY-PNC-TBS-v001\n",
        "GEELY PLUG & CHARGE TBS\n", "TBS:", "DOC\n",
    ]
    suffixes = ["", "\n"]

    kv_seps = ["=", "=", ":", ": ", " = ", "=>"]
    line_seps = ["\n", "\r\n", ";", "; ", "&", "|", ",", ", ", " "]
    trails = [False, True]
    quotes = [False, True]
    upper_keys = [False, True]

    for oname, keys in orderings(rec):
        # A. key/value lines
        for kv_sep, line_sep, trail, quote, up, pre in itertools.product(
                kv_seps, line_seps, trails, quotes, upper_keys, prefixes):
            tbs = pre + fmt_kv(rec, keys, kv_sep, line_sep, trail, quote, up)
            if tbs in seen:
                continue
            seen.add(tbs)
            yield (f"kv ord={oname} kvsep={kv_sep!r} lsep={line_sep!r} "
                   f"trail={trail} quote={quote} upper={up} pre={pre!r}", tbs.encode())

        # B. JSON
        for compact, quote in itertools.product([True, False], [False, True]):
            tbs = fmt_json(rec, keys, compact, quote)
            if tbs not in seen:
                seen.add(tbs)
                yield (f"json ord={oname} compact={compact}", tbs.encode())
            for pre in prefixes:
                t2 = pre + tbs
                if t2 not in seen:
                    seen.add(t2)
                    yield (f"json ord={oname} compact={compact} pre={pre!r}", t2.encode())

        # C. values only
        for sep, trail in itertools.product(["\n", ";", "|", ",", "&", ""], trails):
            tbs = fmt_value_only(rec, keys, sep, trail)
            if tbs not in seen:
                seen.add(tbs)
                yield (f"valonly ord={oname} sep={sep!r} trail={trail}", tbs.encode())

        # D. xml-ish
        for pre_s in ["", "<tbs>\n"]:
            for post_s in ["", "\n</tbs>"]:
                body = "\n".join(f"<{k}>{val(rec,k)}</{k}>" for k in keys)
                tbs = pre_s + body + post_s
                if tbs not in seen:
                    seen.add(tbs)
                    yield (f"xml ord={oname} pre={pre_s!r} post={post_s!r}", tbs.encode())


def main():
    ref = records[0]
    targets = {r["record_id"]: r["tbs_sha256"] for r in records}
    print(f"[*] targets: {json.dumps(targets, indent=2)}")

    # Phase 1: candidates that match record 0
    cands = []
    n = 0
    for label, tbs in generate(ref):
        n += 1
        if hashlib.sha256(tbs).hexdigest() == targets[ref["record_id"]]:
            cands.append((label, tbs))
    print(f"[*] phase1: tested {n} candidates, {len(cands)} matched record0")

    # Phase 2: validate across all records
    good = []
    for label, tbs in cands:
        ok = True
        for r in records[1:]:
            hit = False
            for l2, t2 in generate(r):
                if l2 == label and hashlib.sha256(t2).hexdigest() == targets[r["record_id"]]:
                    hit = True
                    break
            if not hit:
                ok = False
                break
        if ok:
            good.append(label)

    print(f"[*] phase2: fully consistent formats = {good}")
    if good:
        print("[+] TBS format recovered:")
        for g in good:
            print("    ", g)
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
