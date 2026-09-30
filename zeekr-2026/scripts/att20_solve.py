#!/usr/bin/env python3
"""
GEELY "Ghost Fleet" / hidden-fleet register recovery  (attachments20.zip)

Chain
-----
1. Each fragment = 16x8 dot matrix -> 16 bytes (row=byte, left col=bit7).
   Validity: TL mark filled, TR mark empty, PARITY disc == XOR of all data dots.
   Exactly three fragments pass (A17 / C09 / F31) - corroborated by
   custody_manifest.csv (continuous + red-wax + IR-004-C).
2. SIGNING KEY = XOR of the three 16-byte values
              = 357bdfa2e150477dbda20531bce9eac9
3. Canonical tenant = "ops_shadow" (broker alias "shadow operations" remapped by
   the internal console).  Vehicle from chassis_label.png, clock from the note.
4. record = "ops_shadow|LSVA24RZ7M1098423|1789600000"
5. FLAG = GEELY{ SHA-256( ASCII(record) || key_bytes ).hexdigest() }   # NOT HMAC
"""
import hashlib
import os

import numpy as np
from PIL import Image

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                    "work", "att20", "attachments")
COLS = [112, 137, 162, 187, 212, 237, 262, 287]
ROWS = [130 + 25 * r for r in range(16)]


def fragment(path):
    a = np.array(Image.open(path).convert("L"))
    dark = a < 128
    data = bytes(
        sum((1 if dark[y - 3:y + 4, x - 3:x + 4].mean() > 0.5 else 0) << (7 - c)
            for c, x in enumerate(COLS))
        for y in ROWS)
    tl = dark[24:45, 24:45].mean() > 0.5        # top-left calibration square
    tr = dark[24:45, 375:396].mean() > 0.5      # top-right calibration square
    par = dark[452:473, 30:51].mean() > 0.5     # PARITY disc, left margin
    xor_all = 0
    for b in data:
        xor_all ^= b
    return data, (tl and not tr and par == bool(bin(xor_all).count("1") & 1))


def main():
    frags = {}
    for i in range(1, 6):
        d, ok = fragment(os.path.join(BASE, "fragments", f"fragment_0{i}.png"))
        frags[i] = d
        print(f"fragment_0{i}: {d.hex()}  {'VALID' if ok else 'invalid'}")
    good = [i for i in frags if fragment(
        os.path.join(BASE, "fragments", f"fragment_0{i}.png"))[1]]
    print("valid:", good)
    key = bytes(a ^ b ^ c for a, b, c in zip(*(frags[i] for i in good)))
    print("signing key:", key.hex())

    record = b"ops_shadow|LSVA24RZ7M1098423|1789600000"
    digest = hashlib.sha256(record + key).hexdigest()
    print("record     :", record.decode())
    print(f"FLAG = GEELY{{{digest}}}")


if __name__ == "__main__":
    main()
