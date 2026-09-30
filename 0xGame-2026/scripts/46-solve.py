#!/usr/bin/env python3
"""0xGame 2026 - 46 Interesting_ppt  (Misc / document steg, offline)

Story: "used AI to build a recruitment PPT; after completely deleting the AI
watermark he left an easter egg."

Facts recovered from the OOXML package:
  * docProps/custom.xml  -> custom property name="AIGC" (the "AI watermark"),
    value is base64 ciphertext.
  * docProps/core.xml    -> a stray base64 blob smuggled *inside*
    <cp:coreProperties> (illegal position, so PowerPoint ignores it):
        a2V5PTB4R2FtZV8yMDI2   ->  b"key=0xGame_2026"

Decrypt: base64 -> repeating-key XOR with b"0xGame_2026" -> base64 -> flag.

Usage:  python3 scripts/46-solve.py [path/to/0xgame.zip|0xgame.pptx]
"""
import base64
import io
import os
import re
import sys
import zipfile

DEFAULT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "firmware", "46_Interesting_ppt", "0xgame.zip",
)


def open_pptx(path):
    """Return the raw bytes of the .pptx (handles both .zip and .pptx input)."""
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            if "[Content_Types].xml" in names:          # already a pptx
                return open(path, "rb").read()
            for n in names:                             # the challenge zip
                if n.lower().endswith((".pptx", ".ppt")):
                    return z.read(n)
    raise SystemExit("no pptx found in %s" % path)


def part(pptx_bytes, name):
    with zipfile.ZipFile(io.BytesIO(pptx_bytes)) as z:
        return z.read(name).decode("utf-8", "replace")


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    data = open_pptx(path)

    core = part(data, "docProps/core.xml")
    custom = part(data, "docProps/custom.xml")

    # 1. key smuggled into core.xml as a bare base64 blob
    key = None
    for blob in re.findall(r">([A-Za-z0-9+/=]{12,})<", core):
        try:
            cand = base64.b64decode(blob, validate=True)
        except Exception:
            continue
        if cand.startswith(b"key="):
            key = cand.split(b"=", 1)[1]
            print("[+] key from core.xml : %r  (base64 %s)" % (key, blob))
            break
    if not key:
        raise SystemExit("no key found in core.xml")

    # 2. the "AIGC" watermark custom property holds the ciphertext
    m = re.search(r'name="AIGC"[^>]*>([A-Za-z0-9+/=]+)<', custom)
    if not m:
        m = re.search(r'name="AIGC"[^>]*>([^<]+)<', custom)
    ct = base64.b64decode(m.group(1))
    print("[+] AIGC property     : %d bytes ciphertext" % len(ct))

    # 3. repeating-key XOR, then base64
    xored = bytes(c ^ key[i % len(key)] for i, c in enumerate(ct))
    print("[+] after XOR        : %s" % xored.decode("latin-1"))
    flag = base64.b64decode(xored).decode()
    print("[+] FLAG: %s" % flag)
    return flag


if __name__ == "__main__":
    main()
