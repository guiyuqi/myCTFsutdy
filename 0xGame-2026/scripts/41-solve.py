#!/usr/bin/env python3
"""41 - ez_pytorch  (AI / malicious pickle in .pth)

SAFETY: never torch.load() / pickle.load() the sample. The payload is
__builtin__ exec(...) via REDUCE. We instead:
  1. treat the .pth as a zip, read model/data.pkl
  2. statically disassemble it with pickletools (no execution)
  3. extract the embedded source string from the BINUNICODE operand
  4. re-implement the four decoders ourselves from the recovered source
"""
import io
import re
import zipfile
import pickletools
import base64

PTH = "firmware/41_ez_pytorch/attach.zip"


def load_pth_bytes(path: str) -> bytes:
    if path.endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            with z.open("model.pth") as f:
                return f.read()
    with open(path, "rb") as f:
        return f.read()


def main() -> None:
    pth = load_pth_bytes(PTH)
    zf = zipfile.ZipFile(io.BytesIO(pth))

    pkl = zf.read("model/data.pkl")
    print("--- pickletools.dis(model/data.pkl) ---")
    pickletools.dis(pkl)

    # Pull the BINUNICODE payload source without ever unpickling.
    src = None
    for op, arg, pos in pickletools.genops(pkl):
        if op.name == "BINUNICODE":
            src = arg
    assert src, "payload source not found"
    print("\n--- recovered payload source ---")
    print(src)
    open("work/41_pytorch/payload_recovered.py", "w").write(src)

    b0 = zf.read("model/data/0")
    b1 = zf.read("model/data/1").decode()
    b2 = zf.read("model/data/2").decode()
    b3 = zf.read("model/data/3").decode()

    # --- part 0: repeating-key XOR, key (0x5A, 0xA3, 0x3C) ---
    k0 = (0x5A, 0xA3, 0x3C)
    p0 = bytes(b0[i] ^ k0[i % 3] for i in range(len(b0)))

    # --- part 1: reversed base64 ---
    p1 = base64.b64decode(b1[::-1])

    # --- part 2: hex, then subtract index mod 256 ---
    b2h = bytes.fromhex(b2)
    p2 = bytes((b2h[i] - i) & 0xFF for i in range(len(b2h)))

    # --- part 3: base64, then XOR chaining with first byte ^ 0xA5 ---
    b3d = base64.b64decode(b3)
    r3 = []
    for i in range(len(b3d)):
        if i == 0:
            r3.append(b3d[0] ^ 0xA5)
        else:
            r3.append(b3d[i] ^ b3d[i - 1])
    p3 = bytes(r3)

    flag = (p0 + p1 + p2 + p3).decode()
    print("\n--- parts ---")
    for n, p in enumerate((p0, p1, p2, p3)):
        print(f"p{n} = {p!r}")
    print(f"\nFLAG = {flag}")
    assert re.match(r"^(0xGame|flag)\{.*\}$", flag), flag


if __name__ == "__main__":
    main()
