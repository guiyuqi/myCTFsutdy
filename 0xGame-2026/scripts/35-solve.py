#!/usr/bin/env python3
"""35 · signin — 0xGame2026 Reverse (494 pts, offline)

The PE64 (MinGW-w64, x86-64) asks for a flag, requires strlen == 0x34 (52),
then `check_input` compares each byte of the input XOR 0x5A against the
52-byte table `reference_data` at VA 0x4040a0:

    401565: movzx eax, BYTE PTR [rax]      ; input[i]
    401574: xor   eax, 0x5a
    40157e: lea   rdx, [rip+0x2b1b]        ; 0x4040a0 <reference_data>
    401585: movzx eax, BYTE PTR [rax+rdx]  ; reference_data[i]
    401589: cmp   cl, al

So flag = bytes(reference_data) XOR 0x5a.

Note: the plaintext flag ALSO appears verbatim in .rdata at 0x404060 and is
what a naive `strings | grep -i flag` surfaces — here it happens to be the
genuine flag, not a decoy, but the XOR table is the authoritative source.

Usage:
    python3 scripts/35-solve.py [path/to/signin.exe]

Reproducible / self-contained: only the standard library.
"""
import sys
from pathlib import Path

DEFAULT_BIN = Path(__file__).resolve().parent.parent / "firmware" / "35_signin" / "signin.exe"
# fall back to the extracted copy if the original attachment is not present
FALLBACK_BIN = Path(__file__).resolve().parent.parent / "work" / "35_signin" / "signin.exe"

# PE section table: name -> (file_offset, virtual_address, virtual_size)
SECTIONS = [
    (".text", 0x400, 0x401000, 0x1DA8),
    (".data", 0x2200, 0x403000, 0xD0),
    (".rdata", 0x2400, 0x404000, 0x570),
]

REFERENCE_DATA_VA = 0x4040A0
REFERENCE_DATA_LEN = 0x34        # cmp DWORD PTR [rbp-0x4], 0x33 ; jle  -> 0..0x33
XOR_KEY = 0x5A
EXPECTED_LEN = 0x34              # strlen(input) == 0x34


def va_to_offset(va: int) -> int:
    for _name, off, base, size in SECTIONS:
        if base <= va < base + size:
            return off + (va - base)
    raise ValueError(f"VA 0x{va:x} not mapped in section table")


def read_reference_data(blob: bytes) -> bytes:
    off = va_to_offset(REFERENCE_DATA_VA)
    return blob[off:off + REFERENCE_DATA_LEN]


def main() -> int:
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_BIN
    if not src.exists():
        src = FALLBACK_BIN
    blob = src.read_bytes()

    ref = read_reference_data(blob)
    flag = bytes(b ^ XOR_KEY for b in ref).decode("ascii")

    print(f"[*] binary          : {src}")
    print(f"[*] reference_data  : {ref.hex()}  ({len(ref)} bytes)")
    print(f"[*] xor key         : 0x{XOR_KEY:02x}")
    print(f"[+] recovered flag  : {flag}")
    print(f"[+] length          : {len(flag)} (expected {EXPECTED_LEN})")

    assert len(flag) == EXPECTED_LEN, "length mismatch: wrong slice or binary"
    # sanity: re-encrypt and compare against the on-disk table
    assert bytes(ord(c) ^ XOR_KEY for c in flag) == ref, "round-trip failed"

    # Cross-check against the plaintext copy embedded at 0x404060 (informational).
    off = va_to_offset(0x404060)
    embedded = blob[off:off + EXPECTED_LEN].decode("ascii")
    print(f"[*] embedded @404060: {embedded}")
    print(f"[*] matches         : {embedded == flag}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
