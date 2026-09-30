#!/usr/bin/env python3
"""ATRIUM-MICROCODE-8 boot image solver.

Pipeline (per attachments/protocol/*.txt):
  1. Parse the 0x1000 lane table: 16 lanes x 0x100 stride.
  2. Validate each lane (status==0x6D, reserved==0xC3, marker=="ATRM",
     crc32 == CRC32(unmasked chunk)).
  3. unmasked = masked XOR SHA256(FAMILY || u16be(lane_id) || u32be(seed) || "ATRIUM-LANE")
  4. Order valid lanes by ascending CRC32(unmasked) and concat -> 0xC0 VM program.
  5. R0..R5 = lane_ids in that order, R6..R15 = 0. Run VM.
  6. First 32 OUT bytes = KEY; manifest @0x1C00 len 0x60 XOR repeating KEY; strip 0xA5.
"""
import hashlib
import struct
import sys
import zlib

IMG = "work/attachments/firmware/atrium_boot.bin"
FAMILY = b"ATRIUM-MICROCODE-8"
TAG = b"ATRIUM-LANE"

LANE_TABLE = 0x1000
LANE_STRIDE = 0x100
LANE_CHUNK = 0x20
MANIFEST_OFF = 0x1C00
MANIFEST_LEN = 0x60


def u16be(b, o):
    return struct.unpack_from(">H", b, o)[0]


def u32be(b, o):
    return struct.unpack_from(">I", b, o)[0]


def lane_mask(lane_id, seed):
    h = hashlib.sha256()
    h.update(FAMILY)
    h.update(struct.pack(">H", lane_id))
    h.update(struct.pack(">I", seed))
    h.update(TAG)
    return h.digest()


def parse_lanes(img):
    lanes = []
    for i in range(16):
        base = LANE_TABLE + i * LANE_STRIDE
        masked = img[base:base + LANE_CHUNK]
        lane_id = u16be(img, base + 0x20)
        status = img[base + 0x22]
        reserved = img[base + 0x23]
        seed = u32be(img, base + 0x24)
        crc = u32be(img, base + 0x28)
        marker = img[base + 0x2C:base + 0x30]

        mask = lane_mask(lane_id, seed)
        unmasked = bytes(a ^ b for a, b in zip(masked, mask))
        calc = zlib.crc32(unmasked) & 0xFFFFFFFF

        ok = (status == 0x6D and reserved == 0xC3 and marker == b"ATRM"
              and crc == calc)
        lanes.append(dict(idx=i, base=base, lane_id=lane_id, status=status,
                          reserved=reserved, seed=seed, crc=crc, marker=marker,
                          mask=mask, unmasked=unmasked, calc=calc, ok=ok))
    return lanes


def run_vm(program, regs_init):
    regs = list(regs_init) + [0] * (16 - len(regs_init))
    out = []
    pc = 0
    trace = []
    while pc + 1 < len(program):
        b0, b1 = program[pc], program[pc + 1]
        op = b0 >> 4
        dst = b0 & 0xF
        src = b1 >> 4
        imm = b1 & 0xF
        pc += 2
        if op == 0x0:
            pass
        elif op == 0x1:
            regs[dst] = regs[src]
        elif op == 0x2:
            regs[dst] ^= regs[src]
        elif op == 0x3:
            regs[dst] = (regs[dst] + regs[src]) & 0xFFFFFFFF
        elif op == 0x4:
            regs[dst] = (regs[dst] * regs[src]) & 0xFFFFFFFF
        elif op == 0x5:
            n = imm % 32
            v = regs[dst] & 0xFFFFFFFF
            regs[dst] = ((v << n) | (v >> ((32 - n) % 32))) & 0xFFFFFFFF
        elif op == 0x6:
            regs[dst] = (regs[dst] << imm) & 0xFFFFFFFF
        elif op == 0x7:
            regs[dst] = (regs[dst] >> imm) & 0xFFFFFFFF
        elif op == 0x8:
            regs[dst] = (regs[dst] ^ imm) & 0xFFFFFFFF
        elif op == 0x9:
            regs[dst] = (regs[dst] + imm) & 0xFFFFFFFF
        elif op == 0xA:
            out.append(regs[dst] & 0xFF)
        elif op == 0xF:
            trace.append((pc - 2, "HALT"))
            break
        else:
            trace.append((pc - 2, f"BAD_OP {op:X}"))
            break
    return out, regs, trace, program[:pc]


def main():
    img = open(IMG, "rb").read()
    print(f"[*] image {len(img)} bytes (0x{len(img):X})")
    lanes = parse_lanes(img)

    print("\n[*] lane table:")
    for L in lanes:
        print(f"  lane#{L['idx']:2d} @0x{L['base']:04X} id=0x{L['lane_id']:04X} "
              f"status=0x{L['status']:02X} rsv=0x{L['reserved']:02X} "
              f"seed=0x{L['seed']:08X} crc=0x{L['crc']:08X} "
              f"calc=0x{L['calc']:08X} marker={L['marker']!r} "
              f"{'VALID' if L['ok'] else 'reject'}")

    valid = [L for L in lanes if L["ok"]]
    valid.sort(key=lambda L: L["crc"])
    print(f"\n[*] {len(valid)} valid lanes, ordered by crc32:")
    for L in valid:
        print(f"    id=0x{L['lane_id']:04X} crc=0x{L['crc']:08X} "
              f"chunk={L['unmasked'].hex()}")

    program = b"".join(L["unmasked"] for L in valid)
    print(f"\n[*] VM program: {len(program)} bytes (expect 0xC0)")
    for i in range(0, len(program), 16):
        print(f"    {i:04X}: {program[i:i+16].hex(' ')}")

    regs_init = [L["lane_id"] for L in valid]
    print(f"\n[*] init regs R0..R{len(regs_init)-1} = "
          f"{[hex(r) for r in regs_init]}")
    out, regs, trace, used = run_vm(program, regs_init)
    print(f"[*] executed {len(used)} bytes, OUT produced {len(out)} bytes")
    print(f"[*] final regs: {[hex(r) for r in regs]}")
    print(f"[*] OUT hex: {bytes(out).hex()}")
    print(f"[*] OUT repr: {bytes(out)!r}")

    key = bytes(out[:32])
    print(f"\n[*] KEY (first 32 OUT bytes) = {key.hex()}")

    manifest = img[MANIFEST_OFF:MANIFEST_OFF + MANIFEST_LEN]
    plain = bytes(c ^ key[i % 32] for i, c in enumerate(manifest))
    print(f"[*] manifest cipher : {manifest.hex()}")
    print(f"[*] manifest plain  : {plain.hex()}")
    print(f"[*] manifest repr   : {plain!r}")
    stripped = plain.rstrip(b"\xA5")
    print(f"[*] strip 0xA5      : {stripped!r}")
    try:
        print(f"[*] ascii           : {stripped.decode()}")
    except Exception as e:
        print(f"[!] decode error: {e}")

    import re
    for blob in (stripped, plain):
        for m in re.findall(rb"GEELY\{[^}]*\}|flag\{[^}]*\}|FLAG\{[^}]*\}", blob, re.I):
            print(f"\n[+] FLAG CANDIDATE: {m.decode(errors='replace')}")


if __name__ == "__main__":
    sys.exit(main())
