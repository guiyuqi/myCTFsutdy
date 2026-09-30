#!/usr/bin/env python3
"""attachments30.zip (MOSAIC CARRIER) — 全量候选表（供批量提交）

平台提示已确认链路 = 取表内 5 页(21/24/27/2B/2E) → 用 mask_for(page_id, order)
解掩码 → 5 份份额逐字节异或 → 32 字节 manifest secret → 平台要 sha256_hex。
唯一未定的是 mask_for 的字节编码（卡片与提示都没写）。

本脚本枚举: FAMILY 变体 × 可选 tag × pid 编码 × order 编码 × 分隔符，
每种给出 3 种 flag 写法（secret.hex() / sha256(secret) / sha256(hex(secret))），
按"可能性"排 tier，输出 work/att30/candidates_full.tsv。
"""
import hashlib
import struct

D = open("work/att30/attachments/carrier.bin", "rb").read()
P = {}
for i in range(16):
    page = D[i * 0x200:(i + 1) * 0x200]
    P[page[0x1E0]] = page
SLOT = {pid: i for i, pid in enumerate(sorted(P))}
TABLE = [(0x21, 1), (0x24, 2), (0x27, 3), (0x2B, 4), (0x2E, 5)]

FAMILIES = [b"MOSAIC-CARRIER-7", b"GEELY-MOSAIC-CARRIER-7", b"MOSAIC CARRIER MAP",
            b"MOSAIC CARRIER MAP / REVISION 7", b"MOSAIC-CARRIER", b"MOSAIC-CARRIER-07"]
TAGS = [b"", b"MOSAIC", b"PAGE", b"SHARE", b"MOSAIC-PAGE", b"MOSAIC-SHARE", b"MANIFEST"]
PIDM = ["1B", "u16be", "u32be", "hexU", "hexl", "dec", "slot0", "slot1"]
ORDM = ["1B", "u16be", "u32be", "dec", "dec2", "zero"]
SEPS = [b"", b"|", b"||", b":", b"-", b"\x00"]


def pid_b(pid, m):
    return {"1B": bytes([pid]), "u16be": struct.pack(">H", pid), "u32be": struct.pack(">I", pid),
            "hexU": b"%02X" % pid, "hexl": b"%02x" % pid, "dec": b"%d" % pid,
            "slot0": bytes([SLOT[pid]]), "slot1": bytes([SLOT[pid] + 1])}[m]


def ord_b(o, m):
    return {"1B": bytes([o]), "u16be": struct.pack(">H", o), "u32be": struct.pack(">I", o),
            "dec": b"%d" % o, "dec2": b"%02d" % o, "zero": bytes([o - 1])}[m]


MASKMODES = {
    "digest[:32]": lambda h: h.digest()[:32],
    "hexdigest[:32].encode()": lambda h: h.hexdigest()[:32].encode(),
    "hexdigest[:32].upper().encode()": lambda h: h.hexdigest()[:32].upper().encode(),
    "hexdigest[-32:].encode()": lambda h: h.hexdigest()[-32:].encode(),
    "digest[:16]*2": lambda h: h.digest()[:16] * 2,
}

rows = []
for fam in FAMILIES:
    for tag in TAGS:
        for pm in PIDM:
            for om in ORDM:
                for sep in SEPS:
                    for mm, mf in MASKMODES.items():
                        acc = bytearray(32)
                        for pid, o in TABLE:
                            msg = fam + sep + pid_b(pid, pm) + sep + ord_b(o, om) + (sep + tag if tag else b"")
                            m = mf(hashlib.sha256(msg))
                            for j in range(32):
                                acc[j] ^= P[pid][j] ^ m[j]
                        rows.append((fam, tag, pm, om, sep, mm, bytes(acc)))

seen = set()
out = []
for fam, tag, pm, om, sep, mm, s in rows:
    if s in seen:
        continue
    seen.add(s)
    tier = 1 if (fam == b"MOSAIC-CARRIER-7" and not tag and sep == b"" and mm == "digest[:32]") else (2 if not tag else 3)
    out.append((tier, fam, tag, pm, om, sep, mm, s))
out.sort(key=lambda r: (r[0], r[1], r[2], r[3], r[4], r[5]))

with open("work/att30/candidates_full.tsv", "w") as f:
    f.write("tier\tFAMILY\ttag\tpid_enc\torder_enc\tsep\tmask_mode\tsecret\tflag_hex\tflag_sha256_secret\tflag_sha256_hexstr\n")
    for tier, fam, tag, pm, om, sep, mm, s in out:
        f.write(f"{tier}\t{fam.decode()}\t{tag.decode()}\t{pm}\t{om}\t{sep!r}\t{mm}\t{s.hex()}\t"
                f"GEELY{{{s.hex()}}}\tGEELY{{{hashlib.sha256(s).hexdigest()}}}\t"
                f"GEELY{{{hashlib.sha256(s.hex().encode()).hexdigest()}}}\n")

print(f"distinct candidates: {len(out)} -> work/att30/candidates_full.tsv")
for tier, fam, tag, pm, om, sep, mm, s in out[:14]:
    print(f"  T{tier} {fam.decode():22s} pid={pm:6s} order={om:6s} sep={sep!r:6s} mask={mm:30s} GEELY{{{s.hex()}}}")
