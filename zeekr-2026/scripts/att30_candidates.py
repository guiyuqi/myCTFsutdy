#!/usr/bin/env python3
"""attachments30.zip (MOSAIC CARRIER) — 候选 flag 生成器

背景: 卡片给出的掩码公式 `SHA256(FAMILY || page_id || order)[0:32]` 没有写
page_id / order 的编码方式; 平台提示也只重复了这条公式。于是"真正的" secret
无法从附件唯一确定 —— 只能按可能性枚举。本脚本输出分层的候选表:

  work/att30/candidates.tsv   tier  mask公式                     secret  flag(hex)  flag(sha256(secret))  flag(sha256(hex(secret)))

tier 1 = 最符合同批出题器风格(FORGE 里小序号用 uint16be)的读法
tier 2 = 其余整数宽度/大小写/补零组合
tier 3 = 生成器"忘记解掩码"的 bug 变体(直接异或原始 share)
tier 4 = 附件文件级 sha256
"""
import binascii
import hashlib
import struct

CARRIER = "work/att30/attachments/carrier.bin"
OUT = "work/att30/candidates.tsv"
FAMILY = b"MOSAIC-CARRIER-7"
TABLE = [(0x21, 1), (0x24, 2), (0x27, 3), (0x2B, 4), (0x2E, 5)]

D = open(CARRIER, "rb").read()
PAGES = {}
for i in range(16):
    PAGES[D[i * 0x200 + 0x1E0]] = D[i * 0x200:(i + 1) * 0x200]
SLOT = {pid: i for i, pid in enumerate(sorted(PAGES))}


def pid_bytes(pid, mode):
    return {
        "1B": bytes([pid]), "u16be": struct.pack(">H", pid), "u32be": struct.pack(">I", pid),
        "hexU": b"%02X" % pid, "hexl": b"%02x" % pid, "dec": b"%d" % pid,
        "slot1": bytes([SLOT[pid] + 1]),
    }[mode]


def ord_bytes(o, mode):
    return {
        "1B": bytes([o]), "u16be": struct.pack(">H", o), "u32be": struct.pack(">I", o),
        "dec": b"%d" % o, "dec2": b"%02d" % o, "hexU": b"%X" % o, "zero": bytes([o - 1]),
    }[mode]


def secret(pm, om, sep=b"", pid_pages=None, raw=False):
    acc = bytearray(32)
    for pid, o in (pid_pages or TABLE):
        if raw:
            m = bytes(32)
        else:
            m = hashlib.sha256(FAMILY + sep + pid_bytes(pid, pm) + sep + ord_bytes(o, om)).digest()[:32]
        for j in range(32):
            acc[j] ^= PAGES[pid][j] ^ m[j]
    return bytes(acc)


TIERS = [
    (1, "pid=u16be, order=u16be", dict(pm="u16be", om="u16be")),
    (1, "pid=1B,    order=u16be", dict(pm="1B", om="u16be")),
    (1, "pid=u16be, order=1B", dict(pm="u16be", om="1B")),
    (1, "pid=1B,    order=1B", dict(pm="1B", om="1B")),
    (1, "pid=hexU,  order=dec", dict(pm="hexU", om="dec")),
    (2, "pid=1B,    order=u32be", dict(pm="1B", om="u32be")),
    (2, "pid=u16be, order=u32be", dict(pm="u16be", om="u32be")),
    (2, "pid=u32be, order=u32be", dict(pm="u32be", om="u32be")),
    (2, "pid=hexU,  order=1B", dict(pm="hexU", om="1B")),
    (2, "pid=hexl,  order=1B", dict(pm="hexl", om="1B")),
    (2, "pid=hexl,  order=dec", dict(pm="hexl", om="dec")),
    (2, "pid=hexU,  order=dec2", dict(pm="hexU", om="dec2")),
    (2, "pid=1B,    order=dec", dict(pm="1B", om="dec")),
    (2, "pid=1B,    order=dec2", dict(pm="1B", om="dec2")),
    (2, "pid=1B,    order=zero(0基)", dict(pm="1B", om="zero")),
    (2, "pid=slot1, order=1B", dict(pm="slot1", om="1B")),
    (2, "pid=dec,   order=dec", dict(pm="dec", om="dec")),
    (2, "sep='||' pid=hexU order=dec", dict(pm="hexU", om="dec", sep=b"||")),
    (2, "sep='|'  pid=hexU order=dec", dict(pm="hexU", om="dec", sep=b"|")),
]

rows = []
for tier, desc, kw in TIERS:
    s = secret(**kw)
    rows.append((tier, desc, s.hex(), hashlib.sha256(s).hexdigest(),
                 hashlib.sha256(s.hex().encode()).hexdigest()))

# tier 3: generator bug — no unmasking at all
for label, setp in (("原始 share XOR（表内 5 页）", TABLE),
                    ("原始 share XOR（表内 5 页 + 2A）", TABLE + [(0x2A, 6)]),
                    ("原始 share XOR（全部 status==5A 页）", [(p, 0) for p in sorted(PAGES) if PAGES[p][0x1E2] == 0x5A]),
                    ("原始 share XOR（全部 16 页）", [(p, 0) for p in sorted(PAGES)])):
    s = secret(None, None, pid_pages=setp, raw=True)
    rows.append((3, label, s.hex(), hashlib.sha256(s).hexdigest(),
                 hashlib.sha256(s.hex().encode()).hexdigest()))

# tier 4: artifact-level digests
ART = {
    "sha256(carrier.bin)": hashlib.sha256(D).digest(),
    "sha256(carrier_map.png)": hashlib.sha256(open("work/att30/attachments/carrier_map.png", "rb").read()).digest(),
    "sha256(attachments30.zip)": hashlib.sha256(open("work/att30/attachments30.zip", "rb").read()).digest(),
    "sha256(5 个真实页拼接)": hashlib.sha256(b"".join(PAGES[p] for p, _ in TABLE)).digest(),
}
for k, v in ART.items():
    rows.append((4, k, "-", v.hex(), v.hex()))

rows.sort(key=lambda r: (r[0], r[1]))
with open(OUT, "w") as f:
    f.write("tier\tmask/来源\tsecret\tflag=secret.hex()\tflag=sha256(secret.hex())\tflag=sha256(secret)\n")
    for t, desc, s, sh, shh in rows:
        f.write(f"{t}\t{desc}\t{s}\t{'GEELY{%s}' % s if s != '-' else '-'}\t"
                f"GEELY{{{shh}}}\tGEELY{{{sh}}}\n")

print(f"wrote {OUT}: {len(rows)} rows")
print("\n== tier1/2 候选（flag=secret.hex() 形式） ==")
for t, desc, s, sh, shh in rows:
    if t <= 2:
        print(f"  T{t} {desc:34s} GEELY{{{s}}}")
print("\n== tier3/4 候选 ==")
for t, desc, s, sh, shh in rows:
    if t >= 3:
        print(f"  T{t} {desc:34s} GEELY{{{sh if s=='-' else s}}}")
