题目名称：ATRIUM（atrium_boot.bin，正式名可自行替换）
题目类型：固件逆向 / 自定义 VM 微码 / 数据校验与解密

FLAG：GEELY{ATRIUM_007C1B66052D3321_86B3F3C6DBDD9B5C}

解题思路：

1. 附件结构
   attachments.zip 内含 8KB 镜像 atrium_boot.bin（0x2000）+ 3 份说明：
   - atrium_protocol.txt：lane 布局、校验规则、拼装与解密流程
   - opcode_plate.txt：VM 指令集（2 字节指令，16 个 32 位寄存器）
   - hardware_stamp.txt：关键偏移

   镜像布局：
   - 0x1000  lane table，16 个 lane，stride 0x100
   - 0x1C00  manifest，长 0x60，用重复 KEY 做 XOR

2. lane 过滤（本题核心陷阱）
   每个 lane record：+000 masked chunk(0x20)、+020 lane_id(u16be)、+022 status、
   +023 reserved、+024 seed(u32be)、+028 crc32(u32be)、+02C "ATRM"。

   LANE_MASK = SHA256("ATRIUM-MICROCODE-8" || u16be(lane_id) || u32be(seed) || "ATRIUM-LANE")
   unmasked  = masked XOR LANE_MASK
   valid ⟺ status==0x6D && reserved==0xC3 && marker=="ATRM" && crc32==CRC32(unmasked)

   16 个 lane 中只有 6 个通过（与 protocol 的 VALID LANES 6 一致）：
   - lane#0–#5：全部通过 → 真
   - lane#6/#7：marker 和 crc 都对，但 status/reserved 错 → 伪造，专门骗只看 crc 的人
   - lane#8–#15：marker 都不是 ATRM，crc 也算不上 → 废数据
   注意：CRC32 必须对「mask 之后的 chunk」计算，这是区分真伪的唯一硬判据。

3. 拼装程序
   6 个有效 lane 按 CRC32(unmasked) 升序排列，chunk 依次拼接 →
   6 × 0x20 = 0xC0 字节，正好等于 opcode_plate 声明的程序长度，自校验成立。

4. 跑 VM 取 KEY
   R0..R5 初值 = 有效 lane 的 lane_id（0xBE1F, 0x3C4D, 0x7A8B, 0x5E6F, 0x9C0D, 0x1A2B），
   R6..R15 = 0。指令编码 byte0=[opcode(4)|dst(4)]、byte1=[src(4)|imm(4)]。
   执行 192 字节后 OUT 恰好吐出 32 字节，即 KEY：
   007c1b66052d332186b3f3c6dbdd9b5c5ceb50b4eadce3efd1faa763eceb87eb

5. 解 manifest
   0x1C00 起 0x60 字节与 KEY 循环 XOR，剥掉 0xA5 padding：
   ATRIUM|GEELY{ATRIUM_007C1B66052D3321_86B3F3C6DBDD9B5C}|<0xA5…>
   得 flag。

一句话链路：
lane 表按四项校验筛出 6 条真 lane → 按 crc 升序拼成 0xC0 字节 VM 程序 →
跑 VM 输出 32 字节 KEY → KEY 循环 XOR 解 0x1C00 的 manifest → flag。

编写脚本：（scripts/atrium_solve.py，python3 scripts/atrium_solve.py 即可复现）

```python
#!/usr/bin/env python3
"""ATRIUM-MICROCODE-8 boot image solver."""
import hashlib, struct, zlib

IMG         = "work/attachments/firmware/atrium_boot.bin"
FAMILY      = b"ATRIUM-MICROCODE-8"
TAG         = b"ATRIUM-LANE"
LANE_TABLE  = 0x1000
LANE_STRIDE = 0x100
LANE_CHUNK  = 0x20
MANIFEST_OFF, MANIFEST_LEN = 0x1C00, 0x60

u16 = lambda b, o: struct.unpack_from(">H", b, o)[0]
u32 = lambda b, o: struct.unpack_from(">I", b, o)[0]


def lane_mask(lane_id, seed):
    return hashlib.sha256(FAMILY + struct.pack(">H", lane_id)
                          + struct.pack(">I", seed) + TAG).digest()


def parse_lanes(img):
    lanes = []
    for i in range(16):
        base = LANE_TABLE + i * LANE_STRIDE
        lane_id, status = u16(img, base + 0x20), img[base + 0x22]
        reserved, seed = img[base + 0x23], u32(img, base + 0x24)
        crc, marker = u32(img, base + 0x28), img[base + 0x2C:base + 0x30]

        unmasked = bytes(a ^ b for a, b in
                         zip(img[base:base + LANE_CHUNK], lane_mask(lane_id, seed)))
        ok = (status == 0x6D and reserved == 0xC3 and marker == b"ATRM"
              and crc == (zlib.crc32(unmasked) & 0xFFFFFFFF))
        lanes.append(dict(lane_id=lane_id, crc=crc, chunk=unmasked, ok=ok))
    return lanes


def run_vm(prog, regs):
    regs = list(regs) + [0] * (16 - len(regs))
    out, pc = [], 0
    while pc + 1 < len(prog):
        b0, b1 = prog[pc], prog[pc + 1]
        op, dst, src, imm = b0 >> 4, b0 & 0xF, b1 >> 4, b1 & 0xF
        pc += 2
        if   op == 0x0: pass
        elif op == 0x1: regs[dst] = regs[src]
        elif op == 0x2: regs[dst] ^= regs[src]
        elif op == 0x3: regs[dst] = (regs[dst] + regs[src]) & 0xFFFFFFFF
        elif op == 0x4: regs[dst] = (regs[dst] * regs[src]) & 0xFFFFFFFF
        elif op == 0x5:
            n, v = imm % 32, regs[dst] & 0xFFFFFFFF
            regs[dst] = ((v << n) | (v >> ((32 - n) % 32))) & 0xFFFFFFFF
        elif op == 0x6: regs[dst] = (regs[dst] << imm) & 0xFFFFFFFF
        elif op == 0x7: regs[dst] >>= imm
        elif op == 0x8: regs[dst] = (regs[dst] ^ imm) & 0xFFFFFFFF
        elif op == 0x9: regs[dst] = (regs[dst] + imm) & 0xFFFFFFFF
        elif op == 0xA: out.append(regs[dst] & 0xFF)
        elif op == 0xF: break
    return bytes(out)


img = open(IMG, "rb").read()

valid = sorted((L for L in parse_lanes(img) if L["ok"]), key=lambda L: L["crc"])
print("[*] valid lanes:", [hex(L["lane_id"]) for L in valid])

prog = b"".join(L["chunk"] for L in valid)
print(f"[*] program {len(prog)} bytes (expect 0xC0)")

key = run_vm(prog, [L["lane_id"] for L in valid])[:32]
print("[*] KEY:", key.hex())

plain = bytes(c ^ key[i % 32]
              for i, c in enumerate(img[MANIFEST_OFF:MANIFEST_OFF + MANIFEST_LEN]))
print("[*] manifest:", plain.rstrip(b"\xA5").decode())
```
