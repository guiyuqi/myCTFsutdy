#!/usr/bin/env python3
"""
37 · 欸？云朵  (Reverse, PE32+ x64 GUI, MinGW)  —— solve script

题目关键句「咦？是不是有什么东西闪过去了？」= 窗口类名 `CloudFlashWindow`：
WinMain 注册窗口后立刻 SendMessage(WM_PAINT)，窗口过程在 WM_PAINT 里
把藏在 .rdata 的密文 RC4 解密 → DrawTextA 画到屏幕 → **DestroyWindow**。
所以字只"闪"一帧就没了。

静态定位（VA）:
  0x405000 "CloudFlashWindow"  窗口类名
  0x405018 "0xGame2026"       窗口标题
  0x405028 "Your flag is "    前缀
  0x405038 "ShedaLight"       RC4 key（明文躺在 .rdata 里！）
  0x405050 26 字节密文        0x40191a..0x40194b 处被 load 进栈缓冲

函数:
  0x401550  RC4 KSA   (sbox, key, keylen)
  0x401620  RC4 PRGA/解密 (in-place: buf ^= keystream, buf_len, key, keylen)
  0x401871  窗口过程 WndProc；WM_PAINT(0xF) 分支调用 0x401620
  0x401aa2  WinMain；0x401d40 点完就 DestroyWindow

用法:
  python3 scripts/37-solve.py [attachment.exe]
  python3 scripts/37-solve.py --emulate [attachment.exe]   # 用 unicorn 跑真机码验证
"""
import sys
import os
import struct

# ---- 从 PE 里抠出来的常量（附校验，防止附件被换） ----
RDATA_VA = 0x405000
RDATA_OFF = 0x2C00          # .rdata raw offset
KEY = b"ShedaLight"
KEY_VA = 0x405038
CT_VA = 0x405050
CT_LEN = 26
# 0x40191a..0x40194b 处从 0x405050 起搬 8+8+8+2 = 26 字节
CT = bytes([
    0xD7, 0x8C, 0x35, 0xAC, 0xA1, 0xFF, 0xA3, 0x57,
    0x0C, 0x79, 0xE7, 0x13, 0xE7, 0xBC, 0xFF, 0x8B,
    0x99, 0x54, 0x5C, 0x68, 0x73, 0x70, 0xDD, 0x44,
    0x77, 0xF0,
])

KSA_VA = 0x401550
DEC_VA = 0x401620
TEXT_OFF = 0x400            # .text raw offset


def rc4(key: bytes, data: bytes) -> bytes:
    """标准 RC4 —— 与 0x401550 / 0x401620 语义一致。"""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def carve(path):
    """从附件里动态抠出 key/密文，并与硬编码常量交叉校验。"""
    pe = open(path, "rb").read()
    blob = pe[RDATA_OFF:RDATA_OFF + 0x600]
    key = blob[KEY_VA - RDATA_VA: KEY_VA - RDATA_VA + 10]
    ct = blob[CT_VA - RDATA_VA: CT_VA - RDATA_VA + CT_LEN]
    return pe, key, ct


def emulate(path, key, ct):
    """用 unicorn 直接执行 0x401550 / 0x401620 的真机码，作为独立验证。"""
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
    from unicorn.x86_const import (
        UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RCX,
        UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9,
    )
    pe = open(path, "rb").read()
    base = 0x1000000
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(base, 0x100000)
    mu.mem_write(base + 0x1000, pe[TEXT_OFF:TEXT_OFF + 0x2600])

    key_a, ct_a = base + 0x80000, base + 0x90000
    mu.mem_write(key_a, key)
    mu.mem_write(ct_a, ct)
    sbox = base + 0xA0000
    stack = base + 0x7000
    retmagic = base + 0x1FF0
    mu.mem_write(retmagic, b"\xf4")  # hlt

    def call(addr, args):
        mu.reg_write(UC_X86_REG_RSP, stack)
        mu.reg_write(UC_X86_REG_RBP, stack)
        for reg, val in args:
            mu.reg_write(reg, val)
        sp = mu.reg_read(UC_X86_REG_RSP) - 8
        mu.mem_write(sp, struct.pack("<Q", retmagic))
        mu.reg_write(UC_X86_REG_RSP, sp)
        # .text 落在 base+0x1000，而 .text 的 VMA 是 0x401000
        mu.emu_start(base + (addr - 0x401000) + 0x1000, retmagic)

    call(KSA_VA, [(UC_X86_REG_RCX, sbox), (UC_X86_REG_RDX, key_a),
                  (UC_X86_REG_R8, len(key))])
    call(DEC_VA, [(UC_X86_REG_RCX, ct_a), (UC_X86_REG_RDX, len(ct)),
                  (UC_X86_REG_R8, key_a), (UC_X86_REG_R9, len(key))])
    return bytes(mu.mem_read(ct_a, len(ct)))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    want_emu = "--emulate" in sys.argv
    path = args[0] if args else os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "work", "37_cloud", "att2", "attachment.exe")

    pe, key, ct = carve(path)
    assert key == KEY, f"key 不符: {key!r}"
    assert ct == CT, f"密文不符: {ct.hex()}"
    print(f"[*] key      = {key!r}")
    print(f"[*] ciphertext({len(ct)}) = {ct.hex()}")

    pt = rc4(key, ct)
    print(f"[+] RC4 解密 = {pt.decode()}")

    if want_emu:
        emu = emulate(path, key, ct)
        print(f"[+] unicorn 跑真机码 = {emu.decode()}")
        assert emu == pt, "模拟结果与 RC4 实现不一致！"
        print("[+] 两种方法一致 ✔")

    return pt.decode()


if __name__ == "__main__":
    main()
