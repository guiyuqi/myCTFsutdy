#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
40 · Guess  (0xGame2026, Reverse, 812 pts)

题目给的是 PyInstaller onefile 打包的 Windows x64 控制台程序 (attachment.exe)。
README 明说「真正的 flag 没有直接输出」——猜数字只是幌子，
猜中后程序只打印一个假 flag `0xGame{I'm just kidding :D}`，
真正的 flag 藏在 `tea_decrypt(FLAG_CIPHERTEXT, TEA_KEY)` 的结果里。

解法（两步，全程静态）:
  1) 从 PyInstaller CArchive 里抽出 `game` 脚本 (type 's' = marshalled code object,
     zlib 压缩)。本机 Python 3.14 直接 marshal.loads + dis 即可拿到全部逻辑。
  2) 伪代码是标准 XTEA 解密 (DELTA=0x9E3779B9, 32 轮, MASK=0xFFFFFFFF),
     密钥 b'guess_secret_key', 密文硬编码在 FLAG_CIPHERTEXT。
     用 Python 复刻一遍解密 + PKCS#7 去填充就得到真 flag。

成品脚本：本文件。用法:
    python3 scripts/40-solve.py
    python3 scripts/40-solve.py firmware/40_Guess/attachment5.zip   # 从附件从头跑
"""

import io
import os
import struct
import sys
import zipfile
import zlib

# ---------------------------------------------------------------- PyInstaller

COOKIE_MAGIC = b"MEI\014\013\012\013\016"


def extract_pyinstaller_payload(exe_bytes: bytes) -> dict:
    """手工解析 PyInstaller CArchive, 返回 {name: raw_bytes} (只解出 s/m/z 类条目)。

    不改附件、不依赖 pyinstxtractor; CArchive 结构:
        [overlay data][cookie(88B)][TOC][\n][PKG data]
        cookie = magic(8) | pkglen(4) | toc(4) | toclen(4) | pyvers(4) | pylibname(64)
        TOC entry = elen(4) | epos(4) | cmprs_size(4) | uncmprs_size(4) |
                    cmprs_flag(1) | typecode(1) | name(elen-18)
        所有整数 big-endian。
    """
    i = exe_bytes.rfind(COOKIE_MAGIC)
    if i < 0:
        raise RuntimeError("PyInstaller cookie 未找到")
    p = i + 8
    pkglen, toc_off, toc_len, pyvers = struct.unpack(">IIII", exe_bytes[p:p + 16])
    arch_start = i + 88 - pkglen

    out = {}
    q = arch_start + toc_off
    end = q + toc_len
    while q < end:
        elen, epos, cmprs_size, _uncmprs, cflag, typecode = struct.unpack(
            "!IIIIBc", exe_bytes[q:q + 18]
        )
        name = exe_bytes[q + 18:q + elen].rstrip(b"\0").decode("utf-8", "replace")
        raw = exe_bytes[arch_start + epos: arch_start + epos + cmprs_size]
        if cflag:
            raw = zlib.decompress(raw)
        out[name] = (typecode, raw)
        q += elen
    return out


def load_game_codeobj(payload: dict):
    """取 `game` 条目: 它没有 pyc 头, 是裸的 marshal 流 (首字节 0x63 == TYPE_CODE)。"""
    import marshal

    typecode, raw = payload["game"]
    assert typecode == b"s", f"game 条目类型异常: {typecode!r}"
    return marshal.loads(raw)


# ---------------------------------------------------------------------- XTEA

DELTA = 2654435769          # 0x9E3779B9
MASK = 0xFFFFFFFF


def tea_decrypt(data: bytes, key: bytes) -> bytes:
    """从 game 模块反汇编还原的标准 XTEA 解密 (含 PKCS#7 去填充)。"""
    words = struct.unpack("<4I", key)
    result = bytearray()
    for offset in range(0, len(data), 8):
        left, right = struct.unpack("<2I", data[offset:offset + 8])
        total = (DELTA * 32) & MASK
        for _ in range(32):
            right = (right - ((((left << 4) + words[2]) ^ (left + total)
                               ^ ((left >> 5) + words[3])))) & MASK
            total = (total - DELTA) & MASK
            left = (left - ((((right << 4) + words[0]) ^ (right + total)
                             ^ ((right >> 5) + words[1])))) & MASK
        result.extend(struct.pack("<2I", left, right))
    padding = result[-1]
    if not (1 <= padding <= 8 and bytes(result[-padding:]) == bytes([padding]) * padding):
        raise ValueError("bad padding")
    return bytes(result[:-padding])


# ----------------------------------------------------------------------- main

def solve(exe_bytes: bytes) -> str:
    payload = extract_pyinstaller_payload(exe_bytes)
    code = load_game_codeobj(payload)

    # 从模块命名空间常量里取 FLAG_CIPHERTEXT / TEA_KEY（而不是硬编码在脚本里,
    # 这样换附件也能跑）。co_consts 顺序来自反汇编:
    #   [0, None, DELTA, MASK, TEA_KEY, FLAG_CIPHERTEXT_HEX, '__main__']
    consts = code.co_consts
    tea_key = next(c for c in consts if isinstance(c, bytes) and c == b"guess_secret_key")
    hexes = [c for c in consts if isinstance(c, str) and len(c) > 32
             and all(ch in "0123456789abcdef" for ch in c)]
    assert len(hexes) == 1, f"密文常量定位失败: {hexes}"
    ciphertext = bytes.fromhex(hexes[0])

    secret = tea_decrypt(ciphertext, tea_key)

    # 复刻程序自带的完整性检查: secret.startswith(b'0xGame{')
    assert secret.startswith(b"0xGame{"), f"integrity check failed: {secret!r}"
    return secret.decode("utf-8")


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)

    if len(sys.argv) > 1:
        src = sys.argv[1]
    else:
        src = os.path.join(root, "firmware", "40_Guess", "attachment5.zip")

    if src.endswith(".zip"):
        with zipfile.ZipFile(src) as zf:
            member = next(n for n in zf.namelist() if n.lower().endswith(".exe"))
            exe_bytes = zf.read(member)
        print(f"[*] 从 {src} 读取 {member} ({len(exe_bytes)} bytes)")
    else:
        with open(src, "rb") as f:
            exe_bytes = f.read()

    flag = solve(exe_bytes)
    print(f"[+] flag: {flag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
