#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
0xGame2026 - 题7 "decode for love" (Crypto, 900, 离线) 复现脚本
=================================================================
flag: 0xGame{ENCODINGGETTT}

附件: firmware/7_decode_for_love/week1 Crypto decode for love.txt
      (中文故事 + 最后一行 64 个 emoji 密文)

实际层序（不是 2009 原帖那套摩斯/T9/栅栏，是改编版）:

  层1  表情替换 : emoji-aes (aghorler/emoji-aes) 的 65 项表, rotation=0
                  emoji -> base64 字符 (a-z A-Z 0-9 + / =)
  层2  AES      : CryptoJS.AES.encrypt(msg, "0x2026") 输出, OpenSSL "Salted__" 格式
                  AES-256-CBC + EVP_BytesToKey(MD5, salt) 派生 key/iv
  层3  Base64   : 解出的明文本身又是 base64      -> LUJVKPUNNLAAA
  层4  凯撒     : 26 个位移中只有 shift=7 出英文  -> ENCODINGGETTT

  密文(emoji) --层1--> b64 --层2--> b64 --层3--> LUJVKPUNNLAAA --层4--> ENCODINGGETTT

依赖: 只用标准库 (hashlib/base64) + cryptography (环境已装)
用法: python3 scripts/7-solve.py [附件路径]
"""
import base64
import hashlib
import os
import sys

# ----------------------------------------------------------------------------
# emoji-aes 表 (aghorler/emoji-aes, js/emoji-aes.js 里的 emojisInit)
# 索引 0..25 -> a-z, 26..51 -> A-Z, 52..61 -> 0-9, 62 -> '+', 63 -> '/', 64 -> '='
# ----------------------------------------------------------------------------
EMOJI_TABLE = [
    "🍎", "🍌", "🏎", "🚪", "👁", "👣", "😀", "🖐", "ℹ", "😂", "🥋", "✉", "🚹",
    "🌉", "👌", "🍍", "👑", "👉", "🎤", "🚰", "☂", "🐍", "💧", "✖", "☀", "🦓",
    "🏹", "🎈", "😎", "🎅", "🐘", "🌿", "🌏", "🌪", "☃", "🍵", "🍴", "🚨", "📮",
    "🕹", "📂", "🛩", "⌨", "🔄", "🔬", "🐅", "🙃", "🐎", "🌊", "🚫", "❓", "⏩",
    "😁", "😆", "💵", "🤣", "☺", "😊", "😇", "😡", "🎃", "😍", "✅", "🔪", "🗒",
]
B64_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
assert len(EMOJI_TABLE) == len(B64_ALPHABET) == 65

DEFAULT_TXT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "firmware", "7_decode_for_love", "week1 Crypto decode for love.txt",
)


def extract_emoji(path):
    """取附件中最后一行非空内容，即 emoji 密文。"""
    text = open(path, encoding="utf-8").read().replace("\r", "")
    lines = [l for l in text.split("\n") if l.strip()]
    return list(lines[-1].strip())


def emoji_to_base64(emoji, rotation=0):
    """层1: emoji -> base64 字符。rotation 对应 emoji-aes 工具的 rotation 参数。"""
    idx = {c: i for i, c in enumerate(EMOJI_TABLE)}
    return "".join(B64_ALPHABET[(idx[c] - rotation) % 65] for c in emoji)


def evp_bytes_to_key(passphrase, salt, klen=48):
    """OpenSSL/CryptoJS EVP_BytesToKey (MD5, 1 iteration)。"""
    out, prev = b"", b""
    while len(out) < klen:
        prev = hashlib.md5(prev + passphrase + salt).digest()
        out += prev
    return out[:klen]


def cryptojs_aes_decrypt(b64_ciphertext, passphrase):
    """层2: 还原 CryptoJS.AES.encrypt(msg, passphrase).toString() 的明文。"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    raw = base64.b64decode(b64_ciphertext)
    if not raw.startswith(b"Salted__"):          # CryptoJS 固定 8 字节前缀
        raise ValueError("not an OpenSSL/CryptoJS salted ciphertext")
    salt, ct = raw[8:16], raw[16:]
    k = evp_bytes_to_key(passphrase, salt, 48)   # AES-256: 32B key + 16B iv
    dec = Cipher(algorithms.AES(k[:32]), modes.CBC(k[32:48])).decryptor()
    pt = dec.update(ct) + dec.finalize()
    pad = pt[-1]                                  # 去掉 PKCS7 填充
    if not (1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad):
        raise ValueError("bad PKCS7 padding (wrong passphrase?)")
    return pt[:-pad]


def caesar_bruteforce(s):
    """层4: 26 个凯撒位移，返回 (shift, 明文) 列表。"""
    res = []
    for k in range(26):
        out = []
        for c in s:
            if "A" <= c <= "Z":
                out.append(chr((ord(c) - 65 - k) % 26 + 65))
            elif "a" <= c <= "z":
                out.append(chr((ord(c) - 97 - k) % 26 + 97))
            else:
                out.append(c)
        res.append((k, "".join(out)))
    return res


def solve(path=DEFAULT_TXT, passphrase=b"0x2026", rotation=0, shift=7, verbose=True):
    emoji = extract_emoji(path)

    # --- 层1: 表情 -> base64 ------------------------------------------------
    b64_outer = emoji_to_base64(emoji, rotation)
    if verbose:
        print(f"[*] emoji 个数          : {len(emoji)}")
        print(f"[1] 表情替换(rotation={rotation}) : {b64_outer}")

    # --- 层2: AES (CryptoJS, passphrase = 0x2026) ---------------------------
    inner_b64 = cryptojs_aes_decrypt(b64_outer, passphrase).decode()
    if verbose:
        print(f"[2] AES-256-CBC 解密   : {inner_b64}")

    # --- 层3: base64 --------------------------------------------------------
    caesar_ct = base64.b64decode(inner_b64).decode()
    if verbose:
        print(f"[3] base64 解码        : {caesar_ct}")

    # --- 层4: 凯撒 (26 位移里唯一能读出英文的是 7) -------------------------
    shifted = dict(caesar_bruteforce(caesar_ct))[shift]
    if verbose:
        print(f"[4] 凯撒位移 {shift}       : {shifted}")
        print("    全部 26 个位移:")
        for k, v in caesar_bruteforce(caesar_ct):
            print(f"      -{k:2d} -> {v}")

    flag = "0xGame{%s}" % shifted
    if verbose:
        print(f"\n[+] FLAG = {flag}")
    return flag


if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TXT
    solve(p)
