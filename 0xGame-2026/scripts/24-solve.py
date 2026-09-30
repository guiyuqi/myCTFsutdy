#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
0xGame2026 · Misc 24 · 小伊卡...不胖...不胖...   (610 pts, offline)

思路（"一屁股把图坐扁了" = PNG 被非等比压扁）
------------------------------------------------
题目附件只有一个 PNG `fat_Y1k@.png`，IHDR 声称 1500x1280。
关键判据：**IHDR 的 CRC 校验失败** —— 说明宽/高字段被人为改过，而 IDAT
像素数据没动。

验证方法（不靠肉眼，靠像素算）：
    raw = zlib.decompress(所有 IDAT 拼接)
    raw 长度 = 6_751_500
    1500*3 + 1 = 4501  (每行字节数 = 宽*3 + 1 个 filter 字节)
    6_751_500 / 4501 = 1500   ->  真实高度就是 1500，不是 1280

所以原图是 1500x1500，被人把 IHDR 的高度改成 1280（看起来"坐扁"了）。
把高度还原成 1500 并重算 IHDR 的 CRC4 后，图片恢复正常宽高比，
图里的 flag 文字即可读出：

    0xGame{w0w_thi5_1s_thE_tru3_Length}

注意点（踩过的坑）：肉眼看低分辨率渲染时 `thi5` 里的数字 5
极易被误认成字母 s。用连通域 + 字高判定可以区分：
数字/大写 = 全高(~53px)，小写 x-height = ~39px；该字形是全高 -> 是 '5'。

用法：
    python3 scripts/24-solve.py            # 默认路径
    python3 scripts/24-solve.py <zip> <outdir>
"""

import os
import sys
import zlib
import struct
import zipfile

DEFAULT_ZIP = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "firmware", "24_小伊卡...不胖...不胖...", "little1kA.zip",
)
DEFAULT_OUT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "work", "24_little1kA",
)

FLAG = "0xGame{w0w_thi5_1s_thE_tru3_Length}"


def parse_chunks(data):
    """返回 [(type, data_offset, length, crc_offset)]"""
    out = []
    off = 8
    while off < len(data):
        (ln,) = struct.unpack(">I", data[off:off + 4])
        typ = data[off + 4:off + 8]
        out.append((typ, off + 8, ln, off + 8 + ln))
        off += 12 + ln
        if typ == b"IEND":
            break
    return out


def fix_png(path_in, path_out):
    data = bytearray(open(path_in, "rb").read())
    chunks = parse_chunks(data)

    # --- 1. 找 IHDR, 检查 CRC ---
    ihdr = [c for c in chunks if c[0] == b"IHDR"][0]
    _, doff, ln, croff = ihdr
    w, h = struct.unpack(">II", bytes(data[doff:doff + 8]))
    stored_crc = struct.unpack(">I", bytes(data[croff:croff + 4]))[0]
    calc_crc = zlib.crc32(bytes(data[doff - 4:croff])) & 0xFFFFFFFF
    print(f"[*] IHDR 声称        : {w} x {h}")
    print(f"[*] IHDR CRC 存储/计算: 0x{stored_crc:08x} / 0x{calc_crc:08x} "
          f"-> {'OK' if stored_crc == calc_crc else 'MISMATCH (字段被改过!)'}")

    # --- 2. 用 IDAT 解压后的真实字节数反推正确尺寸 ---
    idat = b"".join(bytes(data[d:d + l]) for t, d, l, _ in chunks if t == b"IDAT")
    raw = zlib.decompress(idat)
    n = len(raw)
    print(f"[*] IDAT 解压后字节数: {n}")

    bpp = 3  # 8-bit RGB
    # 已知宽度可信时，直接算高
    if n % (w * bpp + 1) == 0:
        true_w, true_h = w, n // (w * bpp + 1)
    else:
        # 兜底：暴力找能整除的尺寸，优先正方形/常规比例
        cands = []
        for tw in range(16, 4097):
            row = tw * bpp + 1
            if n % row == 0:
                cands.append((tw, n // row))
        if not cands:
            raise SystemExit("[-] 无法反推尺寸")
        cands.sort(key=lambda t: (abs(t[0] / t[1] - 1.0), -t[0]))
        true_w, true_h = cands[0]
    print(f"[+] 真实尺寸 (IDAT 反推): {true_w} x {true_h}")

    if (true_w, true_h) == (w, h):
        print("[!] 尺寸未变，可能本题不是「改 IHDR」路线")
        return None

    # --- 3. 改写 IHDR 并重算 CRC ---
    struct.pack_into(">II", data, doff, true_w, true_h)
    new_crc = zlib.crc32(bytes(data[doff - 4:croff])) & 0xFFFFFFFF
    struct.pack_into(">I", data, croff, new_crc)

    open(path_out, "wb").write(bytes(data))
    print(f"[+] 已还原宽高比 -> {path_out}  ({true_w}x{true_h})")
    return (true_w, true_h)


def main():
    zip_path = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ZIP)
    outdir = os.path.abspath(sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUT)
    os.makedirs(outdir, exist_ok=True)

    with zipfile.ZipFile(zip_path) as z:
        z.extractall(outdir)

    # 附件目录名带省略号，直接按后缀找
    png = None
    for root, _dirs, files in os.walk(outdir):
        for f in files:
            if f.lower().endswith(".png"):
                png = os.path.join(root, f)
    if png is None:
        raise SystemExit("[-] 压缩包里没找到 PNG")

    print(f"[*] 附件: {png}  ({os.path.getsize(png)} bytes)")
    fixed = os.path.join(outdir, "fixed.png")
    fix_png(png, fixed)

    print()
    print("=" * 60)
    print("FLAG:", FLAG)
    print("=" * 60)
    print("还原后的图里文字为两行：")
    print("    0xGame{w0w_thi5_1")
    print("    s_thE_tru3_Length}")


if __name__ == "__main__":
    main()
