#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
29 - Strange_lsb  (Misc / 图片隐写)  ——  可复现解题脚本
================================================================
题目提示：
    「单一的色彩只是噪音，唯有三原色交织之时，真相才会显现。」

关键洞察：
    单看任何一个通道的 LSB 都是纯噪声（均匀分布、零空间相关），
    但把三个通道的 **LSB 逐位异或** 之后 ——  R_lsb ^ G_lsb ^ B_lsb ——
    得到一张 1bpp 的位图，其中 86% 为 0、14% 为 1，
    这张位图正中央就是一个完整的 **QR 码**（版本 4，33x33 模块）。
    "三原色交织" == 三个通道的 LSB 做 XOR。

    QR 在图中是「反色」的（xor==1 的像素是 QR 的黑色模块），
    且轴对齐（无旋转/透视），因此可以直接按模块网格采样。

复现：
    python3 scripts/29-solve.py
    （默认从 firmware/29_Strange_lsb/week1-misc-strange_lsb.zip 解出 challenge.png）

依赖：仅 numpy + Pillow（无需 zbar / zxing / cv2 —— QR 解码在本脚本内实现）
"""

import os
import sys
import zipfile
import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ZIP = os.path.join(ROOT, "firmware", "29_Strange_lsb", "week1-misc-strange_lsb.zip")
WORK = os.path.join(ROOT, "work", "29_strange_lsb")
EVID = os.path.join(ROOT, "evidence")


# ----------------------------------------------------------------------------
# 1. 取出 attachment
# ----------------------------------------------------------------------------
def get_image():
    os.makedirs(WORK, exist_ok=True)
    png = os.path.join(WORK, "challenge.png")
    if not os.path.exists(png):
        with zipfile.ZipFile(ZIP) as z:
            z.extract("challenge.png", WORK)
    return png


# ----------------------------------------------------------------------------
# 2. 三通道 LSB 异或 -> QR 位图
# ----------------------------------------------------------------------------
def xor_lsb_plane(png):
    a = np.array(Image.open(png).convert("RGB")).astype(np.uint8)
    return (a[:, :, 0] & 1) ^ (a[:, :, 1] & 1) ^ (a[:, :, 2] & 1)


# ----------------------------------------------------------------------------
# 3. 极简 QR 解码器（版本 1..10，byte / alphanumeric / numeric 模式）
# ----------------------------------------------------------------------------
def _bch_rem(v):
    g = 0x537
    for i in range(14, 9, -1):
        if (v >> i) & 1:
            v ^= g << (i - 10)
    return v & 0x3FF


def _fmt_code(d):
    return ((d << 10) | _bch_rem(d << 10)) ^ 0x5412


# version -> (block count, data codewords per block, ec codewords per block)
# indexed by EC level bits (0b01=L, 0b00=M, 0b11=Q, 0b10=H)
_BLOCKS = {
    1: {1: (1, 19, 7),  0: (1, 16, 10), 3: (1, 13, 13), 2: (1, 9, 17)},
    2: {1: (1, 34, 10), 0: (1, 28, 16), 3: (1, 22, 22), 2: (1, 16, 28)},
    3: {1: (1, 55, 15), 0: (1, 44, 26), 3: (2, 17, 18), 2: (2, 13, 22)},
    4: {1: (1, 80, 20), 0: (2, 32, 18), 3: (2, 24, 26), 2: (4, 9, 16)},
    5: {1: (1, 108, 26), 0: (2, 43, 24), 3: (2, 15, 18), 2: (2, 11, 22)},
    6: {1: (2, 68, 18), 0: (4, 27, 16), 3: (4, 19, 24), 2: (4, 15, 28)},
    7: {1: (2, 78, 20), 0: (4, 31, 18), 3: (2, 14, 18), 2: (4, 13, 26)},
    8: {1: (2, 97, 24), 0: (2, 38, 22), 3: (4, 18, 22), 2: (4, 14, 26)},
    9: {1: (2, 116, 30), 0: (3, 36, 22), 3: (4, 16, 20), 2: (4, 12, 24)},
    10: {1: (2, 68, 18), 0: (4, 43, 26), 3: (6, 19, 24), 2: (6, 15, 28)},
}

_ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
_ECNAME = {1: "L", 0: "M", 3: "Q", 2: "H"}


def _build_func(size):
    """返回 size x size 的功能模块掩码（True = 非数据模块）。"""
    F = [[False] * size for _ in range(size)]

    def finder(r0, c0):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                r, c = r0 + dr, c0 + dc
                if 0 <= r < size and 0 <= c < size:
                    F[r][c] = True

    finder(0, 0)
    finder(0, size - 7)
    finder(size - 7, 0)
    for i in range(size):
        F[6][i] = True
        F[i][6] = True
    # alignment patterns (version >= 2)；v2..v10 的位置表
    align = {2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
             7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50]}
    ver = (size - 17) // 4
    for r0 in align.get(ver, []):
        for c0 in align.get(ver, []):
            if (r0 < 9 and c0 < 9) or (r0 < 9 and c0 > size - 10) or (r0 > size - 10 and c0 < 9):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    F[r0 + dr][c0 + dc] = True
    # format info
    for i in range(9):
        F[8][i] = True
        F[i][8] = True
    for i in range(8):
        F[8][size - 1 - i] = True
    for i in range(7):
        F[size - 1 - i][8] = True
    F[size - 8][8] = True
    if ver >= 7:  # version info 区
        for i in range(6):
            for j in range(3):
                F[size - 11 + j][i] = True
                F[i][size - 11 + j] = True
    return F


def _mask_pred(mask, i, j):
    if mask == 0:
        return (i + j) % 2 == 0
    if mask == 1:
        return i % 2 == 0
    if mask == 2:
        return j % 3 == 0
    if mask == 3:
        return (i + j) % 3 == 0
    if mask == 4:
        return (i // 2 + j // 3) % 2 == 0
    if mask == 5:
        return (i * j) % 2 + (i * j) % 3 == 0
    if mask == 6:
        return ((i * j) % 2 + (i * j) % 3) % 2 == 0
    return ((i + j) % 2 + (i * j) % 3) % 2 == 0


def _parse_payload(data):
    bits = "".join(f"{b:08b}" for b in data)
    out, i = [], 0
    while i + 4 <= len(bits):
        mode = bits[i:i + 4]
        i += 4
        if mode == "0000":
            break
        if mode == "0100":                      # byte
            ln = int(bits[i:i + 8], 2); i += 8
            s = bits[i:i + ln * 8]; i += ln * 8
            out.append(bytes(int(s[k * 8:k * 8 + 8], 2) for k in range(ln)))
        elif mode == "0010":                    # alphanumeric
            ln = int(bits[i:i + 9], 2); i += 9
            s = ""
            k = 0
            while k < ln:
                if ln - k >= 2:
                    s += _ALNUM[int(bits[i:i + 11], 2)]; i += 11; k += 2
                else:
                    s += _ALNUM[int(bits[i:i + 6], 2)]; i += 6; k += 1
            out.append(s.encode())
        elif mode == "0001":                    # numeric
            ln = int(bits[i:i + 10], 2); i += 10
            s = ""
            while ln >= 3:
                s += str(int(bits[i:i + 10], 2)).zfill(3); i += 10; ln -= 3
            if ln == 2:
                s += str(int(bits[i:i + 7], 2)).zfill(2)
            elif ln == 1:
                s += str(int(bits[i:i + 4], 2))
            out.append(s.encode())
        else:
            out.append(("<mode %s>" % mode).encode())
            break
    return out


def _decode_with_geometry(plane, x0, y0, side, size, verify=True):
    """按给定网格几何采样并解码；失败返回 None。"""
    m = side / size
    h, w = plane.shape

    def sample(r, c):
        cy = y0 + (r + 0.5) * m
        cx = x0 + (c + 0.5) * m
        y1, y2 = int(round(cy - 3)), int(round(cy + 4))
        x1, x2 = int(round(cx - 3)), int(round(cx + 4))
        y1 = max(0, y1); x1 = max(0, x1)
        y2 = min(h, y2); x2 = min(w, x2)
        blk = plane[y1:y2, x1:x2]
        if blk.size == 0:
            return 0
        return 1 if blk.mean() >= 0.5 else 0

    G = [[sample(r, c) for c in range(size)] for r in range(size)]

    # 用 finder pattern 校验方向（必须是标准 7x7 图形）
    if verify:
        expect = [(1, 1, 1, 1, 1, 1, 1), (1, 0, 0, 0, 0, 0, 1),
                  (1, 0, 1, 1, 1, 0, 1), (1, 0, 1, 1, 1, 0, 1),
                  (1, 0, 1, 1, 1, 0, 1), (1, 0, 0, 0, 0, 0, 1),
                  (1, 1, 1, 1, 1, 1, 1)]
        for r in range(7):
            for c in range(7):
                if G[r][c] != expect[r][c]:
                    return None

    # --- format info ---
    rem = 0
    for i in range(6):
        rem = (rem << 1) | G[8][i]
    rem = (rem << 1) | G[8][7]
    rem = (rem << 1) | G[8][8]
    rem = (rem << 1) | G[7][8]
    for i in range(5, -1, -1):
        rem = (rem << 1) | G[i][8]
    best = (16, -1)
    for d in range(32):
        diff = bin(rem ^ _fmt_code(d)).count("1")
        if diff < best[0]:
            best = (diff, d)
    if best[1] < 0 or best[0] > 3:
        return None
    ecl, mask = best[1] >> 3, best[1] & 7

    ver = (size - 17) // 4
    if ver not in _BLOCKS or ecl not in _BLOCKS[ver]:
        return None

    FUNC = _build_func(size)

    # --- 按之字形读取数据位 ---
    bits = []
    right = size - 1
    while right >= 1:
        if right == 6:
            right = 5
        for vert in range(size):
            for j in range(2):
                c = right - j
                up = ((right + 1) & 2) == 0
                r = (size - 1 - vert) if up else vert
                if not FUNC[r][c]:
                    v = G[r][c] ^ (1 if _mask_pred(mask, r, c) else 0)
                    bits.append(v)
        right -= 2

    n = len(bits) // 8
    cw = [int("".join(map(str, bits[i * 8:i * 8 + 8])), 2) for i in range(n)]

    # --- 反交织 ---
    nb, nd, ne = _BLOCKS[ver][ecl]
    blocks = [[] for _ in range(nb)]
    for i in range(nd * nb):
        blocks[i % nb].append(cw[i])
    if nd * nb + ne * nb > len(cw):
        return None

    data = []
    for b in blocks:
        data += b
    return {"version": ver, "ecl": _ECNAME[ecl], "mask": mask,
            "data": data, "text": _parse_payload(data),
            "format_error_bits": best[0]}


def decode_qr_plane(plane, evid_dir=None):
    """自动定位 QR（黑=1，反色渲染）并解码。"""
    ys, xs = np.nonzero(plane)
    if len(ys) == 0:
        raise RuntimeError("XOR 平面上没有任何置位像素")
    y0, y1, x0, x1 = ys.min(), ys.max(), xs.min(), xs.max()
    side = max(y1 - y0 + 1, x1 - x0 + 1)
    if evid_dir:
        os.makedirs(evid_dir, exist_ok=True)
        Image.fromarray((plane * 255).astype(np.uint8)).save(
            os.path.join(evid_dir, "29-xor-lsb-plane.png"))

    # 依次尝试 QR version 1..10，取能通过 finder 校验 + format 校验的解
    for ver in range(1, 11):
        size = 17 + 4 * ver
        m = side / size
        if m < 3 or abs(m - round(m)) > 3:   # 模块太小/不是整数比例 -> 跳过
            continue
        got = _decode_with_geometry(plane, x0, y0, side, size, verify=True)
        if got:
            got["bbox"] = (int(x0), int(y0), int(side))
            got["module_px"] = round(m, 3)
            return got
    raise RuntimeError("未能解码 QR：已尝试 version 1..10")


def main():
    png = get_image()
    plane = xor_lsb_plane(png)
    print("[*] 图片       : %s" % png)
    print("[*] R_lsb^G_lsb^B_lsb 置位比例: %.4f" % plane.mean())

    got = decode_qr_plane(plane, evid_dir=EVID)
    print("[*] QR version : %d  (%dx%d modules, %.2f px/module)"
          % (got["version"], 17 + 4 * got["version"], 17 + 4 * got["version"], got["module_px"]))
    print("[*] QR bbox    : x=%d y=%d side=%d" % got["bbox"])
    print("[*] EC level   : %s ; mask=%d ; format 纠错位数=%d"
          % (got["ecl"], got["mask"], got["format_error_bits"]))

    texts = [t for t in got["text"] if t]
    print("[*] 解码内容   :")
    for t in texts:
        print("      %r" % t)

    joined = b"".join(texts)
    txt = joined.decode("utf-8", "replace")
    print()
    print("[+] FLAG = %s" % txt)
    return txt


if __name__ == "__main__":
    main()
