#!/usr/bin/env python3
"""
39 · z3_solver (Reverse, 773)  --  0xGame 2026 / CTF+

attachment4.zip -> attachment3.exe (PE32+ x86-64, mingw-w64, console)

校验逻辑（Ghidra 伪代码 FUN_00401550，唯一 gate 函数）:

    if (strlen(input) != 0x17) -> "Wrong length."   # 23 字节
    for i in 0..22:
        if input[i] not in 0x20..0x7e -> fail
        b1 = input[(i+1) % 23]
        b2 = input[(i+7) % 23]
        #  (b2*9 + b2*2) == b2*11 , (b1*4 + b1) == b1*5
        3*input[i] + 5*b1 + 11*b2 + 7*input[(i+4) % 23]  ==  C[i]
    其中 C[i] 是 .rdata 里 DAT_00404000 处的 23 个 little-endian int16 常量。

常量表直接按 RVA 0x4000 从 PE 里读，不硬编码 -> 完全可复现。

用法:
    python3 scripts/39-solve.py                 # 默认读 firmware/39_z3_solver/attachment4.zip
    python3 scripts/39-solve.py <attachment3.exe>

需要: z3 (source ~/re-tools/fw-env.sh)
"""
import json
import os
import struct
import sys
import zipfile

import z3

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ZIP = os.path.join(ROOT, "firmware", "39_z3_solver", "attachment4.zip")

N = 23               # 0x17, 校验的输入长度
CONST_RVA = 0x4000   # DAT_00404000 的 RVA (image base 0x400000)


def load_exe(argv):
    """返回 PE 文件字节。"""
    if len(argv) > 1:
        return open(argv[1], "rb").read()
    with zipfile.ZipFile(ZIP) as z:
        name = z.namelist()[0]          # attachment3.exe
        return z.read(name)


def extract_consts(pe):
    """从 PE 节表把 CONST_RVA 处的 23 个 LE uint16 常量读出来。"""
    e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    assert pe[e_lfanew:e_lfanew + 4] == b"PE\0\0", "not a PE"
    n_sec = struct.unpack_from("<H", pe, e_lfanew + 6)[0]
    opt_sz = struct.unpack_from("<H", pe, e_lfanew + 20)[0]
    sec0 = e_lfanew + 24 + opt_sz
    for i in range(n_sec):
        sec = pe[sec0 + i * 40: sec0 + (i + 1) * 40]
        vsz, va, rsz, ra = struct.unpack_from("<IIII", sec, 8)
        if va <= CONST_RVA < va + max(vsz, rsz):
            fo = ra + (CONST_RVA - va)
            return list(struct.unpack_from("<%dH" % N, pe, fo))
    raise RuntimeError("constant table section not found")


def solve(C):
    s = [z3.BitVec("s%d" % i, 8) for i in range(N)]
    sol = z3.Solver()
    for i in range(N):
        sol.add(z3.UGE(s[i], 0x20), z3.ULE(s[i], 0x7E))       # isprint
        expr = (z3.ZeroExt(16, s[i]) * 3
                + z3.ZeroExt(16, s[(i + 1) % N]) * 5          # b1*4 + b1
                + z3.ZeroExt(16, s[(i + 7) % N]) * 11         # b2*9 + b2*2
                + z3.ZeroExt(16, s[(i + 4) % N]) * 7)
        sol.add(expr == C[i])
    assert sol.check() == z3.sat, "unsat"
    m = sol.model()
    return "".join(chr(m[s[i]].as_long()) for i in range(N))


def main():
    pe = load_exe(sys.argv)
    C = extract_consts(pe)
    flag = solve(C)
    # 独立复算一遍，确认与二进制里的方程组逐条相符
    v = [ord(c) for c in flag]
    assert all(3 * v[i] + 5 * v[(i + 1) % N] + 11 * v[(i + 7) % N] + 7 * v[(i + 4) % N] == C[i]
               for i in range(N)), "self-check failed"
    print("C =", json.dumps(C))
    print("FLAG:", flag)
    print("[ok] 23/23 constraints verified against the binary")


if __name__ == "__main__":
    main()
