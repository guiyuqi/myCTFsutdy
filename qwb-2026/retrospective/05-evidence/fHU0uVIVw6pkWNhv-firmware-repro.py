#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""firmware（fHU0uVIVw6pkWNhv）赛后复现：官方解法那一步，用我方已有中间量直接解 30 B flag。

背景（2026-11-02 复盘）：赛时我方已把整条派生链走通——
    P  = SM3("QWB2026::TWIN::DEVICE-A")[:16]        # 我方 README §2 记为 L
    A  = SM3(keymat || P || vm_out8)                # 我方 README §2 记为 X
    B  = SM3("twin-ctr" || A[:16])                  # 我方 README §2 记为 Y
    SM3(B[:16])[:16] == cc6bc929b72471e6094c50776b65ff91   # fw_a 门2 常量（已对上）
却把 OTA 尾部那 30 B 归进"第 4 段棘轮 crc4"，扫了 2³² 个 crc4（`work/firmware_task/crc4scan.c`），全空。

官方解法只有一行：flag 密文是**独立的 SM4-CTR 记录**
    key = SM3(P)[:16]
    iv  = B[:16]        # 每块大端 +1，无 padding，30 B 恰跨 2 块
本脚本就是那一行，用于证明"我们不缺数据、只缺原语族的联想"。

用法：
    python3 scripts/fHU0uVIVw6pkWNhv-firmware-repro.py [ota_package.bin]
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

def _find_ws(start: Path) -> Path:
    """向上找含 `work/firmware_task/` 的工作区根（本脚本可能被复制到 retrospective/ 下运行）。"""
    for p in [start, *start.parents]:
        if (p / "work/firmware_task").is_dir():
            return p
    return start.parents[1]


_HERE = Path(__file__).resolve().parent
# ① 本目录自带副本（复盘包自包含）→ ② 原工作区
DEFAULT_OTA = next((c for c in (_HERE / "ota_package.bin",
                                _find_ws(_HERE) / "work/firmware_task/ota_package.bin") if c.exists()),
                   _HERE / "ota_package.bin")

KEYMAT = bytes.fromhex("dd97cb2de25cea1a8a9bc49b81abf9f4")  # fw_b 变换后 32 B 材料的前 16 B
VM_OUT8 = bytes.fromhex("9f3e7c1a5b2d8460")                 # OTA 0x3c 起 38 B 程序跑出的 8 B
GATE2 = "cc6bc929b72471e6094c50776b65ff91"                  # fw_a 内置门2 常量


def sm3(b: bytes) -> bytes:
    return hashlib.new("sm3", b).digest()


def main() -> int:
    ota_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OTA
    if not ota_path.exists():
        sys.exit(f"[!] 找不到 {ota_path}")
    ota = ota_path.read_bytes()

    p = sm3(b"QWB2026::TWIN::DEVICE-A")[:16]
    a = sm3(KEYMAT + p + VM_OUT8)
    b = sm3(b"twin-ctr" + a[:16])
    assert sm3(b[:16])[:16].hex() == GATE2, "门2 常量对不上：keymat / P / vm_out8 取值有误"

    assert ota[0x86:0x8e] == b"QWBPFLAG", ota[0x86:0x8e]
    n = int.from_bytes(ota[0x8e:0x92], "little")
    ct = ota[0x92:0x92 + n]

    key, iv = sm3(p)[:16], b[:16]
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        dec = Cipher(algorithms.SM4(key), modes.CTR(iv)).decryptor()
        pt = dec.update(ct) + dec.finalize()
        how = "cryptography"
    except Exception:  # 退路：pycryptodome
        from Cryptodome.Cipher import AES  # 仅用于错误提示
        raise SystemExit("[!] 缺 SM4 实现：pip install cryptography>=42（或 pycryptodome 的 SM4 封装）")

    print(f"[i] P            = {p.hex()}")
    print(f"[i] B            = {b.hex()}")
    print(f"[i] 门2 校验      = {sm3(b[:16])[:16].hex()} ✓")
    print(f"[i] 密文偏移/长度 = 0x92 / {n} B")
    print(f"[i] key=SM3(P)   = {key.hex()}")
    print(f"[i] iv =B[:16]   = {iv.hex()}")
    print(f"[i] 实现         = {how}")
    print(f"[+] 明文          = {pt.decode(errors='replace')}")
    assert pt.startswith(b"flag{") and pt.endswith(b"}"), "明文不像 flag，检查端序/计数块"
    return 0


if __name__ == "__main__":
    sys.exit(main())
