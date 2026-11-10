#!/usr/bin/env python3
"""Exact note-solver for route97_rhythm.exe based on hand-decoded assembly."""
import struct, hashlib, math, re, sys

WAV = 'work/extracted/radio/radio_channel.wav'
EXE = 'work/extracted/radio/route97_rhythm.exe'
TOKEN = b'AJ9U_N1ghtR0ute_97FM_S1gnal'
M = 0xffffffff

def mix32(c):
    c &= M
    a = ((c >> 16) ^ c) & M
    c = (a * 0x7fe911ab) & M
    a = ((c >> 15) ^ c) & M
    a = (a * 0x846b2e6b) & M
    return ((a >> 16) ^ a) & M

def rol32(v, n):
    v &= M; n &= 31
    return ((v << n) | (v >> (32 - n))) & M if n else v

def xtea_dec_block(v0, v1, key):
    s = 0xc6ef3720
    for _ in range(32):
        v1 = (v1 - ((((v0 << 4) & M) ^ (v0 >> 5)) + v0 ^ (s + key[(s >> 11) & 3]))) & M
        s = (s + 0x61c88647) & M
        v0 = (v0 - ((((v1 << 4) & M) ^ (v1 >> 5)) + v1 ^ (s + key[s & 3]))) & M
    return v0, v1

def xtea_cbc_dec(data, keybytes, iv):
    key = list(struct.unpack('<4I', keybytes))
    prev = iv; out = b''
    for i in range(0, len(data), 8):
        c = data[i:i+8]
        p = xtea_dec_block(*struct.unpack('<2I', c), key)
        out += bytes(a ^ b for a, b in zip(struct.pack('<2I', *p), prev))
        prev = c
    return out

def parse_chunks(path):
    d = open(path, 'rb').read()
    assert d[0:4] == b'RIFF' and d[8:12] == b'WAVE'
    off = 12; ch = {}
    while off + 8 <= len(d):
        name = d[off:off+4]
        size = struct.unpack('>I', d[off+4:off+8])[0]
        if name in (b'data', b'fmt '):
            size = struct.unpack('<I', d[off+4:off+8])[0]
        ch[name] = d[off+8:off+8+size]
        off += 8 + ((size + 1) & ~1)
    return d, ch

def fnv64(b):
    h = 0xcbf29ce484222325
    for c in b:
        h = ((h ^ c) * 0x100000001b3) & 0xffffffffffffffff
    return h

# ---- read EXPECT tables from PE .rdata
import pefile
pe = pefile.PE(EXE)
IB = pe.OPTIONAL_HEADER.ImageBase
def rd(va, n):
    rva = va - IB
    for s in pe.sections:
        srva = s.VirtualAddress; vsz = max(s.Misc_VirtualSize, s.SizeOfRawData)
        if srva <= rva < srva + vsz:
            data = s.get_data()
            o = rva - srva
            return data[o:o+n]
    raise KeyError(hex(va))

EXP0 = list(struct.unpack('<56I', rd(0x406540, 56*4)))
EXP1 = list(struct.unpack('<56I', rd(0x406460, 56*4)))

d, ch = parse_chunks(WAV)
abox, ach1, ach2, ach3, flgx = ch[b'abox'], ch[b'ach1'], ch[b'ach2'], ch[b'ach3'], ch[b'flgx']
md5tok = hashlib.md5(TOKEN).digest()
sha_tok = hashlib.sha256(TOKEN).digest()

g0 = bytes(b ^ 0xA7 for b in ach1)
g1 = xtea_cbc_dec(ach2[8:], b'AJ9U-R97AJ9U-R97', ach2[0:8])
g2 = xtea_cbc_dec(ach3[8:], md5tok, ach3[0:8])
groups = [(g0, 8), (g1, 16), (g2, 32)]

# DFT16
dat = ch[b'data']
samples = dat[0x5140:0x5140+4096]
dft = []
for k in range(16):
    f = 50 + 8*k
    re = im = 0.0
    for i in range(4096):
        s = samples[i] - 128
        ph = 2*math.pi*f*i/4096.0
        re += s*math.cos(ph); im -= s*math.sin(ph)
    dft.append(int(round(math.sqrt(re*re + im*im) * (2**-8))) & 0xff)
buf810 = bytes(a ^ b for a, b in zip(dft, md5tok))

# state init
S = list(struct.unpack('<5I', sha_tok[0:20]))
fold = 0x9e3779b9
for i in range(0x1000):
    fold = mix32(fold ^ i)
s0 = fold ^ S[0]
eax = 0x9e3779b9
for i in range(16):
    eax = mix32(buf810[i] ^ eax)
s1 = eax ^ S[1]
st = [s0, s1, S[2], S[3], S[4]]
print('state init', [hex(x) for x in st])
A4 = mix32(st[0] ^ st[4])
A8 = mix32(st[1] ^ st[2])
AC = mix32((st[1] ^ st[2]) ^ st[3])
print('A4 %08x A8 %08x AC %08x' % (A4, A8, AC))

def run_note(st, idx, a, b, t):
    s0, s1, s2, s3, s4 = st
    v5c = (idx * 0x9e3779b9) & M
    N = (mix32(v5c ^ s4) & 3) + 1
    v68 = (((idx * 0x85ebca6b) & M) ^ AC ^ rol32(A8, idx & 31)) & M
    t44 = t & 0xff
    t48 = (t << (a & 3)) & M
    r13, ebx, esi, edi, r12 = s0, s1, s2, s3, s4
    aa, bb = a & 0xff, b & 0xff
    v5c = (v5c ^ A4) & M
    for _ in range(N):
        r13 = mix32(r13 ^ aa)
        ebx = rol32((ebx + bb) & M, 7)
        r15 = (t48 ^ r13) & M
        esi = mix32(esi ^ ebx ^ t44)
        edi = rol32(edi ^ r13, 13)
        r12 = (r12 ^ r15 ^ esi) & M
        ebx = mix32((ebx + edi) & M)
    tgt0 = mix32(v5c) ^ EXP0[idx]
    tgt1 = mix32(v68) ^ EXP1[idx]
    return (r13, ebx, esi, edi, r12), tgt0, tgt1, N

notes = []
idx = 0
for gdata, count in groups:
    for j in range(count):
        t = gdata[3*j + 2]
        st_cur = st
        _, tg0, tg1, N = run_note(st_cur, idx, 0, 0, t)
        cands = [a for a in range(256) if run_note(st_cur, idx, a, 0, t)[0][0] == tg0]
        sols = []
        for a in cands:
            for b in range(256):
                newst, g0_, g1_, _ = run_note(st_cur, idx, a, b, t)
                if newst[0] == g0_ and newst[2] == g1_:
                    sols.append((a, b, newst, N))
        print('idx %2d t=%02x N=%d a_cands=%s sols=%s' % (idx, t, N, cands, [(a, b) for a, b, _, _ in sols]))
        if len(sols) != 1:
            print('!! not unique', len(sols)); sys.exit(1)
        a, b, newst, _ = sols[0]
        notes.append((a, b))
        st = list(newst)
        idx += 1

print('final state', [hex(x) for x in st])
with open('mywork/notes_solved.txt', 'w') as f:
    for a, b in notes:
        f.write('%d %d\n' % (a, b))
print(open('mywork/notes_solved.txt').read())

# ---- key derivation + flgx decryption
exe = open(EXE, 'rb').read()
fn = fnv64(exe)
edx = ((fn >> 32) ^ fn) & M
buf28 = struct.pack('<5I', *st) + bytes([0x38, 0, 0, 0]) + struct.pack('<I', edx)
h = hashlib.sha256(buf28).digest()
print('h', h.hex())
key16 = bytes(h[i//2] if i % 2 == 0 else md5tok[i//2] for i in range(16))
print('key16', key16.hex())
T = [0]*256
for i in range(256):
    T[abox[i]] = i

def rol8(v, n):
    v &= 0xff; n &= 7
    return ((v << n) | (v >> (8-n))) & 0xff if n else v

def dec_block(block, pad, k):
    s = bytearray(block)
    for r in range(12):
        for pos in range(16):
            s[pos] ^= ((0xa7 - 7*r + pos) & 0xff) ^ key16[(0xb - r + pos) & 0xf]
        for i in range(8):
            q = 7 - i
            p = (16 - i) & 15
            v = s[q]
            c = v ^ s[p]
            s[q] = rol8(c, 1) ^ v
            s[p] = c
        for q in range(7, -1, -1):
            v = s[q]
            c = v ^ s[q+8]
            s[q] = rol8(c, 1) ^ v
            s[q+8] = c
        for pos in range(16):
            s[pos] = T[s[pos]]
    return bytes(x ^ y for x, y in zip(s, pad))

pt = b''
pad = h[16:32]
for n in range(3):
    ct = flgx[16*n:16*n+16]
    pt += dec_block(ct, pad, n)
    pad = ct
print('plaintext hex :', pt.hex())
print('plaintext repr:', pt)
tgt = ((mix32(0x44d9bc7a) << 32) | mix32(0x9a4a75d6))
print('fnv32(pt) = %016x target %016x %s' % (fnv64(pt[:32]), tgt, 'MATCH' if fnv64(pt[:32]) == tgt else 'NOMATCH'))
