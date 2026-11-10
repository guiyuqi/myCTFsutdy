#!/usr/bin/env python3
"""Solve the 56 notes by brute force inside the running unicorn harness.

At 0x4028d7 (note-start jmp into the mixing loop) all state is loaded into
registers / stack slots. We read them, compute the required r13/esi at the
0x402702 check, brute-force (a,b) with an offline replica of the mixing loop,
then patch [rsp+0x4c]/[rsp+0x58]/[rsp+0x48] so the real code uses our note.
"""
import sys, struct, os
sys.path.insert(0, 'mywork')
import emu as E
from unicorn.x86_const import *

M = 0xffffffff
WAV = 'work/extracted/radio/radio_channel.wav'
TOKEN = b'AJ9U_N1ghtR0ute_97FM_S1gnal'

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

def chain(s0, N, aa, bb, t44, t48, tgt0, tgt1, s1=None, s2=None, s3=None, s4=None):
    """Return full state after the mixing loop or None."""
    r13, ebx, esi, edi, r12 = s0, s1, s2, s3, s4
    for _ in range(N):
        r13 = mix32(r13 ^ aa)
        ebx = rol32((ebx + bb) & M, 7)
        r15 = (t48 ^ r13) & M
        esi = mix32(esi ^ ebx ^ t44)
        edi = rol32(edi ^ r13, 13)
        r12 = (r12 ^ r15 ^ esi) & M
        ebx = mix32((ebx + edi) & M)
    return (r13, ebx, esi, edi, r12)

def solve_note(st, N, t44, t48base, tgt0, tgt1, verbose=False):
    s0, s1, s2, s3, s4 = st
    # stage 1: r13 chain depends on a only (and t48 via r15? r15 only feeds r12, not r13/esi)
    cand_a = []
    for a in range(256):
        aa = a & 0xff
        r13 = s0
        for _ in range(N):
            r13 = mix32(r13 ^ aa)
        if r13 == tgt0:
            cand_a.append(a)
    sols = []
    for a in cand_a:
        t48 = (t44 << (a & 3)) & M
        for b in range(256):
            out = chain(s0, N, a & 0xff, b & 0xff, t44, t48, None, None, s1, s2, s3, s4)
            if out[2] == tgt1:
                sols.append((a, b, out))
    return sols

def main():
    notes_path = 'mywork/notes_dummy.txt'
    with open(notes_path, 'w') as f:
        f.write('0 0\n' * 64)
    files = {WAV: open(WAV, 'rb').read(),
             notes_path: open(notes_path, 'rb').read(),
             'route97_rhythm.exe': open(E.EXE, 'rb').read()}
    e = E.Emu(['route97_rhythm.exe', WAV, notes_path, TOKEN.decode()], files)
    uc = e.uc
    EXP0 = 0x406540
    EXP1 = 0x406460

    def rd32(off):
        rsp = uc.reg_read(UC_X86_REG_RSP)
        return struct.unpack('<I', uc.mem_read(rsp + off, 4))[0]

    def wr8(off, v):
        rsp = uc.reg_read(UC_X86_REG_RSP)
        uc.mem_write(rsp + off, bytes([v & 0xff]))

    def wr32(off, v):
        rsp = uc.reg_read(UC_X86_REG_RSP)
        uc.mem_write(rsp + off, struct.pack('<I', v & M))

    def reg(r):
        return uc.reg_read(r) & M

    state = {'notes': [], 'done': False, 'log': []}

    def at_note(em):
        if state['done']:
            return
        idx = rd32(0x60)
        if idx >= 56:
            state['done'] = True
            return
        r13, ebx, esi, edi, r12 = reg(UC_X86_REG_R13), reg(UC_X86_REG_EBX), reg(UC_X86_REG_ESI), reg(UC_X86_REG_EDI), reg(UC_X86_REG_R12)
        N = reg(UC_X86_REG_R14)
        v5c = rd32(0x5c); v68 = rd32(0x68)
        t44 = rd32(0x44)
        tgt0 = mix32(v5c) ^ struct.unpack('<I', uc.mem_read(EXP0 + idx*4, 4))[0]
        tgt1 = mix32(v68) ^ struct.unpack('<I', uc.mem_read(EXP1 + idx*4, 4))[0]
        sols = solve_note((r13, ebx, esi, edi, r12), N, t44, (t44 << (rd32(0x4c) & 3)) & M, tgt0, tgt1)
        if len(sols) == 0:
            print('!! idx %d no solution  state=%08x %08x %08x %08x %08x N=%d t=%02x tgt=%08x/%08x' %
                  (idx, r13, ebx, esi, edi, r12, N, t44, tgt0, tgt1))
            state['log'].append(('fail', idx))
            raise SystemExit(1)
        if len(sols) > 1:
            print('   idx %d multiple solutions: %s' % (idx, [(s[0], s[1]) for s in sols]))
        a, b, out = sols[0]
        wr8(0x4c, a & 0xff)
        wr8(0x58, b & 0xff)
        wr32(0x48, (t44 << (a & 3)) & M)
        state['notes'].append((idx, a, b, t44))
        if idx % 8 == 0 or idx > 50:
            print('idx %2d t=%02x -> a=%3d b=%3d' % (idx, t44, a, b))
        if idx == 55:
            state['done'] = True

    e.hooks[0x4028d7] = at_note
    out = e.run(maxins=80_000_000)
    print('OUT:', out)
    if len(state['notes']) == 56:
        with open('mywork/notes_solved.txt', 'w') as f:
            for idx, a, b, t in sorted(state['notes']):
                f.write('%d %d\n' % (a, b))
        print('wrote mywork/notes_solved.txt')

if __name__ == '__main__':
    main()
