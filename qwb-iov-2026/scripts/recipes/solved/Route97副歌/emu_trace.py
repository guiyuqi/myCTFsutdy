#!/usr/bin/env python3
"""Run emu.py harness with instrumentation at the note checkpoints."""
import sys, struct
sys.path.insert(0, 'mywork')
import emu as E
from unicorn.x86_const import *

wav = 'work/extracted/radio/radio_channel.wav'
notes = sys.argv[1] if len(sys.argv) > 1 else 'mywork/notes.txt'
tok = b'AJ9U_N1ghtR0ute_97FM_S1gnal'
files = {wav: open(wav, 'rb').read(),
         notes: open(notes, 'rb').read(),
         'route97_rhythm.exe': open(E.EXE, 'rb').read()}
argv = ['route97_rhythm.exe', wav, notes, tok.decode()]
e = E.Emu(argv, files)

log = []

def dump(em, tag, addrs):
    uc = em.uc
    g = lambda r: uc.reg_read(r) & 0xffffffff
    rsp = uc.reg_read(UC_X86_REG_RSP)
    def s32(off):
        return struct.unpack('<I', uc.mem_read(rsp+off, 4))[0]
    d = dict(tag=tag, rsp=rsp,
             r13=g(UC_X86_REG_R13), esi=g(UC_X86_REG_RSI), ebx=g(UC_X86_REG_EBX),
             edi=g(UC_X86_REG_RDI), r12=g(UC_X86_REG_R12), r14=g(UC_X86_REG_R14),
             eax=g(UC_X86_REG_RAX), ebp=g(UC_X86_REG_RBP))
    for off in addrs:
        d['s%02x' % off] = s32(off)
    log.append(d)
    return d

def h_check(em):
    d = dump(em, 'check', [0x5c, 0x50, 0x60, 0x44, 0x48, 0x4c, 0x58, 0x68, 0x540, 0x544, 0x548, 0x54c, 0x550, 0xa0, 0xa4, 0xa8, 0xac, 0xb8, 0x70])
    print('CHECK idx=%d r13=%08x esi=%08x ebx=%08x edi=%08x r12=%08x N=%d v5c=%08x v68=%08x t=%02x a=%02x b=%02x exp0idx=%d state=%08x %08x %08x %08x %08x' % (
        d['sa0'], d['r13'], d['esi'], d['ebx'], d['edi'], d['r12'], d['r14'], d['s5c'], d['s68'], d['s44'], d['s4c'], d['s58'],
        (d['s50'] - 0x406540)//4, d['s540'], d['s544'], d['s548'], d['s54c'], d['s550']))

def h_ok(em):
    dump(em, 'ok', [0x540, 0x544, 0x548, 0x54c, 0x550])
    print('  -> MATCH idx=%d' % em.uc.reg_read(UC_X86_REG_RSP) if False else '  -> MATCH')

e.hooks[0x402702] = h_check
e.hooks[0x402733] = h_ok
out = e.run(maxins=200_000_000)
print('OUT:', out)
