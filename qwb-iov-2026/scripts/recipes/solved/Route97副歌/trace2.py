#!/usr/bin/env python3
"""Dump note-start register state at 0x4028d7 and check results at 0x402702."""
import sys, struct
sys.path.insert(0, 'mywork')
import emu as E
from unicorn.x86_const import *

wav = 'work/extracted/radio/radio_channel.wav'
notes = sys.argv[1] if len(sys.argv) > 1 else 'mywork/notes.txt'
tok = b'AJ9U_N1ghtR0ute_97FM_S1gnal'
files = {wav: open(wav,'rb').read(), notes: open(notes,'rb').read(),
         'route97_rhythm.exe': open(E.EXE,'rb').read()}
argv = ['route97_rhythm.exe', wav, notes, tok.decode()]
e = E.Emu(argv, files)

def rd32(off):
    uc=e.uc; rsp=uc.reg_read(UC_X86_REG_RSP)
    return struct.unpack('<I', uc.mem_read(rsp+off,4))[0]
def reg(r): return e.uc.reg_read(r)&0xffffffff

notes_seen=[]
cur=None
def note_begin(em):
    global cur
    cur=dict(r13=reg(UC_X86_REG_R13), ebx=reg(UC_X86_REG_EBX), esi=reg(UC_X86_REG_ESI),
             edi=reg(UC_X86_REG_EDI), r12=reg(UC_X86_REG_R12), N=reg(UC_X86_REG_R14),
             a=rd32(0x4c), b=rd32(0x58), t=rd32(0x44), t48=rd32(0x48),
             v5c=rd32(0x5c), v68=rd32(0x68), idx=rd32(0x60),
             s540=rd32(0x540), s544=rd32(0x544), s548=rd32(0x548), s54c=rd32(0x54c), s550=rd32(0x550),
             a4=rd32(0xa4), a8=rd32(0xa8), ac=rd32(0xac))
    notes_seen.append(cur)

cnt=[0]
def check(em):
    d=dict(r13=reg(UC_X86_REG_R13), esi=reg(UC_X86_REG_ESI), ebx=reg(UC_X86_REG_EBX),
           edi=reg(UC_X86_REG_EDI), r12=reg(UC_X86_REG_R12), idx=rd32(0x60))
    print('CHECK idx=%d r13=%08x esi=%08x ebx=%08x edi=%08x r12=%08x'%(d['idx'],d['r13'],d['esi'],d['ebx'],d['edi'],d['r12']))
    cnt[0]+=1
    if cnt[0]>3: return

e.hooks[0x4028d7]=note_begin
e.hooks[0x402702]=check
out=e.run(maxins=20_000_000)
print('OUT:',out[:500])
for k,n in enumerate(notes_seen[:6]):
    print('NOTE',k, {kk:(('%08x'%vv) if isinstance(vv,int) and vv>255 else vv) for kk,vv in n.items()})
