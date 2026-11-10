import sys, struct
sys.path.insert(0,'mywork')
import emu as E
from unicorn.x86_const import *
wav='work/extracted/radio/radio_channel.wav'; notes='mywork/notes.txt'
tok=b'AJ9U_N1ghtR0ute_97FM_S1gnal'
files={wav:open(wav,'rb').read(),notes:open(notes,'rb').read(),'route97_rhythm.exe':open(E.EXE,'rb').read()}
e=E.Emu(['route97_rhythm.exe',wav,notes,tok.decode()],files)
def rd32(off):
    rsp=e.uc.reg_read(UC_X86_REG_RSP); return struct.unpack('<I',e.uc.mem_read(rsp+off,4))[0]
def reg(r): return e.uc.reg_read(r)&0xffffffff
cnt=[0]
def asm(em):
    cnt[0]+=1
    if cnt[0]<=8:
        print('ASM#%d r13=%08x ebx=%08x esi=%08x edi=%08x r12=%08x a=%d b=%d t=%02x v5c=%08x v68=%08x N=%d idx=%d'%(
          cnt[0],reg(UC_X86_REG_R13),reg(UC_X86_REG_EBX),reg(UC_X86_REG_ESI),reg(UC_X86_REG_EDI),reg(UC_X86_REG_R12),
          rd32(0x4c),rd32(0x58),rd32(0x44),rd32(0x5c),rd32(0x68),reg(UC_X86_REG_R14),rd32(0x60)))
chk=[0]
def ck(em):
    chk[0]+=1
    if chk[0]<=8:
        print('CK#%d r13=%08x esi=%08x ebx=%08x edi=%08x r12=%08x'%(chk[0],reg(UC_X86_REG_R13),reg(UC_X86_REG_ESI),reg(UC_X86_REG_EBX),reg(UC_X86_REG_EDI),reg(UC_X86_REG_R12)))
e.hooks[0x4026b4]=asm
e.hooks[0x402702]=ck
e.run(maxins=40_000_000)
print('counts asm',cnt[0],'ck',chk[0],'out',e.out[:100])
