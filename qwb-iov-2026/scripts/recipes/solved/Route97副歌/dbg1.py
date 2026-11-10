import sys, struct
sys.path.insert(0,'mywork')
import emu as E
from unicorn.x86_const import *
M=0xffffffff
WAV='work/extracted/radio/radio_channel.wav'; TOKEN=b'AJ9U_N1ghtR0ute_97FM_S1gnal'
def reg(r): return e.uc.reg_read(r)&M
def rd32(off):
    rsp=e.uc.reg_read(UC_X86_REG_RSP); return struct.unpack('<I',e.uc.mem_read(rsp+off,4))[0]
def rd8(off):
    rsp=e.uc.reg_read(UC_X86_REG_RSP); return e.uc.mem_read(rsp+off,1)[0]
np='mywork/notes_dummy.txt'
files={WAV:open(WAV,'rb').read(),np:open(np,'rb').read(),'route97_rhythm.exe':open(E.EXE,'rb').read()}
e=E.Emu(['route97_rhythm.exe',WAV,np,TOKEN.decode()],files)
# pre-seed a,b for idx 0..2 from previous solve: need to patch at 0x4028d7 by index
solved={0:(0,1)}
n=[0]; seen=[]
def note(em):
    idx=rd32(0x60)
    if idx<6:
        print('NOTE idx=%d regs %08x %08x %08x %08x %08x N=%d v5c=%08x v68=%08x t44=%02x t48=%08x a4=%08x a8=%08x ac=%08x flags 30=%02x 38=%02x 28=%02x 20=%02x mem540..= %s'%(
          idx, reg(UC_X86_REG_R13),reg(UC_X86_REG_EBX),reg(UC_X86_REG_ESI),reg(UC_X86_REG_EDI),reg(UC_X86_REG_R12),
          reg(UC_X86_REG_R14), rd32(0x5c), rd32(0x68), rd32(0x44), rd32(0x48), rd32(0xa4),rd32(0xa8),rd32(0xac),
          rd8(0x30),rd8(0x38),rd8(0x28),rd8(0x20),
          ' '.join('%08x'%rd32(0x540+4*i) for i in range(6))))
    n[0]+=1
def chk(em):
    idx=rd32(0x60)
    if idx<6:
        print('  CHK idx=%d regs %08x %08x %08x %08x %08x  tgt=%08x/%08x'%(
          idx, reg(UC_X86_REG_R13),reg(UC_X86_REG_EBX),reg(UC_X86_REG_ESI),reg(UC_X86_REG_EDI),reg(UC_X86_REG_R12),
          struct.unpack('<I',e.uc.mem_read(0x406540+idx*4,4))[0], struct.unpack('<I',e.uc.mem_read(0x406460+idx*4,4))[0]))
e.hooks[0x4028d7]=note
e.hooks[0x402702]=chk
def wr(em):
    pass
e.run(maxins=30_000_000)
print('calls note', n[0], 'out', e.out[:80])
