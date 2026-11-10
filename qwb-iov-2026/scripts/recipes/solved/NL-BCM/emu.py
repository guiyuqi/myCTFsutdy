from unicorn import *
from unicorn.arm_const import *
import struct

FLASH=0x08000000
BUF=0x20010000
STACK=0x20040000

def decrypt(key, data, fwcode):
    mu=Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    mu.mem_map(FLASH, 0x4000)
    mu.mem_write(FLASH, fwcode.ljust(0x4000,b'\0'))
    mu.mem_map(BUF, 0x20000)
    mu.mem_write(BUF, data)
    mu.mem_map(STACK-0x2000, 0x4000)
    mu.reg_write(UC_ARM_REG_SP, STACK-0x100)
    mu.reg_write(UC_ARM_REG_R0, key & 0xffffffff)
    mu.reg_write(UC_ARM_REG_R1, BUF)
    mu.reg_write(UC_ARM_REG_R2, len(data))
    mu.reg_write(UC_ARM_REG_LR, 0x080007F0 | 1)
    END=0x080007F0
    try:
        mu.emu_start(0x08000101, END, count=20000000)
    except UcError as e:
        return None, str(e), mu.reg_read(UC_ARM_REG_PC)
    out=mu.mem_read(BUF, len(data))
    return bytes(out), None, None

if __name__=='__main__':
    import sys
    fwcode=open('work_b_boot.bin','rb').read()
    d=open('../att/attachment/BCM_UPDATE.fwpk','rb').read()
    payload=d[32:]
    known=fwcode
    keys=[0x13572468,0xeeadd93e,0x08000000,0x1258,0,1,0x1a,0x18,0x32aa,0x0801c000,0x1000,0x100,0x20,
          0x13572468^0xeeadd93e,0x13572468+0xeeadd93e,0x2003F000,0xFFFFFFFF,0x12345678,0xdeadbeef,0xcafebabe,0x4418]
    L=0x1000
    data=payload[:L]
    for k in keys:
        out,err,pc=decrypt(k,data,fwcode)
        if out is None: print(hex(k),'ERR',err,hex(pc)); continue
        eq=sum(1 for a,b in zip(out,known) if a==b)
        print(hex(k),'match',eq,'/',L,'head',out[:16].hex())
