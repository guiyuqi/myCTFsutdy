from unicorn import *
from unicorn.arm_const import *
import struct

FLASH=0x08000000
RAM=0x20000000
RAM_SZ=0x40000
STATE=0x20004000
VIN_ADDR=0x20000060
REQ=0x20010000
RESP=0x20011000
STACK=0x2003F000
HANDLER=0x08001258

class ECU:
    def __init__(self, flash=None, vin=b'NLBC1FA704F42700B'):
        self.flash=open('flash.bin','rb').read() if flash is None else flash
        self.mu=Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.mu.mem_map(FLASH, 0x20000)
        self.mu.mem_write(FLASH, self.flash.ljust(0x20000, b'\0'))
        self.mu.mem_map(RAM, RAM_SZ)
        self.mu.mem_write(STATE, b'\x01'+b'\0'*0xff)   # default session
        self.mu.mem_write(VIN_ADDR, vin)
        self.mu.reg_write(UC_ARM_REG_SP, STACK-0x400)
        self.log=[]
    def call(self, req, cap=600, entry=HANDLER, timeout=0):
        mu=self.mu
        mu.mem_write(REQ, bytes(req))
        mu.mem_write(RESP, b'\0'*cap)
        mu.reg_write(UC_ARM_REG_R0, REQ)
        mu.reg_write(UC_ARM_REG_R1, len(req))
        mu.reg_write(UC_ARM_REG_R2, RESP)
        mu.reg_write(UC_ARM_REG_R3, cap)
        mu.reg_write(UC_ARM_REG_LR, 0x08003FF0|1)
        try:
            mu.emu_start(entry|1, 0x08003FF0, count=200000000)
        except UcError as e:
            return None, str(e), mu.reg_read(UC_ARM_REG_PC)
        n=mu.reg_read(UC_ARM_REG_R0)
        if n==0 or n>cap:
            return b'', None, n
        return bytes(mu.mem_read(RESP, n)), None, n

if __name__=='__main__':
    e=ECU()
    for req in [b'\x22\xf1\x90', b'\x22\xf1\x80', b'\x10\x03', b'\x10\x02', b'\x22\xfd\x10', b'\x27\x01']:
        r,err,n=e.call(req)
        print(req.hex(), '->', None if r is None else r.hex(), 'err', err, n)
