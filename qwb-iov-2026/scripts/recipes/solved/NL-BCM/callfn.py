from unicorn import *
from unicorn.arm_const import *
import struct
FLASH=0x08000000; RAM=0x20000000; RAM_SZ=0x40000
BUF=0x20010000; STACK=0x2003F000; RET=0x08003FF0

def call(flash, entry, args, out=None, extra_mem=None):
    """args: list of up to 4 register args; out: (addr,size) buffer to read back (BUF default)"""
    mu=Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    mu.mem_map(FLASH, 0x20000); mu.mem_write(FLASH, flash.ljust(0x20000,b'\0'))
    mu.mem_map(RAM, RAM_SZ)
    if extra_mem:
        for addr,data in extra_mem: mu.mem_write(addr,data)
    mu.reg_write(UC_ARM_REG_SP, STACK-0x400)
    for i,a in enumerate(args):
        mu.reg_write([UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3][i], a)
    mu.reg_write(UC_ARM_REG_LR, RET|1)
    try:
        mu.emu_start(entry|1, RET, count=200000000)
    except UcError as e:
        return None, str(e)+' pc=%x'%mu.reg_read(UC_ARM_REG_PC)
    r0=mu.reg_read(UC_ARM_REG_R0)
    return (r0, bytes(mu.mem_read(out, 8)) if out else None, mu), None
