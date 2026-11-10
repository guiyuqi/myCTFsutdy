from unicorn import *
from unicorn.arm_const import *
import struct
FLASH=0x08000000
BUF=0x10000000
STACK=0x20040000
def run_func(entry, key, data, fwcode, extra=sorted([])):
    mu=Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    mu.mem_map(FLASH, 0x4000)
    mu.mem_write(FLASH, fwcode.ljust(0x4000,b'\0'))
    mu.mem_map(BUF, 0x200000)
    mu.mem_write(BUF, data)
    mu.mem_map(STACK-0x4000, 0x8000)
    mu.reg_write(UC_ARM_REG_SP, STACK-0x400)
    mu.reg_write(UC_ARM_REG_R0, key & 0xffffffff)
    mu.reg_write(UC_ARM_REG_R1, BUF)
    mu.reg_write(UC_ARM_REG_R2, len(data))
    mu.reg_write(UC_ARM_REG_LR, 0x080007F0 | 1)
    try:
        mu.emu_start(entry|1, 0x080007F0, count=200000000)
    except UcError as e:
        return None, str(e)
    return bytes(mu.mem_read(BUF, len(data))), None
