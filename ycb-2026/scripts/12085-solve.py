#!/usr/bin/env python3
"""2026 羊城杯 12085 VVMM --- self-contained solver.

Pipeline
  1. locate the VMC2 container inside VVMM.exe (.rdata @ VA 0x140006f60, size @ VA 0x14000bda0)
  2. decrypt every container entry (custom keystream + FNV-1a checksum) and keep the one
     whose plaintext starts with  01 ?? ?? ?? 0D F0 DE C0  (version 1 / MAGIC 0xC0DEF00D)
  3. decode the 8-byte instruction stream and symbolically execute it with z3
     against the 31 CMPI8 expectations at the end of the program
  4. self-check the recovered candidate on a byte-exact concrete VM model

Usage:  python3 scripts/12085-solve.py [path/to/VVMM.exe]
"""
import struct, sys
from z3 import BitVec, BitVecVal, Extract, ZeroExt, Concat, RotateLeft, RotateRight, Solver, sat

M32 = 0xffffffff
VMC2_MAGIC = 0xC0DEF00D          # required at program offset +4
BLOB_VA, BLOB_SIZE_VA = 0x6f60, 0xbda0

# ---------------------------------------------------------------- PE helpers
SECTIONS = [(0x400, 0x1000, 0x3190), (0x3600, 0x5000, 0xb0), (0x3800, 0x6000, 0x6518),
            (0x9e00, 0xd000, 0x2a0), (0xa200, 0xe000, 0x25c), (0xa600, 0x10000, 0x9fc),
            (0xb000, 0x11000, 0x10), (0xb200, 0x12000, 0x4e8), (0xb800, 0x13000, 0x6c)]

def read_va(data, va, n):
    for raw, base, size in SECTIONS:
        if base <= va < base + size:
            return data[raw + (va - base): raw + (va - base) + n]
    raise ValueError('VA 0x%x not mapped' % va)

# ---------------------------------------------------------------- VMC2 container
def decrypt_entry(blob, off):
    """Mirror of FUN_140002940: per-entry keystream + FNV-1a style checksum."""
    h0, h1 = struct.unpack('<II', blob[off:off + 8])
    clen = struct.unpack('<H', blob[off + 6:off + 8])[0]
    chk = struct.unpack('<I', blob[off + 8:off + 12])[0]
    body = blob[off + 12:off + 12 + clen]
    u15 = ((h1 & 0xff) ^ h0) & M32
    h = (u15 ^ 0x811c9dc5) & M32
    seed = ((h1 & 0xff) + (h0 >> 11)) & M32
    out = bytearray(clen)
    acc = 0
    for i in range(clen):
        u = (acc ^ u15 ^ 0x9e3779b9) & M32
        u = ((u ^ (u >> 16)) * 0x7feb352d) & M32
        u = ((u ^ (u >> 15)) * 0x846ca68b) & M32
        ks = ((u >> 16) ^ u) & M32
        out[i] = body[i] ^ (seed & 0xff) ^ ((ks >> ((i & 3) * 8)) & 0xff)
        seed = (seed - 0x59) & M32
        acc = (acc + 0x45d9f3b) & M32
    for b in out:
        h = ((h ^ b) * 0x1000193) & M32
        h ^= h >> 13
    return bytes(out), (chk == ((clen ^ h) & M32)), clen

def read_exe(path):
    if path.lower().endswith('.zip'):
        import zipfile
        with zipfile.ZipFile(path) as z:
            name = [n for n in z.namelist() if n.lower().endswith('.exe')][0]
            return z.read(name)
    return open(path, 'rb').read()

def load_program(exe):
    data = read_exe(exe)
    size = struct.unpack('<Q', read_va(data, BLOB_SIZE_VA, 8))[0]
    blob = read_va(data, BLOB_VA, size)
    assert blob[:4] == b'VMC2', 'container magic missing'
    off, n = 8, blob[4]
    for _ in range(n):
        prog, ok, clen = decrypt_entry(blob, off)
        # entry 1 is a decoy: correct checksum but MAGIC 0x0BADF00D
        if ok and len(prog) >= 8 and prog[0] == 1 and \
           struct.unpack('<I', prog[4:8])[0] == VMC2_MAGIC:
            return prog
        off += clen + 0x0c
    raise SystemExit('no valid VMC2 entry')

# ---------------------------------------------------------------- instruction set
OPS = {0x00: 'NOP', 0x01: 'MAGIC', 0x10: 'LEN', 0x11: 'LDB', 0x12: 'LDM', 0x13: 'STM',
       0x20: 'MOVI', 0x21: 'XORI', 0x22: 'ADDI', 0x23: 'MULI', 0x24: 'ROLI', 0x25: 'RORI',
       0x26: 'XORR', 0x27: 'ADDR', 0x30: 'STAGE', 0x40: 'CMPI8', 0x41: 'CMPI32',
       0x50: 'JNZ', 0x51: 'JMP', 0xf0: 'OK', 0xf1: 'FAIL'}

def decode(prog, i):
    b = prog[i * 8:(i + 1) * 8]
    imm = struct.unpack('<i', b[4:8])[0]
    return b[0], b[1] & 7, b[2] & 7, imm & 0xffffffff, imm

def ce0(a, b):
    """FUN_140002ce0 -- murmur3-style finalizer on a*0x9e3779b9 ^ (b+0x6d2b79f5)."""
    a &= M32; b &= M32
    u = (((a * 0x9e3779b9) & M32) ^ ((b + 0x6d2b79f5) & M32)) & M32
    u = (((u >> 16) ^ u) * 0x85ebca6b) & M32
    u = (((u >> 13) ^ u) * 0xc2b2ae35) & M32
    return ((u >> 16) ^ u) & M32

def _rol8(v, k):
    k &= 7; v &= 0xff
    return ((v << k) | (v >> (8 - k))) & 0xff

def _ror8(v, k):
    k &= 7; v &= 0xff
    return ((v >> k) | (v << (8 - k))) & 0xff

def d10(a, b):
    """FUN_140002d10 -- STAGE's nonlinear byte mixer (bijective in b)."""
    u = ce0(a, 0xa5)
    v = (((b ^ u) & 0xffffff00) | _rol8((b ^ u) & 0xff, (a * 3 + 1) & 7))
    v = (v + a * 0x31 + 0x42) & M32
    edx = (u & 0xffffff00) | ((u & 0xff) >> 1)
    return (v ^ edx) & 0xff

# ---------------------------------------------------------------- concrete VM
def run_vm(prog, inp, max_steps=20000):
    """Byte-exact model of FUN_140003480 (jump table @ 0x140006580)."""
    n = len(prog) // 8
    regs, mem = [0] * 8, bytearray(0x80)
    pc = steps = zf = 0
    while pc < n:
        if steps >= max_steps:
            return None
        steps += 1
        op, rd, rs, imm, simm = decode(prog, pc)
        if op == 0x00 or op == 0x01:
            pass
        elif op == 0x10:
            zf = int(len(inp) == imm)
        elif op == 0x11:
            regs[rd] = inp[imm] if imm < len(inp) else 0
        elif op == 0x12:
            regs[rd] = mem[imm & 0x7f]
        elif op == 0x13:
            mem[imm & 0x7f] = regs[rd] & 0xff
        elif op == 0x20:
            regs[rd] = imm
        elif op == 0x21:
            regs[rd] = (regs[rd] ^ imm) & M32
        elif op == 0x22:
            regs[rd] = (regs[rd] + imm) & M32
        elif op == 0x23:
            regs[rd] = (regs[rd] * imm) & M32
        elif op == 0x24:
            regs[rd] = (regs[rd] & 0xffffff00) | _rol8(regs[rd], imm)
        elif op == 0x25:
            regs[rd] = (regs[rd] & 0xffffff00) | _ror8(regs[rd], imm)
        elif op == 0x26:
            regs[rd] = (regs[rd] ^ regs[rs]) & M32
        elif op == 0x27:
            regs[rd] = (regs[rd] + regs[rs]) & M32
        elif op == 0x30:
            regs[rd] = d10(imm, regs[rd] & 0xff)
        elif op == 0x40:
            zf = int((regs[rd] & 0xff) == (imm & 0xff))
        elif op == 0x41:
            zf = int(regs[rd] == imm)
        elif op == 0x50:
            if zf == 0:
                pc = pc + 1 + simm
                continue
        elif op == 0x51:
            pc = pc + 1 + simm
            continue
        elif op == 0xf0:
            return 1
        elif op == 0xf1:
            return 0
        else:
            return None
        pc += 1
    return None

# ---------------------------------------------------------------- symbolic solve
def solve(prog, nmax):
    n = len(prog) // 8
    inputs = [BitVec('b%d' % i, 32) for i in range(nmax)]
    regs = [BitVecVal(0, 32) for _ in range(8)]
    mem = [BitVecVal(0, 32) for _ in range(0x80)]
    s = Solver()
    zf = BitVecVal(0, 32)
    for i in range(n):
        op, rd, rs, imm, simm = decode(prog, i)
        if op == 0xf0:
            break
        if op == 0xf1:
            raise SystemExit('straight-line path hits FAIL')
        if op in (0x00, 0x01):
            pass
        elif op == 0x10:
            zf = BitVecVal(int(nmax == imm), 32)
        elif op == 0x11:
            regs[rd] = inputs[imm]
        elif op == 0x12:
            regs[rd] = mem[imm & 0x7f]
        elif op == 0x13:
            mem[imm & 0x7f] = regs[rd]
        elif op == 0x20:
            regs[rd] = BitVecVal(imm, 32)
        elif op == 0x21:
            regs[rd] = regs[rd] ^ BitVecVal(imm, 32)
        elif op == 0x22:
            regs[rd] = regs[rd] + BitVecVal(imm, 32)
        elif op == 0x23:
            regs[rd] = regs[rd] * BitVecVal(imm, 32)
        elif op == 0x24:
            k = imm & 7
            lo = Extract(7, 0, regs[rd])
            regs[rd] = Concat(Extract(31, 8, regs[rd]), RotateLeft(lo, k) if k else lo)
        elif op == 0x25:
            k = imm & 7
            lo = Extract(7, 0, regs[rd])
            regs[rd] = Concat(Extract(31, 8, regs[rd]), RotateRight(lo, k) if k else lo)
        elif op == 0x26:
            regs[rd] = regs[rd] ^ regs[rs]
        elif op == 0x27:
            regs[rd] = regs[rd] + regs[rs]
        elif op == 0x30:
            u = ce0(imm, 0xa5)
            k = (imm * 3 + 1) & 7
            x = Extract(7, 0, regs[rd]) ^ BitVecVal(u & 0xff, 8)
            y = RotateLeft(x, k) if k else x
            y = (y + BitVecVal((imm * 0x31 + 0x42) & 0xff, 8)) ^ BitVecVal((u & 0xff) >> 1, 8)
            regs[rd] = ZeroExt(24, y)
        elif op == 0x40:
            zf = Extract(7, 0, regs[rd]) == BitVecVal(imm & 0xff, 8)
            p_op, p_rd, _, p_imm, _ = decode(prog, i - 1)
            if p_op == 0x12 and p_rd == 0:            # "LDM r0, idx" + "CMPI8 r0, imm"
                s.add(Extract(7, 0, mem[p_imm & 0x7f]) == BitVecVal(imm & 0xff, 8))
        elif op == 0x41:
            zf = regs[rd] == BitVecVal(imm, 32)
        elif op == 0x50:
            s.add(zf == True)                          # must not be taken
        else:
            raise SystemExit('unsupported opcode 0x%02x at pc 0x%x' % (op, i * 8))
    if s.check() != sat:
        raise SystemExit('UNSAT: no input satisfies the program')
    m = s.model()
    return bytes([m.evaluate(Extract(7, 0, inputs[i])).as_long() for i in range(nmax)])

# ---------------------------------------------------------------- main
def main():
    exe = sys.argv[1] if len(sys.argv) > 1 else 'firmware/12085_VVMM/VVMM.zip'
    prog = load_program(exe)
    n = len(prog) // 8
    nmax = None
    for i in range(n):
        op, rd, rs, imm, simm = decode(prog, i)
        if op == 0x10:
            nmax = imm
            break
    print('[*] program: %d bytes / %d instructions, required input length = %d' % (len(prog), n, nmax))
    flag = solve(prog, nmax)
    print('[*] candidate:', flag)
    verdict = run_vm(prog, flag)
    print('[*] concrete VM verdict:', {1: 'ACCEPT', 0: 'REJECT', None: 'ERROR'}[verdict])
    assert verdict == 1, 'self-check failed'
    near = flag[:-1] + bytes([flag[-1] ^ 1])
    assert run_vm(prog, near) == 0, 'discrimination check failed'
    print('[+] flag = %s' % flag.decode())
    return 0

if __name__ == '__main__':
    sys.exit(main())
