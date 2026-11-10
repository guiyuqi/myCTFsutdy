#!/usr/bin/env python3
"""Unicorn harness to run route97_rhythm.exe main() offline (no wine).

Patches:
  * IAT slots replaced by magic trampoline addresses -> python stubs
  * 0x4024a4  je 0x40260c  ->  eb 1c (jmp 0x4024c2), skipping anti-debug PEB read
"""
import sys, os, struct, unicorn, pefile
from unicorn import *
from unicorn.x86_const import *

BASE = 0x400000
EXE = 'work/extracted/radio/route97_rhythm.exe'
MAGIC = 0x700000
SCRATCH = 0x800000
STACK = 0x1000000
STACK_SIZE = 0x80000

def u32(x): return x & 0xffffffff
def rol32(v,n): n&=31; return u32((v<<n)|(v>>(32-n))) if n else u32(v)

class Emu:
    def __init__(self, argv, files, trace_note=False, hooks=None):
        self.pe = pefile.PE(EXE, fast_load=True)
        self.pe.parse_data_directories() if False else None
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.uc.mem_map(BASE, 0x30000)
        for s in self.pe.sections:
            va = s.VirtualAddress; raw = s.PointerToRawData; sz = s.SizeOfRawData
            if raw and sz:
                data = s.get_data()
                self.uc.mem_write(BASE+va, data)
        self.uc.mem_map(MAGIC, 0x1000)
        self.uc.mem_map(SCRATCH, 0x200000)
        self.uc.mem_map(STACK, STACK_SIZE)
        self.imports = {}
        self.tramp_to_name = {}
        # patch IAT
        idx = 0
        pe = pefile.PE(EXE)
        for d in pe.DIRECTORY_ENTRY_IMPORT:
            for i in d.imports:
                name = i.name.decode()
                addr = MAGIC + idx*0x10
                self.tramp_to_name[addr] = name
                self.uc.mem_write(i.address, struct.pack('<Q', addr))
                idx += 1
        # patch anti-debug jump
        self.uc.mem_write(0x4024a4, b'\xeb\x1c')
        self.files = dict(files)      # name -> bytes
        self.fh = {}                  # id -> [bytes, pos]
        self.next_fh = 0
        self.argv = argv
        self.out = b''
        self.malloc_ptr = SCRATCH + 0x1000
        self.notes_ints = None
        self.hooks = hooks or {}
        self.hooks[0x402ee0] = lambda e: e.ret(0)
        self.icount = 0
        self.uc.hook_add(UC_HOOK_CODE, self._code_hook)
        self.uc.hook_add(UC_HOOK_INSN, self._insn_hook, None, 1, 0, UC_X86_INS_SYSCALL)
        self._setup_stack()

    def _setup_stack(self):
        uc = self.uc
        p = SCRATCH + 0x80000
        addrs = []
        base = SCRATCH + 0x40000
        off = base
        for a in self.argv:
            b = a.encode() + b'\0'
            uc.mem_write(off, b)
            addrs.append(off)
            off += len(b) + 8
        arr = off + 0x10
        for i, a in enumerate(addrs):
            uc.mem_write(arr + 8*i, struct.pack('<Q', a))
        uc.mem_write(arr + 8*len(addrs), b'\0'*8)
        sp = STACK + 0x1f000
        uc.mem_write(sp, struct.pack('<Q', 0))
        uc.reg_write(UC_X86_REG_RSP, sp)
        uc.reg_write(UC_X86_REG_RCX, len(self.argv))
        uc.reg_write(UC_X86_REG_RDX, arr)
        uc.reg_write(UC_X86_REG_RBP, sp+0x100)

    def cstr(self, addr, maxlen=4096):
        out = b''
        while maxlen:
            try:
                ch = self.uc.mem_read(addr, 1)
            except Exception:
                break
            if ch == b'\0': break
            out += ch; addr += 1; maxlen -= 1
        return out

    def _insn_hook(self, uc, user, *a):
        return

    def _code_hook(self, uc, addr, size, user):
        name = self.tramp_to_name.get(addr)
        if name is None:
            if addr in self.hooks:
                self.hooks[addr](self)
            return
        try:
            self.call_stub(name, addr)
        except Exception as ex:
            import sys
            print('STUB FAIL', name, ex, 'out=', self.out[:200])
            raise

    def ret(self, val=0):
        uc = self.uc
        sp = uc.reg_read(UC_X86_REG_RSP)
        ra = struct.unpack('<Q', uc.mem_read(sp, 8))[0]
        uc.reg_write(UC_X86_REG_RSP, sp+8)
        uc.reg_write(UC_X86_REG_RAX, val & 0xffffffffffffffff)
        # jump: emulate ret by setting rip
        uc.reg_write(UC_X86_REG_RIP, ra)

    def call_stub(self, name, addr):
        uc = self.uc
        rdi = uc.reg_read(UC_X86_REG_RDI)
        rsi = uc.reg_read(UC_X86_REG_RSI)
        rdx = uc.reg_read(UC_X86_REG_RDX)
        rcx = uc.reg_read(UC_X86_REG_RCX)
        r8 = uc.reg_read(UC_X86_REG_R8)
        r9 = uc.reg_read(UC_X86_REG_R9)
        if name == 'IsDebuggerPresent':
            self.ret(0)
        elif name == 'GetModuleFileNameA':
            ms = b'route97_rhythm.exe\0'
            uc.mem_write(rdx, ms[:max(r8, len(ms))])
            self.ret(len(ms)-1)
        elif name == '__acrt_iob_func':
            self.ret(0x600000 + 0x40*rcx)
        elif name == 'fopen':
            path = self.cstr(rcx).decode()
            data = self.files.get(path)
            if data is None:
                self.ret(0); return
            fid = 0x500000 + 0x100*self.next_fh
            self.next_fh += 1
            self.fh[fid] = [data, 0]
            self.ret(fid)
        elif name == 'fclose':
            self.ret(0)
        elif name == 'fseek':
            fp = self.fh.get(rcx)
            if fp is None: self.ret(-1); return
            off = rdx if rdx < 0x8000000000000000 else rdx - (1<<64)
            whence = r8
            if whence == 0: fp[1] = off
            elif whence == 1: fp[1] += off
            elif whence == 2: fp[1] = len(fp[0]) + off
            self.ret(0)
        elif name == 'ftell':
            fp = self.fh.get(rcx)
            self.ret(fp[1] if fp else -1)
        elif name == 'fread':
            fp = self.fh.get(r9)
            if fp is None: self.ret(0); return
            n = rdx * r8
            chunk = fp[0][fp[1]:fp[1]+n]
            uc.mem_write(rcx, chunk)
            fp[1] += len(chunk)
            self.ret(len(chunk)//rdx if rdx else 0)
        elif name == 'fscanf':
            fp = self.fh.get(rcx)
            fmt = self.cstr(rdx).decode()
            data, pos = fp
            vals = []
            while len(vals) < fmt.count('%d'):
                while pos < len(data) and data[pos:pos+1] in b' \t\r\n': pos += 1
                st = pos
                while pos < len(data) and data[pos:pos+1] in b'0123456789+-': pos += 1
                if st == pos: break
                vals.append(int(data[st:pos]))
            fp[1] = pos
            for i, v in enumerate(vals):
                ptr = [r8, r9][i]
                uc.mem_write(ptr, struct.pack('<i', v))
            self.ret(len(vals))
        elif name == 'malloc':
            p = self.malloc_ptr
            self.malloc_ptr = (self.malloc_ptr + rcx + 0x10 + 0xf) & ~0xf
            self.ret(p)
        elif name == 'calloc':
            n = rcx*rdx
            p = self.malloc_ptr
            self.malloc_ptr = (self.malloc_ptr + n + 0x10 + 0xf) & ~0xf
            uc.mem_write(p, b'\0'*n)
            self.ret(p)
        elif name == 'free':
            self.ret(0)
        elif name in ('memcpy','memmove'):
            if r8:
                uc.mem_write(rcx, bytes(uc.mem_read(rdx, r8)))
            self.ret(rcx)
        elif name == 'memcmp':
            a = bytes(uc.mem_read(rcx, r8)); b = bytes(uc.mem_read(rdx, r8))
            self.ret(0 if a == b else (1 if a > b else -1))
        elif name == 'strlen':
            self.ret(len(self.cstr(rcx)))
        elif name == 'strncmp':
            a = bytes(uc.mem_read(rcx, r8)); b = bytes(uc.mem_read(rdx, r8))
            self.ret(0 if a == b else (1 if a > b else -1))
        elif name == 'printf':
            s = self.cstr(rcx)
            out = self._fmt(s, [rdx, r8, r9], 0, 0)
            self.out += out
            self.ret(len(out))
        elif name == 'fputs':
            s = self.cstr(rcx)
            self.out += s
            self.ret(0)
        elif name == 'fwrite':
            st = uc.reg_read(UC_X86_REG_RSP) + 8
            out = bytes(uc.mem_read(rcx, rdx*r8))
            self.out += out
            self.ret(r8)
        elif name in ('fprintf','vfprintf'):
            pass
        elif name == 'exit':
            raise SystemExit('exit(%d) out=%r' % (rcx, self.out))
        else:
            raise RuntimeError('unhandled import %s at %x' % (name, addr))

    def _fmt(self, fmt, first, stackptr, nfloat):
        # only used for printf("%s\n", buf)
        out = b''
        i = 0
        args = list(first)
        while i < len(fmt):
            c = fmt[i:i+1]
            if c == b'%':
                n = fmt[i+1:i+2]
                if n == b's':
                    p = args.pop(0)
                    out += self.cstr(p)
                elif n == b'd':
                    v = args.pop(0) & 0xffffffff
                    if v >= 0x80000000: v -= 1<<32
                    out += str(v).encode()
                elif n == b'x':
                    out += b'%x' % (args.pop(0) & 0xffffffff)
                else:
                    out += c+n
                i += 2
            else:
                out += c; i += 1
        return out

    def run(self, start=0x401add, maxins=200_000_000):
        uc = self.uc
        try:
            uc.emu_start(start, 0, count=maxins)
        except UcError as e:
            print('UC ERROR', e, 'pc=', hex(uc.reg_read(UC_X86_REG_RIP)))
        return self.out


if __name__ == '__main__':
    wav = 'work/extracted/radio/radio_channel.wav'
    notes = sys.argv[1] if len(sys.argv) > 1 else 'mywork/notes.txt'
    tok = b'AJ9U_N1ghtR0ute_97FM_S1gnal'
    files = {}
    files[wav] = open(wav,'rb').read()
    files[notes] = open(notes,'rb').read() if os.path.exists(notes) else b''
    files['route97_rhythm.exe'] = open(EXE,'rb').read()
    argv = ['route97_rhythm.exe', wav, notes, tok.decode()]
    e = Emu(argv, files)
    out = e.run()
    print('OUT:', out)
    print('raw:', out.hex())
