#!/usr/bin/env python3
"""12084 千千的咲 / generic UE5 IoStore Oodle dumper.

UE5 IoStore compresses each 64 KiB block with Oodle; liboo2core is proprietary.
The shipped Android x86_64 `libUnreal.so` statically links OodleLZ_Decompress, so
this script maps that .so in-process, applies the Android packed relocations
(SHT_ANDROID_RELA, decoded with LIEF -- glibc cannot apply them), binds the PLT
against the host glibc, and calls OodleLZ_Decompress per block.

Usage:
    python3 12084-oodle-ucas-dump.py <libUnreal.so> <in.ucas> <in.utoc> <out.bin>
(needs LIEF once to decode the relocations; uses fw-env's PYTHONPATH)
"""
import ctypes, os, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = 0x150000000000
OODLE_DECOMPRESS = 0x48df8a0          # OodleLZ_Decompress, x86_64 libUnreal.so
#!/usr/bin/env python3
"""Load the Android x86_64 libUnreal.so in-process (relocations pre-decoded by LIEF)
so the statically linked OodleLZ_Decompress can be called.

The Android packed relocations (SHT_ANDROID_RELA) are not understood by glibc, so
they are dumped once to relocs.bin / other_relocs.pkl by the companion step and
applied here by hand.
"""
import array, ctypes, os, pickle, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, '..', 'extract', 'x86', 'lib', 'x86_64', 'libUnreal.so')
REL = os.path.join(HERE, 'relocs.bin')
OTHER = os.path.join(HERE, 'other_relocs.pkl')
BASE = 0x150000000000
OODLE_DECOMPRESS = 0x48df8a0

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int,
                      ctypes.c_int, ctypes.c_long]
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
PROT_R, PROT_W, PROT_X = 1, 2, 4
MAP_PRIVATE, MAP_FIXED, MAP_ANON = 0x2, 0x10, 0x20


LOG_SYMS = {'fputs', 'fprintf', 'printf', 'puts', 'putchar', 'vfprintf', 'vprintf',
            '__fprintf_chk', '__printf_chk', '__vfprintf_chk', 'fputc', 'putc',
            'abort', '__assert2', '__assert_fail', 'perror'}


def resolve(name):
    if not name:
        return 0
    if name in LOG_SYMS:      # Oodle's error logging passes a NULL FILE*; stub it out
        return stub_addr()
    # proper dlsym lookup (handles data symbols such as stdout / stderr too)
    try:
        libdl = ctypes.CDLL('libdl.so.2')
        libdl.dlsym.restype = ctypes.c_void_p
        libdl.dlsym.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        a = libdl.dlsym(ctypes.c_void_p(0), name.encode())   # RTLD_DEFAULT
        if a:
            return a
    except Exception:
        pass
    for lib in (None, 'libm.so.6', 'libz.so.1'):
        try:
            o = ctypes.CDLL(lib, use_errno=True) if lib else libc
            return ctypes.cast(getattr(o, name), ctypes.c_void_p).value
        except Exception:
            pass
    try:   # C++ runtime symbols mangled through libstdc++
        o = ctypes.CDLL('libstdc++.so.6')
        return ctypes.cast(getattr(o, name), ctypes.c_void_p).value
    except Exception:
        return 0


_STUB = None
_STUB_BUF = None          # must keep the buffer alive: it holds the stub code


def stub_addr():
    global _STUB
    if _STUB is None:
        o = ctypes.CDLL(os.path.join(HERE, 'logstub.so'))
        _STUB = ctypes.cast(o.oodle_log_stub, ctypes.c_void_p).value
    return _STUB


def load():
    d = open(SO, 'rb').read()
    e_phoff = struct.unpack_from('<Q', d, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', d, 0x36)[0]
    e_phnum = struct.unpack_from('<H', d, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if struct.unpack_from('<I', d, o)[0] != 1:
            continue
        flags = struct.unpack_from('<I', d, o + 4)[0]
        p_off, p_va, _pa, p_fsz, p_msz = struct.unpack_from('<QQQQQ', d, o + 8)
        segs.append((p_va, p_off, p_fsz, p_msz, flags))
    lo = min(s[0] for s in segs) & ~0xfff
    hi = max(s[0] + s[3] for s in segs)
    span = ((hi - lo) + 0xfff) & ~0xfff
    img = bytearray(span)
    for va, off, fsz, msz, flags in segs:
        img[va - lo:va - lo + fsz] = d[off:off + fsz]
    # relative relocations
    a = array.array('q')
    a.frombytes(open(REL, 'rb').read())
    n = len(a) // 2
    mv = memoryview(img)
    for i in range(n):
        addr = a[2 * i] - lo
        if 0 <= addr < span - 8:
            struct.pack_into('<Q', img, addr, BASE + a[2 * i + 1])
    # symbol relocations
    others = pickle.load(open(OTHER, 'rb'))
    bound = {}
    unresolved = 0
    for typ, addr, sym in others:
        addr -= lo
        if not (0 <= addr < span - 8):
            continue
        if typ.endswith('JUMP_SLOT'):
            if sym not in bound:
                bound[sym] = resolve(sym) or stub_addr()
            val = bound[sym]
        elif typ.endswith('GLOB_DAT'):
            if sym not in bound:
                bound[sym] = resolve(sym) or stub_addr()
            val = bound[sym]
        elif typ.endswith('_64'):
            val = BASE + resolve(sym)
        else:
            continue
        if val == 0:
            unresolved += 1
        struct.pack_into('<Q', img, addr, val)
    r = libc.mmap(ctypes.c_void_p(BASE + lo), span, PROT_R | PROT_W | PROT_X,
                  MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0)
    if r in (0xffffffffffffffff, None):
        raise OSError('mmap failed')
    ctypes.memmove(BASE + lo, bytes(img), span)
    del img
    for va, off, fsz, msz, flags in segs:
        prot = PROT_R
        if flags & 2:
            prot |= PROT_W
        if flags & 1:
            prot |= PROT_X
        pg = (BASE + va) & ~0xfff
        sz = ((va + msz + 0xfff) & ~0xfff) - (va & ~0xfff)
        libc.mprotect(ctypes.c_void_p(pg), sz, prot)
    print("loaded: span=%#x base=%#x relocs=%d syms=%d unresolved=%d" %
          (span, BASE, n, len(bound), unresolved), flush=True)
    return BASE, lo


def oodle_fn():
    base = BASE
    F = ctypes.CFUNCTYPE(ctypes.c_void_p,
                         ctypes.c_void_p, ctypes.c_longlong, ctypes.c_void_p, ctypes.c_longlong,
                         ctypes.c_int, ctypes.c_int, ctypes.c_int,
                         ctypes.c_void_p, ctypes.c_longlong, ctypes.c_void_p, ctypes.c_void_p,
                         ctypes.c_void_p, ctypes.c_longlong, ctypes.c_int)
    return F(base + OODLE_DECOMPRESS)




def dump(so, ucas, utoc, out_path, nblocks=1408, blocktab=20016):
    import glob
    global SO, REL, OTHER
    SO = os.path.abspath(so)
    here = os.path.dirname(os.path.abspath(__file__))
    REL = os.path.join(here, '_relocs.bin')
    OTHER = os.path.join(here, '_other_relocs.pkl')
    if not os.path.exists(REL):
        import lief, array, pickle
        b = lief.parse(SO)
        rel = array.array('q'); other = []
        for r in b.relocations:
            t = str(r.type)
            if 'RELATIVE' in t:
                rel.append(r.address); rel.append(r.addend)
            else:
                try: sym = r.symbol.name
                except Exception: sym = ''
                other.append((t, r.address, sym))
        open(REL, 'wb').write(rel.tobytes())
        pickle.dump(other, open(OTHER, 'wb'))
        print("decoded %d relative / %d other relocations" % (len(rel)//2, len(other)), flush=True)
    load()
    fn = oodle_fn()
    u = open(ucas, 'rb').read()
    t = open(utoc, 'rb').read()
    u40 = lambda b: int.from_bytes(b, 'little')
    out = bytearray(); ok = raw = 0
    for i in range(nblocks):
        o = blocktab + 12 * i
        off = u40(t[o:o+5]); csz = u40(t[o+5:o+8])
        buf = ctypes.create_string_buffer(131072)
        r = fn(u[off:off+csz], csz, buf, 65536, 1, 0, 0, None, 0, None, None, None, 0, 3)
        if r:
            out += buf.raw[:65536]; ok += 1
        else:
            out += u[off:off+65536]; raw += 1
    open(out_path, 'wb').write(bytes(out))
    print("wrote %s (%d bytes) oodle=%d raw=%d" % (out_path, len(out), ok, raw))


if __name__ == '__main__':
    if len(sys.argv) < 5:
        print(__doc__); sys.exit(1)
    dump(*sys.argv[1:5])
