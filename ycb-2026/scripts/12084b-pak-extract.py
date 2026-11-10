#!/usr/bin/env python3
"""UE5 .pak (version 11) 解包器：解析 FPakInfo / EncodedPakEntries / FullDirectoryIndex，
按文件名导出任意 entry。零第三方依赖。
用法: 12084b-pak-extract.py <pak> [名字子串 ...]
      12084b-pak-extract.py <pak> --list
默认导出 CTFGame/Content/Data/p.bin 到 ./p.bin
实测目标: CTFGame-Android_ASTC.pak (4,625,819 B, ver 11, 1397 entries)
"""
import struct, sys, hashlib, os

def load(path):
    d = open(path, 'rb').read()
    mo = d.rfind(b'\xe1\x12\x6f\x5a')          # FPakInfo magic 0x5A6F12E1 (LE)
    magic, ver = struct.unpack_from('<Ii', d, mo)
    assert magic == 0x5A6F12E1
    io, isz = struct.unpack_from('<qq', d, mo + 8)
    # ver>=8: 20B index hash 之后是 5 个 32B 压缩方法名槽（本 build 无加密/GUID 字段，
    # 40+160=204B 正好到 EOF，实测验证）
    p = io
    n = struct.unpack_from('<i', d, p)[0]; mp = d[p+4:p+4+n].rstrip(b'\0').decode(); p += 4+n
    num = struct.unpack_from('<i', d, p)[0]; p += 4
    p += 8                                      # pathHashSeed u64
    hasPH = struct.unpack_from('<i', d, p)[0]; p += 4
    if hasPH: p += 36                           # i64 off, i64 size, 20B sha1
    hasFD = struct.unpack_from('<i', d, p)[0]; p += 4
    fdo, fds = struct.unpack_from('<qq', d, p); p += 16
    p += 20
    esz = struct.unpack_from('<i', d, p)[0]; p += 4
    enc = d[p:p+esz]                            # EncodedPakEntries blob
    return dict(d=d, ver=ver, mount=mp, num=num, enc=enc, fdo=fdo, fds=fds)

def decode_entry(enc, pos):
    """u32 header | u32 offset | u32 usize (+ u32 size + bc*u32 blockSizes if compressed)
    header: b31..29 flags(7) b28..23 method(0=None,1=Oodle) b22 enc b21..6 blockCount b5..0 blockSize>>11"""
    h = struct.unpack_from('<I', enc, pos)[0]; p = pos + 4
    flags = (h >> 29) & 7; method = (h >> 23) & 0x3f; encrypted = (h >> 22) & 1
    bc = (h >> 6) & 0xffff; bs = (h & 0x3f) << 11
    if method == 0:
        off, size = struct.unpack_from('<II', enc, p); p += 8
        usize = size; blocks = []
    else:
        off, usize, size = struct.unpack_from('<III', enc, p); p += 12
        n = bc if bs else 0
        blocks = [struct.unpack_from('<I', enc, p + 4*k)[0] for k in range(n)]; p += 4*n
    return dict(method=method, encrypted=encrypted, off=off, usize=usize, size=size,
                blocks=blocks, nextpos=p)

def dir_index(pk):
    d = pk['d']; p = pk['fdo']; end = p + pk['fds']
    def rf(p):
        n = struct.unpack_from('<i', d, p)[0]; p += 4
        if n < 0: s = d[p:p-2*n].decode('utf-16-le'); p += -2*n
        else:     s = d[p:p+n].decode('utf8');        p += n
        return s.rstrip('\0'), p
    nd = struct.unpack_from('<i', d, p)[0]; p += 4
    files = []
    for _ in range(nd):
        dn, p = rf(p)
        nf = struct.unpack_from('<i', d, p)[0]; p += 4
        for _ in range(nf):
            fn, p = rf(p)
            loc = struct.unpack_from('<i', d, p)[0]; p += 4
            files.append(((dn.rstrip('/') + '/' + fn) if dn else fn, loc))
    assert p == end, (p, end)          # 结构自检
    return files

def main():
    pak = sys.argv[1]
    pk = load(pak)
    files = dir_index(pk)
    print('# mount=%r numEntries=%d files=%d encodedEntries=%dB' %
          (pk['mount'], pk['num'], len(files), len(pk['enc'])))
    if '--list' in sys.argv:
        for n, l in files: print(l, n)
        return
    names = [a for a in sys.argv[2:] if not a.startswith('--')] or ['Content/Data/p.bin']
    d = pk['d']
    for sub in names:
        hit = [(n, l) for n, l in files if sub.lower() in n.lower()]
        for n, l in hit:
            e = decode_entry(pk['enc'], l)
            data = d[e['off']:e['off']+e['size']]
            out = os.path.basename(n.rstrip('/'))
            open(out, 'wb').write(data)
            print('%-60s loc=%-6d method=%d off=%-8d size=%-7d usize=%-7d -> %s (md5 %s)%s' % (
                n, l, e['method'], e['off'], e['size'], e['usize'], out,
                hashlib.md5(data).hexdigest(),
                '' if e['method'] == 0 else '  [需 Oodle 解压: %d blocks]' % len(e['blocks'])))

if __name__ == '__main__':
    main()
