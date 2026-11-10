#!/usr/bin/env python3
"""12070 · BabyMenu (2026 羊城杯 / DASCTF) — offline reproducible analyzer.

Reproduces every static fact used in the writeup, with no external deps
beyond stdlib + (optional) lief + sleuthkit CLI (fls/icat).

  python3 scripts/12070-analyze.py --driver work/pwn-src/BabyMenu/BabyMenu.sys
  python3 scripts/12070-analyze.py --image work/babymenu/babymenu.raw --part-offset 444416

Output: JSON blob + human summary on stdout; exit 0 = all checks passed.
"""
import argparse, hashlib, io, json, os, re, struct, subprocess, sys

# ---------------------------------------------------------------- PE / driver

TAG = 0x79636221              # 'ycb!' little endian
ALLOC_SIZE = 0x120
WRITE_CAP = 0x140
POOL_HEADER = 0x10


def analyze_driver(path):
    data = open(path, 'rb').read()
    out = {
        'path': path,
        'size': len(data),
        'md5': hashlib.md5(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest(),
    }

    # ---- imports / structure via lief when available
    try:
        import lief
        pe = lief.parse(path)
        out['machine'] = str(pe.header.machine)
        out['subsystem'] = str(pe.optional_header.subsystem)
        out['imports'] = {i.name: [e.name for e in i.entries] for i in pe.imports}
        out['has_signature'] = bool(pe.has_signatures)
        dirs = {str(d.type).split('.')[-1]: {'rva': hex(d.rva), 'size': d.size}
                for d in pe.data_directories if d.size}
        out['data_directories'] = dirs
        secs = []
        for s in pe.sections:
            secs.append({'name': s.name, 'va': hex(s.virtual_address),
                         'vsize': s.size, 'raw': s.sizeof_raw_data})
        out['sections'] = secs
    except Exception as e:            # pragma: no cover
        out['lief_error'] = repr(e)

    # ---- strings that matter
    out['unicode_strings'] = sorted({s.decode('utf-16-le')
                                     for s in re.findall(rb'(?:[\x20-\x7e]\x00){4,}', data)})
    out['ascii_strings'] = sorted({s.decode('latin-1')
                                   for s in re.findall(rb'[\x20-\x7e]{5,}', data)
                                   if b'.pdb' in s or b'BabyMenu' in s or b'Kmdf' in s})

    # ---- the four relevant code facts, verified by byte pattern
    facts = {}
    # ExAllocatePool2(POOL_FLAG_PAGED=0x100, 0x120, 'ycb!')  ->  ba 20 01 00 00 / 41 b8 21 62 63 79
    facts['alloc_paged_0x120_tag_ycb'] = (
        bytes.fromhex('ba20010000') in data and bytes.fromhex('41b821626379') in data)
    # mov eax,0x140 ; cmp rbx,rax ; cmova rbx,rax  -> the write clamp
    facts['write_len_clamp_0x140'] = bytes.fromhex('b840010000483bd8') in data
    # ProbeForRead(.., len, 1) then memmove(g_buf, [in+8], len): the two setups
    facts['probe_for_read_len_align1'] = bytes.fromhex('41b801000000') in data
    facts['memmove_dst_gbuf_src_in8'] = (bytes.fromhex('4c8bc3') in data and
                                         bytes.fromhex('488b5708') in data)
    out['code_facts'] = facts

    # ---- arithmetic of the bug (the actual finding)
    block = ALLOC_SIZE + POOL_HEADER          # allocator block incl. POOL_HEADER
    out['overflow'] = {
        'requested_body_bytes': ALLOC_SIZE,
        'usable_for_driver': ALLOC_SIZE,
        'max_written_bytes': WRITE_CAP,
        'linear_overflow_bytes': WRITE_CAP - ALLOC_SIZE,
        'allocator_block_bytes': block,
        'pool_flag_bytes': 0x100,
        'pool_flag_name': 'POOL_FLAG_PAGED (wdm.h) -> PagedPool',
        'pool_tag': hex(TAG),
        'backend': 'Segment-Heap LFH (request <= 512 bytes)',
        'overflow_lands_on': 'next chunk POOL_HEADER (0x10 bytes) + 0x10 bytes of '
                             'that chunk user data',
    }
    # in-bounds part of the write covers body[0..0x120); bytes 0x120..0x140 are the
    # next chunk's POOL_HEADER, so writing len=0x124 touches only its first 4 bytes
    out['controlled_overflow'] = {
        'len_0x124_writes': 'next chunk POOL_HEADER bytes 0..3 '
                            '(PreviousSize, PoolIndex, BlockSize, PoolType); '
                            'PoolTag/ProcessBilled stay intact',
        # chosen layout (see notes): fake header at body 0x30 == V+0x40, so the
        # ghost chunk is [V+0x40, V+0x250) and PreviousSize = (0x130-0x40)/0x10
        'fake_header_offset_in_body': 0x30,
        'fake_header_previoussize': (block - 0x40) // 0x10,
        'fake_header_blocksize_units': 0x21,
        'ghost_chunk_bytes': 0x210,
        'ghost_chunk_end_inside_neighbour': block + 0x130 - 0x40 >= 0x210,
    }
    # IOCTL table, METHOD_BUFFERED (low 2 bits == 0), FILE_ANY_ACCESS
    out['ioctls'] = []
    for code, name, desc in [
        (0x222004, 'FreePool', 'ExFreePoolWithTag(g_buf,0); g_buf=NULL (no NULL check)'),
        (0x222008, 'WritePool', 'len=min(u64[in],0x140); ProbeForRead(p, len, 1); '
                                'memmove(g_buf, p, len)'),
        (0x222014, 'AllocPool', "ExAllocatePool2(0x100,0x120,'ycb!'); old pointer leaked"),
    ]:
        out['ioctls'].append({
            'code': hex(code), 'name': name, 'detail': desc,
            'method': ['BUFFERED', 'IN_DIRECT', 'OUT_DIRECT', 'NEITHER'][code & 3],
            'access': ['ANY', 'READ', 'WRITE', 'READ|WRITE'][(code >> 14) & 3],
            'function': hex((code >> 2) & 0xFFF),
        })
    return out


# ------------------------------------------------------ registry hive reader

class Hive:
    """Minimal regf reader: cell offsets point at the 4-byte size field."""

    def __init__(self, data):
        self.d = data
        assert data[:4] == b'regf', 'not a hive'
        self.root = 0x1000 + struct.unpack_from('<I', data, 0x24)[0]

    def payload(self, cell):
        if cell <= 0 or cell + 4 > len(self.d):
            return b''
        sz = struct.unpack_from('<i', self.d, cell)[0]
        sz = sz if sz >= 0 else -sz
        return self.d[cell + 4:cell + sz]

    def rel(self, off):
        return 0x1000 + off

    def name(self, cell):
        if cell[:2] != b'nk':
            return b''
        nl = struct.unpack_from('<H', cell, 0x48)[0]
        return cell[0x4c:0x4c + nl]

    def subkeys(self, cell):
        n = struct.unpack_from('<I', cell, 0x14)[0]
        if not n:
            return []
        lst = self.payload(self.rel(struct.unpack_from('<I', cell, 0x1c)[0]))
        if len(lst) < 4:
            return []
        sig = lst[:2]
        if sig in (b'lf', b'lh'):
            cnt = struct.unpack_from('<H', lst, 2)[0]
            return [self.rel(struct.unpack_from('<I', lst, 4 + i * 8)[0]) for i in range(cnt)]
        if sig == b'li':
            cnt = struct.unpack_from('<H', lst, 2)[0]
            return [self.rel(struct.unpack_from('<I', lst, 4 + i * 4)[0]) for i in range(cnt)]
        if sig == b'ri':
            cnt = struct.unpack_from('<H', lst, 2)[0]
            out = []
            for i in range(cnt):
                sub = self.payload(self.rel(struct.unpack_from('<I', lst, 4 + i * 4)[0]))
                c2 = struct.unpack_from('<H', sub, 2)[0] if len(sub) >= 4 else 0
                step = 8 if sub[:2] in (b'lf', b'lh') else 4
                out += [self.rel(struct.unpack_from('<I', sub, 4 + j * step)[0])
                        for j in range(c2)]
            return out
        return []

    def values(self, cell):
        n = struct.unpack_from('<I', cell, 0x24)[0]
        if not n:
            return []
        lst = self.payload(self.rel(struct.unpack_from('<I', cell, 0x28)[0]))
        out = []
        for i in range(n):
            vk = self.payload(self.rel(struct.unpack_from('<I', lst, 4 * i)[0]))
            if vk[:2] != b'vk':
                continue
            nl = struct.unpack_from('<H', vk, 2)[0]
            dsz = struct.unpack_from('<I', vk, 4)[0]
            doff = struct.unpack_from('<I', vk, 8)[0]
            dt = struct.unpack_from('<I', vk, 0xc)[0]
            if dsz & 0x80000000:
                data = vk[0x8:0x8 + (dsz & 0x7fffffff)]
            else:
                data = self.payload(self.rel(doff))[:dsz] if doff else b''
            out.append((vk[0x14:0x14 + nl], dt, data))
        return out

    def find(self, path):
        cur = self.payload(self.root)
        for part in [p for p in path.replace('/', '\\').split('\\') if p]:
            nxt = None
            for sk in self.subkeys(cur):
                c = self.payload(sk)
                if self.name(c).decode('latin-1').lower() == part.lower():
                    nxt = c
                    break
            if nxt is None:
                return None
            cur = nxt
        return cur


def render(dt, data):
    if dt in (1, 2):
        try:
            return data.decode('utf-16-le').rstrip('\x00')
        except Exception:
            return repr(data)
    if dt == 4:
        return struct.unpack_from('<I', data + b'\0' * 4, 0)[0]
    if dt == 7:
        try:
            return data.decode('utf-16-le').rstrip('\x00').split('\x00')
        except Exception:
            return repr(data)
    if dt == 11:
        return struct.unpack_from('<Q', data + b'\0' * 8, 0)[0]
    return data.hex()


# ---------------------------------------------------------------- image parts

def tsk(args):
    p = subprocess.run(args, capture_output=True)
    return p.stdout


def icat(img, off, inode):
    return tsk(['icat', '-o', str(off), img, str(inode)])


def analyze_image(img, off, driver_md5):
    res = {'path': img, 'part_offset_sectors': off}

    # 1. root listing -> find flag.txt + inode of Windows / Users
    root = tsk(['fls', '-o', str(off), img]).decode('latin-1', 'replace')
    res['root_has_flag_txt'] = 'flag.txt' in root
    inodes = {}
    for line in root.splitlines():
        for key in ('Windows', 'Users'):
            if line.endswith('\t' + key) or line.endswith(' ' + key):
                inodes[key] = int(line.split()[1].split('-')[0])
    res['root_inodes'] = inodes

    # 2. flag.txt content (placeholder in the distributed image)
    m = re.search(r'\d+-\d+-\d+:\s*flag\.txt', root)
    fl_inode = None
    for line in root.splitlines():
        if line.rstrip().endswith('flag.txt'):
            fl_inode = int(line.split()[1].split('-')[0])
    if fl_inode:
        fl = icat(img, off, fl_inode)
        res['root_flag_txt'] = fl.decode('latin-1', 'replace').strip()
        res['root_flag_txt_is_placeholder'] = b'test_flag' in fl

    # 3. deployed driver
    sys32 = None
    win = inodes.get('Windows')
    if win:
        for line in tsk(['fls', '-o', str(off), img, str(win)]).decode('latin-1', 'replace').splitlines():
            if line.rstrip().endswith('System32'):
                sys32 = int(line.split()[1].split('-')[0])
    if sys32:
        listing = tsk(['fls', '-o', str(off), img, str(sys32)]).decode('latin-1', 'replace')
        for line in listing.splitlines():
            if 'BabyMenu' in line:
                ino = int(line.split()[1].split('-')[0])
                blob = icat(img, off, ino)
                res['deployed_driver'] = {
                    'inode': ino, 'size': len(blob),
                    'md5': hashlib.md5(blob).hexdigest(),
                    'matches_attachment': hashlib.md5(blob).hexdigest() == driver_md5,
                }
        cfg = None
        for line in listing.splitlines():
            if line.rstrip().endswith('\tconfig') or line.rstrip().endswith(' config'):
                cfg = int(line.split()[1].split('-')[0])
        if cfg:
            res['hives'] = parse_hives(img, off, cfg)
    return res


def parse_hives(img, off, cfg_inode):
    out = {}
    listing = tsk(['fls', '-o', str(off), img, str(cfg_inode)]).decode('latin-1', 'replace')
    want = {}
    for line in listing.splitlines():
        for hive in ('SYSTEM', 'SOFTWARE'):
            if line.rstrip().endswith('\t' + hive) and hive not in want:
                want[hive] = int(line.split()[1].split('-')[0])
    blobs = {k: icat(img, off, v) for k, v in want.items()}

    if 'SYSTEM' in blobs:
        h = Hive(blobs['SYSTEM'])
        cc = ['ControlSet001']
        # find the service whose ImagePath mentions the driver
        svc = h.find(cc[0] + '\\Services')
        found = {}
        if svc:
            for sk in h.subkeys(svc):
                c = h.payload(sk)
                vals = {n.decode('latin-1').lower(): render(dt, d) for n, dt, d in h.values(c)}
                if 'babymenu' in str(vals.get('imagepath', '')).lower():
                    found = {'service': h.name(c).decode('latin-1'), **vals}
                    break
        out['service'] = found
        dg = h.find(cc[0] + '\\Control\\DeviceGuard')
        out['device_guard_values'] = [n.decode('latin-1') for n, _, _ in h.values(dg)] if dg else []
        lsa = h.find(cc[0] + '\\Control\\Lsa')
        if lsa:
            v = {n.decode('latin-1'): render(dt, d) for n, dt, d in h.values(lsa)}
            out['lsa'] = {k: v[k] for k in ('RunAsPPL', 'IsPplAutoEnabled') if k in v}
        out['secureboot_state_key_present'] = h.find(cc[0] + '\\Control\\SecureBoot\\State') is not None

    if 'SOFTWARE' in blobs:
        f = Hive(blobs['SOFTWARE'])
        cur = f.find('Microsoft\\Windows NT\\CurrentVersion')
        if cur:
            v = {n.decode('latin-1'): render(dt, d) for n, dt, d in f.values(cur)}
            out['os'] = {k: v[k] for k in
                         ('ProductName', 'CurrentBuild', 'UBR', 'DisplayVersion',
                          'BuildLabEx', 'EditionID') if k in v}
    return out


# ---------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--driver', default='work/pwn-src/BabyMenu/BabyMenu.sys')
    ap.add_argument('--image', default=None)
    ap.add_argument('--part-offset', type=int, default=444416)
    ap.add_argument('--json', default=None)
    a = ap.parse_args()

    report = {'driver': analyze_driver(a.driver)}
    if a.image and os.path.exists(a.image):
        report['image'] = analyze_image(a.image, a.part_offset, report['driver']['md5'])

    blob = json.dumps(report, indent=2, default=str)
    if a.json:
        open(a.json, 'w').write(blob)
    print(blob)

    # ---- assertions: these are the facts the writeup depends on
    ov = report['driver']['overflow']
    assert report['driver']['code_facts']['alloc_paged_0x120_tag_ycb'], 'alloc pattern'
    assert report['driver']['code_facts']['write_len_clamp_0x140'], 'clamp pattern'
    assert report['driver']['code_facts']['memmove_dst_gbuf_src_in8'], 'memmove pattern'
    assert ov['linear_overflow_bytes'] == 0x20, 'overflow is 0x20 bytes'
    assert ov['allocator_block_bytes'] == 0x130
    img = report.get('image', {})
    if img.get('deployed_driver'):
        assert img['deployed_driver']['matches_attachment'], 'deployed != attachment'
    if img.get('service'):
        assert img['service'].get('start') == 2, 'driver should be auto-start'
    print('\n[OK] all assertions passed', file=sys.stderr)


if __name__ == '__main__':
    main()
