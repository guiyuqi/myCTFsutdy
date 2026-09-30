#!/usr/bin/env python3
"""DELTA FORGE PROTOCOL / REVISION 7 - offline solve.

Container = vector of records: uint16 BE payload length, then payload bytes.
Decrypt for sequence S with SHA256(FAMILY || parent_id || uint16be(S)) repeated.
"""
import hashlib, struct, sys, os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BASE = os.path.join(ROOT, 'work/forge/attachments/firmware/base_image.bin')
CONT = os.path.join(ROOT, 'work/forge/attachments/firmware/ecu_delta_container.bin')

FAMILY = b'GEELY-DELTA-FORGE-7'
ROOT_ID = bytes.fromhex('C64A8C1BB751D6CC')
IMAGE_SIZE = 0x2000
MAN_OFF, MAN_LEN = 0x1F00, 0x60
NSEQ = 12

MAGIC = b'\xEC\x4F'
OPS = {0xA0: 'overwrite', 0xA1: 'xor', 0xA2: 'add', 0xA3: 'rotl'}


def keystream(seed, n):
    out = b''
    while len(out) < n:
        out += hashlib.sha256(seed).digest()
    return out[:n]


def parse_records(blob):
    recs = []
    off = 0
    while off + 2 <= len(blob):
        ln = struct.unpack('>H', blob[off:off + 2])[0]
        off += 2
        if off + ln > len(blob):
            recs.append(('TRUNC', off - 2, ln, blob[off:]))
            break
        recs.append((len(recs), off - 2, ln, blob[off:off + ln]))
        off += ln
    return recs


def try_decrypt(ct, parent, seq):
    ks = keystream(FAMILY + parent + struct.pack('>H', seq), len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))


def validate(pt):
    """Return dict if pt is a well-formed patch plaintext (pre-chain check)."""
    if len(pt) < 8:
        return None
    if pt[0:2] != MAGIC:
        return None
    offset = struct.unpack('>H', pt[2:4])[0]
    op = pt[4]
    dlen = pt[5]
    if op not in OPS:
        return None
    if len(pt) != 9 + dlen:
        return None
    data = pt[6:6 + dlen]
    hint = struct.unpack('>H', pt[6 + dlen:8 + dlen])[0]
    chk = pt[8 + dlen]
    # NB: doc says "XOR checksum", implementation is 8-bit SUM mod 256 (verified on-chain)
    calc = 0
    for b in pt[:8 + dlen]:
        calc = (calc + b) & 0xFF
    if offset + dlen > IMAGE_SIZE:
        return None
    return dict(offset=offset, op=op, dlen=dlen, data=data, hint=hint,
                chk=chk, calc=calc, chk_ok=(calc == chk))


def apply_patch(img, p):
    img = bytearray(img)
    off, op, data = p['offset'], p['op'], p['data']
    for i, d in enumerate(data):
        j = off + i
        cur = img[j]
        if op == 0xA0:
            img[j] = d
        elif op == 0xA1:
            img[j] = cur ^ d
        elif op == 0xA2:
            img[j] = (cur + d) & 0xFF
        elif op == 0xA3:
            r = d % 8
            img[j] = ((cur << r) | (cur >> (8 - r))) & 0xFF if r else cur
    return bytes(img)


def main():
    base = open(BASE, 'rb').read()
    cont = open(CONT, 'rb').read()
    print(f'base_image   {len(base)} bytes  sha256={hashlib.sha256(base).hexdigest()}')
    print(f'container    {len(cont)} bytes')
    recs = parse_records(cont)
    print(f'records      {len(recs)}')
    for r in recs:
        print(f'  idx={r[0]:2d} off=0x{r[1]:04x} len={r[2]:3d} ct={r[3].hex()}')

    img = base
    parent = ROOT_ID
    chain_log = []
    used = set()
    for seq in range(1, NSEQ + 1):
        found = []
        for idx, off, ln, ct in recs:
            pt = try_decrypt(ct, parent, seq)
            p = validate(pt)
            if not p:
                continue
            img2 = apply_patch(img, p)
            dig = hashlib.sha256(FAMILY + img2 + struct.pack('>H', seq)).digest()
            hint2 = struct.unpack('>H', dig[:2])[0]
            p2 = dict(p)
            p2.update(idx=idx, seq=seq, pt=pt, chain_ok=(hint2 == p['hint']),
                      digest=dig, img_after=img2)
            found.append(p2)
        good = [f for f in found if f['chk_ok'] and f['chain_ok']]
        print(f'\n=== SEQ {seq} (parent={parent.hex()}) ===')
        for f in found:
            print(f'  cand idx={f["idx"]:2d} off=0x{f["offset"]:04x} op=0x{f["op"]:02x}'
                  f'({OPS[f["op"]]}) len={f["dlen"]} data={f["data"].hex()}'
                  f' chk={f["chk"]:02x}/{f["calc"]:02x}:{"OK" if f["chk_ok"] else "BAD"}'
                  f' hint={f["hint"]:04x} expect={struct.unpack(">H", f["digest"][:2])[0]:04x}'
                  f':{"OK" if f["chain_ok"] else "BAD"}')
        if len(good) != 1:
            print(f'  !! {len(good)} fully-valid candidates at seq {seq}; stopping')
            if not good:
                break
        g = good[0]
        img = g['img_after']
        parent = g['digest'][:8]
        used.add(g['idx'])
        chain_log.append(g)
        print(f'  -> APPLIED idx={g["idx"]} off=0x{g["offset"]:04x} op={OPS[g["op"]]}'
              f' data={g["data"].hex()}  newparent={parent.hex()}')

    print(f'\nused record indices ({len(used)}): {sorted(used)}')
    print(f'decoys: {sorted(set(r[0] for r in recs) - used)}')
    print(f'final image sha256 = {hashlib.sha256(img).hexdigest()}')

    # manifest
    mk = hashlib.sha256(FAMILY + base[:MAN_OFF] + struct.pack('>H', NSEQ) + b'MANIFEST').digest()
    print(f'\nMANIFEST_KEY = {mk.hex()}')
    for label, src in (('final_image', img), ('base_image', base)):
        ct = src[MAN_OFF:MAN_OFF + MAN_LEN]
        pt = bytes(a ^ b for a, b in zip(ct, keystream(mk, MAN_LEN)))
        stripped = pt.rstrip(b'\xA5')
        print(f'\n--- manifest from {label} ---')
        print(f'  ct   = {ct.hex()}')
        print(f'  xored= {pt.hex()}')
        print(f'  strip= {stripped.hex()}')
        try:
            print(f'  ascii= {stripped.decode("utf-8", "replace")!r}')
        except Exception:
            pass

    open(os.path.join(ROOT, 'work/forge/final_image.bin'), 'wb').write(img)
    print('\nwrote work/forge/final_image.bin')


if __name__ == '__main__':
    main()
