#!/usr/bin/env python3
"""DELTA FORGE - independent clean-room verification.

Recomputes the whole chain from the raw attachment and extracts the flag.
Nothing is copied from the exploratory scripts.
"""
import hashlib, struct, sys, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_F = os.path.join(ROOT, 'work/forge/attachments/firmware/base_image.bin')
CONT_F = os.path.join(ROOT, 'work/forge/attachments/firmware/ecu_delta_container.bin')

FAMILY = b'GEELY-DELTA-FORGE-7'
ROOT_ID = bytes.fromhex('C64A8C1BB751D6CC')
MAN_OFF, MAN_LEN = 0x1F00, 0x60

base = open(BASE_F, 'rb').read()
cont = open(CONT_F, 'rb').read()

# --- container: vector of uint16 BE length-prefixed records ---
records, off = [], 0
while off + 2 <= len(cont):
    n = struct.unpack('>H', cont[off:off + 2])[0]
    off += 2
    records.append(cont[off:off + n])
    off += n

def stream_key(*parts, n):
    """keystream = SHA256(parts...) repeated to n bytes"""
    d = hashlib.sha256(b''.join(parts)).digest()
    return (d * (n // len(d) + 1))[:n]

def parse_patch(pt):
    if len(pt) < 9 or pt[0:2] != b'\xEC\x4F':
        return None
    offset = struct.unpack('>H', pt[2:4])[0]
    op, dlen = pt[4], pt[5]
    if op not in (0xA0, 0xA1, 0xA2, 0xA3) or len(pt) != 9 + dlen:
        return None
    return dict(offset=offset, op=op, data=pt[6:6 + dlen],
                hint=struct.unpack('>H', pt[6 + dlen:8 + dlen])[0],
                chk=pt[8 + dlen], calc=sum(pt[:8 + dlen]) & 0xFF)

def apply_patch(img, p):
    img = bytearray(img)
    for i, d in enumerate(p['data']):
        j = p['offset'] + i
        c = img[j]
        img[j] = {0xA0: d, 0xA1: c ^ d, 0xA2: (c + d) & 0xFF,
                  0xA3: ((c << (d % 8)) | (c >> (8 - (d % 8)))) & 0xFF if d % 8 else c}[p['op']]
    return bytes(img)

img, parent, chain = base, ROOT_ID, []
for seq in range(1, 13):
    hits = []
    for idx, ct in enumerate(records):
        pt = bytes(a ^ b for a, b in zip(
            ct, stream_key(FAMILY, parent, struct.pack('>H', seq), n=len(ct))))
        p = parse_patch(pt)
        if not p or p['chk'] != p['calc']:
            continue
        after = apply_patch(img, p)
        dig = hashlib.sha256(FAMILY + after + struct.pack('>H', seq)).digest()
        if struct.unpack('>H', dig[:2])[0] != p['hint']:
            continue
        hits.append((idx, p, after, dig))
    assert len(hits) == 1, f'seq {seq}: {len(hits)} candidates'
    idx, p, after, dig = hits[0]
    chain.append((seq, idx, p))
    img, parent = after, dig[:8]

print(f'records={len(records)}  real chain={len(chain)}  '
      f'used={[c[1] for c in chain]}  decoys={sorted(set(range(len(records)))-set(c[1] for c in chain))}')
print(f'final image sha256 = {hashlib.sha256(img).hexdigest()}')

# --- manifest: XOR with repeating MANIFEST_KEY ---
mk = hashlib.sha256(FAMILY + base[:MAN_OFF] + struct.pack('>H', 12) + b'MANIFEST').digest()
print(f'MANIFEST_KEY = {mk.hex()}')

ct = base[MAN_OFF:MAN_OFF + MAN_LEN]
ks = (mk * (MAN_LEN // len(mk) + 1))[:MAN_LEN]
pt = bytes(a ^ b for a, b in zip(ct, ks))
manifest = pt.rstrip(b'\xA5')
print(f'manifest raw   = {pt.hex()}')
print(f'manifest strip = {manifest!r}')

flag = manifest.decode()
if 'GEELY{' in flag:
    f = flag[flag.index('GEELY{'):flag.index('}') + 1]
    print(f'\n>>> FLAG = {f}')
