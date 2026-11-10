#!/usr/bin/env python3
"""g9 broad payload brute: keystream-prefix oracle + AEAD sweep over many key/nonce/layout candidates."""
import pickle, hashlib, hmac, itertools, sys
sys.path.append('/tmp/kpylib')
from Crypto.Cipher import AES, ChaCha20, ChaCha20_Poly1305

d = pickle.load(open('work/diag.pkl','rb'))
known = pickle.load(open('shared/known3.pkl','rb'))
se = pickle.load(open('shared/se.pkl','rb'))
payload = d['payload']
config = d['config']
slots = d['slots']  # (ts, slot, ek)
hslots = d['hslots']

P = b'BCM-DIAG-KDF-v1'
A = b'BCM-DIAG-PAYLOAD'
C = b'BCM/DIAG/ACK/v1'

def H(x, n=32):
    return hashlib.sha256(x).digest()[:n]

def kdf_hkdf(ikm, salt=b'', info=b'', n=32):
    prk = hmac.new(salt if salt else b'\x00'*32, ikm, hashlib.sha256).digest()
    okm = b''
    t = b''
    i = 1
    while len(okm) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:n]

def expand(x, n=96):
    """produce n bytes of keystream-ish output from x"""
    out = b''
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(x + ctr.to_bytes(4,'big')).digest()
        ctr += 1
    return out[:n]

mats = {}
def add(name, val):
    if isinstance(val, str): val = val.encode()
    if isinstance(val, (bytes, bytearray)) and 0 < len(val) <= 4096:
        mats[name] = bytes(val)

infos = known['info']
for sl in (3,9,14):
    inf = infos[sl]
    for f in ('K','K_fin','m','tag','ct','ek'):
        if f=='K_fin':
            add(f'{f}{sl}', hashlib.shake_256(inf['K']+hashlib.sha3_256(inf['ct']).digest()).digest(32))
        else:
            add(f'{f}{sl}', inf[f])
    add(f'rho{sl}', inf['ek'][-32:])
    add(f'ts_be{sl}', inf['ts'].to_bytes(4,'big'))
    add(f'ts_le{sl}', inf['ts'].to_bytes(4,'little'))
    add(f'slot{sl}', bytes([sl]))
add('P',P); add('A',A); add('C',C)
add('config', config)
for tok in config.split(b'\n'):
    if b'=' in tok:
        k,v = tok.split(b'=',1)
        add('cfg_'+k.decode(errors='replace'), v)
# s/e encodings
sc = se['s_coeff']; ec = se['e_coeff']
add('s_coeff_u8', bytes((c % 256) for c in sc))
add('s_coeff_i16le', b''.join(int(c).to_bytes(2,'little',signed=True) for c in sc))
add('s_coeff_q16le', b''.join((c % 3329).to_bytes(2,'little') for c in sc))
add('s_ntt_u8', bytes((c % 256) for c in sum(se['s_ntt'],[])))
add('s_str', ','.join(str(c) for c in sc).encode())
if isinstance(ec, dict):
    for sl, e in ec.items():
        if isinstance(e, list) and e and not isinstance(e[0], list):
            add(f'e_u8_{sl}', bytes((c%256) for c in e))
# combos
for perm in itertools.permutations((3,9,14)):
    add('Kfin_cat_'+''.join(map(str,perm)), b''.join(hashlib.shake_256(infos[s]['K']+hashlib.sha3_256(infos[s]['ct']).digest()).digest(32) for s in perm))
    add('K_cat_'+''.join(map(str,perm)), b''.join(infos[s]['K'] for s in perm))
    add('m_cat_'+''.join(map(str,perm)), b''.join(infos[s]['m'] for s in perm))
add('Kfin_xor', bytes(a^b^c for a,b,c in zip(*[hashlib.shake_256(infos[s]['K']+hashlib.sha3_256(infos[s]['ct']).digest()).digest(32) for s in (3,9,14)])))
add('K_xor', bytes(a^b^c for a,b,c in zip(*[infos[s]['K'] for s in (3,9,14)])))
add('m_xor', bytes(a^b^c for a,b,c in zip(*[infos[s]['m'] for s in (3,9,14)])))
# hashes of materials as extra materials
base = dict(mats)
for n,v in base.items():
    if n.startswith(('K','K_fin','m','tag','cdot')) or n in ('P','A','C','config') or n.startswith('s_') or n in ('Kfin_cat_396','K_cat_396','m_cat_396'):
        add('sha256_'+n, hashlib.sha256(v).digest())
        add('sha3_'+n, hashlib.sha3_256(v).digest())

streams = {}
def addstr(name, fn):
    streams[name] = fn

addstr('raw', lambda x: (x*((96//max(1,len(x)))+1))[:96])
addstr('sha256ctr_be', lambda x: expand(x,96))
addstr('sha256ctr_le', lambda x: b''.join(hashlib.sha256(x+i.to_bytes(4,'little')).digest() for i in range(3)))
addstr('sha3ctr', lambda x: b''.join(hashlib.sha3_256(x+i.to_bytes(4,'big')).digest() for i in range(3)))
addstr('shake256', lambda x: hashlib.shake_256(x).digest(96))
addstr('shake256P', lambda x: hashlib.shake_256(P+x+A).digest(96))
addstr('shake256xP', lambda x: hashlib.shake_256(x+P).digest(96))
addstr('hkdf_saltP_infoA', lambda x: kdf_hkdf(x,P,A,96))
addstr('hkdf_saltA_infoP', lambda x: kdf_hkdf(x,A,P,96))
addstr('hkdf_salt0_infoA', lambda x: kdf_hkdf(x,b'',A,96))
addstr('hkdf_saltP_info0', lambda x: kdf_hkdf(x,P,b'',96))
addstr('hmac_ctr_be', lambda x: b''.join(hmac.new(x,i.to_bytes(4,'big'),hashlib.sha256).digest() for i in range(3)))
addstr('hmac_ctr_le', lambda x: b''.join(hmac.new(x,i.to_bytes(4,'little'),hashlib.sha256).digest() for i in range(3)))
addstr('hmac_P_msg_x', lambda x: b''.join(hmac.new(P,x+i.to_bytes(4,'big'),hashlib.sha256).digest() for i in range(3)))

hits = []
target0 = b'flag{'
for name, x in mats.items():
    for sname, fn in streams.items():
        try:
            ks = fn(x)
        except Exception:
            continue
        for off in range(0, 20):
            if off+5 <= len(payload):
                pt = bytes(payload[i] ^ ks[off+i] for i in range(off, min(len(payload), len(ks))))
                if target0 in pt.lower():
                    hits.append(('STREAM', name, sname, off, pt))
print('stream hits:', len(hits))
for h in hits[:20]: print(h)

# ---- AEAD sweep ----
hits2 = []
lay = []
lay.append((None, payload[:-16], payload[-16:], 'tail16'))
lay.append((payload[:12], payload[12:-16], payload[-16:], 'pre12'))
lay.append((payload[:16], payload[16:-16], payload[-16:], 'pre16'))
lay.append((payload[:24], payload[24:-16], payload[-16:], 'pre24'))
lay.append((payload[-12:], payload[:-16], payload[-16:], 'post12'))

aads = {b'':'', A:'A', P:'P', C:'C', config:'config', P+A:'P+A', A+C:'A+C'}
noncepool = {b'\x00'*12:'zero12', b'\x00'*16:'zero16', b'\x00'*8:'zero8', b'\x00'*24:'zero24'}
for nm, v in list(mats.items()):
    for pre in (0,):
        if len(v) >= 12: noncepool[v[:12]] = nm+':pre12'
        if len(v) >= 8: noncepool[v[:8]] = nm+':pre8'
    noncepool[hashlib.sha256(v).digest()[:12]] = 'sha256('+nm+')12'
    noncepool[hashlib.sha3_256(v).digest()[:12]] = 'sha3('+nm+')12'
print('mats', len(mats), 'nonces', len(noncepool))
count = 0
keys = []
for km, kval in mats.items():
    for key in (kval[:32], kval[:16], hashlib.sha256(kval).digest(), hashlib.sha3_256(kval).digest(), hashlib.sha512(kval).digest()[:32]):
        if len(key) in (16,24,32): keys.append((km, key))
print('keys', len(keys))
def try_all(key, nonce, aad, ct, tag, tagdesc):
    global count
    count += 1
    try:
        c = AES.new(key, AES.MODE_GCM, nonce=nonce); c.update(aad)
        pt = c.decrypt_and_verify(ct, tag)
        hits2.append(('AESGCM', len(key), aad, nonce.hex()[:24], tagdesc, pt))
    except Exception: pass
    if len(nonce) in (8,12):
        try:
            c = ChaCha20_Poly1305.new(key=key, nonce=nonce); c.update(aad)
            pt = c.decrypt_and_verify(ct, tag)
            hits2.append(('CHACHA', len(key), aad, nonce.hex()[:24], tagdesc, pt))
        except Exception: pass
# pass 1: inline layout nonces + zero
for km, key in keys:
    for cn, ct, tag, desc in lay:
        for aad in aads:
            try_all(key, cn if cn is not None else b'\x00'*12, aad, ct, tag, desc)
    for nv, nn in ((b'\x00'*8,'z8'),(b'\x00'*12,'z12'),(b'\x00'*16,'z16')):
        ct, tag = payload[:-16], payload[-16:]
        for aad in aads:
            try_all(key, nv, aad, ct, tag, 'flat:'+nn)
# pass 2: nonce pool with flat layout
for km, key in keys:
    ct, tag = payload[:-16], payload[-16:]
    for nv, nn in noncepool.items():
        for aad in (b'', A, P):
            try_all(key, nv, aad, ct, tag, 'flat:'+nn)
print('aead tried', count, 'hits', len(hits2))
for h in hits2[:40]: print(h)
