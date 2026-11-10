import hashlib, pickle, itertools, sys
from Crypto.Cipher import AES, ChaCha20_Poly1305

hs = pickle.load(open('shared/hs.pkl','rb'))
d = open('work/ext_etc_bcm_diag.bin','rb').read()
payload = d[0x9208:0x9208+75]
PREFIX = b'BCM-DIAG-KDF-v1'
AAD = b'BCM-DIAG-PAYLOAD'
ACK = b'BCM/DIAG/ACK/v1'

def sha256(x): return hashlib.sha256(x).digest()
def sha3_256(x): return hashlib.sha3_256(x).digest()
def shake256(x,n=32): return hashlib.shake_256(x).digest(n)
def hkdf(ikm, salt=b'', info=b'', n=32):
    if salt == b'': salt = b'\x00'*32
    prk = __import__('hmac').new(salt, ikm, hashlib.sha256).digest()
    okm=b''; t=b''; i=1
    while len(okm)<n:
        t = __import__('hmac').new(prk, t+info+bytes([i]), hashlib.sha256).digest()
        okm+=t; i+=1
    return okm[:n]

def candidates(tag, slot, ek, ct):
    base = {}
    base['raw'] = tag
    for nm, f in [('sha256',sha256),('sha3',sha3_256),('shake',shake256)]:
        base[nm+'(t)'] = f(tag)
        base[nm+'(p|t)'] = f(PREFIX+tag)
        base[nm+'(t|p)'] = f(tag+PREFIX)
        base[nm+'(t|aad)'] = f(tag+AAD)
        base[nm+'(aad|t)'] = f(AAD+tag)
        base[nm+'(t|ack)'] = f(tag+ACK)
        base[nm+'(ek|t)'] = f(ek+tag)
        base[nm+'(t|ek)'] = f(tag+ek)
        base[nm+'(ct|t)'] = f(ct+tag)
        base[nm+'(t|ct)'] = f(tag+ct)
    base['hkdf(t,info=prefix)'] = hkdf(tag, b'', PREFIX)
    base['hkdf(t,salt=prefix)'] = hkdf(tag, PREFIX, b'')
    base['hkdf(t,aad)'] = hkdf(tag, b'', AAD)
    base['hkdf(t,info=ack)'] = hkdf(tag, b'', ACK)
    return base

found=[]
for slot, ct, tag in hs:
    ck_off = 0xc0
    # find ek for slot
    R = d[0xc0:0xc0+19068]; off=12; ek=None
    for i in range(16):
        s2 = R[off+4]; el = int.from_bytes(R[off+5:off+7],'big')
        if s2 == slot: ek = R[off+7:off+7+el]
        off += 7+el
    for name, key in candidates(tag, slot, ek, ct).items():
        if len(key) not in (16,24,32): continue
        ctv, tg = payload[:59], payload[59:]
        trials = [
            ('gcm0', lambda: AES.new(key, AES.MODE_GCM, nonce=b'\x00'*12)),
            ('gcm_t12', lambda: AES.new(key, AES.MODE_GCM, nonce=tag[:12])),
            ('gcm_ct12', lambda: AES.new(key, AES.MODE_GCM, nonce=ct[:12])),
            ('ccp0', lambda: ChaCha20_Poly1305.new(key=key, nonce=b'\x00'*12)),
            ('ccp_t12', lambda: ChaCha20_Poly1305.new(key=key, nonce=tag[:12])),
        ]
        for tn, mk in trials:
            try:
                c = mk()
                try: c.update(AAD)
                except Exception: pass
                pt = c.decrypt_and_verify(ctv, tg)
                print("HIT", slot, name, tn, pt)
                found.append((slot,name,tn,pt))
            except Exception:
                pass
print("done", found)
