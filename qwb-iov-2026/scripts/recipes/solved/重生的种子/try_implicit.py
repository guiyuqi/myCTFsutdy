import sys, struct, hashlib, hmac, itertools
sys.path.append('/tmp/kpylib')
from kyber_py.ml_kem import ML_KEM_768 as K
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Hash import SHA256 as CSHA256, SHA3_256
exec(open('shared/t1.py').read().split("for (ts,slot,ek) in slots:\n    rho=")[0])
def unpack_raw12(b):
    v=[]
    for i in range(0,len(b),3):
        v.append(b[i]|((b[i+1]&0xF)<<8)); v.append((b[i+1]>>4)|(b[i+2]<<4))
    return v
def pack12(vals):
    bits=0;nbits=0;out=bytearray()
    for v in vals:
        bits|=(v&0xFFF)<<nbits;nbits+=12
        while nbits>=8: out.append(bits&0xFF);bits>>=8;nbits-=8
    return bytes(out)
def std_ek(ek): return pack12(unpack_raw12(ek[:1152]))+ek[1152:]
def dec_v(ct): return K.R.decode(ct[:128],4).decompress(4)
def comp1(poly):
    return bytes([0])*32 if False else poly.compress(1).encode(1)
payload=recs[3]; pl_aad=b'BCM-DIAG-PAYLOAD'; ack=b'BCM/DIAG/ACK/v1'; prefix=b'BCM-DIAG-KDF-v1'
ctload, tagload = payload[:59], payload[59:]
hid={s:(ct,tag) for s,ct,tag in hslots}
slotsd={s:ek for ts,s,ek in slots}
print('payload',payload.hex())
def sha256(b): return hashlib.sha256(b).digest()
def shake(b,n=32): return hashlib.shake_256(b).digest(n)
def sha3(b): return hashlib.sha3_256(b).digest()
def hkdf(ikm,salt,info,n=32):
    if salt is None: salt=bytes(32)
    prk=hmac.new(salt,ikm,hashlib.sha256).digest()
    okm=b''; t=b''; i=1
    while len(okm)<n:
        t=hmac.new(prk,t+info+bytes([i]),hashlib.sha256).digest(); okm+=t; i+=1
    return okm[:n]
def derivs(base, x):
    yield 'id',base
    yield 'sha256(pf||K)',sha256(prefix+base)
    yield 'sha256(K||pf)',sha256(base+prefix)
    yield 'sha3(pf||K)',sha3(prefix+base)
    yield 'shake(pf||K)',shake(prefix+base)
    yield 'shake(K||pf)',shake(base+prefix)
    yield 'hkdf(pf,K)',hkdf(base,None,prefix)
    yield 'hkdf(saltpf,K)',hkdf(base,prefix,b'')
    yield 'hkdf(K,pf)',hkdf(prefix,base,b'')
    yield 'sha256(K||x)',sha256(base+x)
    yield 'sha256(x||K)',sha256(x+base)
    yield 'hmac(K,x)',hmac.new(base,x,hashlib.sha256).digest()
    yield 'hmac(x,K)',hmac.new(x,base,hashlib.sha256).digest()
    yield 'pf||K[:16]',(prefix+base)[:32]
    yield 'K||pf',(base+prefix)[:32]
    yield 'sha256(K)',sha256(base)
    yield 'sha3(K)',sha3(base)
    yield 'shake(K)',shake(base)
def try_payload(key):
    for nname,nonce in [('z12',bytes(12)),('ct12',ctload[:12]),('tag12',tagload[:12])]:
        for aad in [pl_aad,b'',ack]:
            try:
                c=AES.new(key,AES.MODE_GCM,nonce=nonce)
                c.update(aad)
                pt=c.decrypt_and_verify(ctload,tagload)
                return ('AESGCM',nname,aad,pt)
            except Exception: pass
            try:
                c=ChaCha20_Poly1305.new(key=key,nonce=nonce)
                c.update(aad)
                pt=c.decrypt_and_verify(ctload,tagload)
                return ('CHACHA',nname,aad,pt)
            except Exception: pass
    return None
def try_tag(Kc):
    cands = {
      'id':Kc,'sha256':sha256(Kc),'sha3':sha3(Kc),'shake':shake(Kc),
      'hmac(K,ack)':hmac.new(Kc,ack,hashlib.sha256).digest(),
      'hmac(K,prefix)':hmac.new(Kc,prefix,hashlib.sha256).digest(),
      'hmac(K,empty)':hmac.new(Kc,b'',hashlib.sha256).digest(),
      'sha256(K||ack)':sha256(Kc+ack),'sha256(ack||K)':sha256(ack+Kc),
      'sha256(pf||K)':sha256(prefix+Kc),'sha3(K||ack)':sha3(Kc+ack),
    }
    return cands
found=[]
for ts,slot,ek in slots:
    ct,tag=hid[slot]
    e=std_ek(ek)
    bases={}
    # implicit rejection with z candidates
    for zn,z in [('z0',bytes(32)),('z11',bytes([0x11])*32)]:
        bases['impl_'+zn]=hashlib.shake_256(z+ct).digest(32)
        bases['implsha3_'+zn]=hashlib.shake_256(z+ct).digest(32)
    # mlkem K with m guesses
    H=K._H(e)
    v=dec_v(ct)
    mcomp=v.compress(1).encode(1)
    for mn,m in [('m0',bytes(32)),('mcomp',mcomp),('m11',bytes([0x11])*32)]:
        bases['mlkem_'+mn]=K._G(m+H)[0]
    for bname,base in bases.items():
        # tag check
        for kn,kv in try_tag(base).items():
            if kv==tag:
                print('TAG MATCH',slot,bname,kn); found.append((slot,bname,kn))
        # payload
        for dn,dv in derivs(base,b''):
            r=try_payload(dv)
            if r: print('PAYLOAD MATCH',slot,bname,dn,r); found.append((slot,bname,dn,r))
print('found',found)
