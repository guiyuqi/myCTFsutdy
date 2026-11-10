import sys, hashlib, hmac, itertools, pickle
sys.path.insert(0,'/tmp/kpylib')
tag=bytes.fromhex('a3f9af3ed74b1fd2c6f5fe582fc667ae0709e4313abc7aae1b86448a5c89bde3')
d=pickle.load(open('work/diag.pkl','rb'))
payload=bytes(d['payload']); cfg=d['config']
PREFIX=b'BCM-DIAG-KDF-v1'; AAD=b'BCM-DIAG-PAYLOAD'; ACK=b'BCM/DIAG/ACK/v1'
try:
    from Crypto.Cipher import AES, ChaCha20_Poly1305
except Exception as e:
    print('no pycryptodome', e); raise SystemExit
# collect all Ks
Ks=[]
for line in open('shared/found_K.bin','rb').read().split(b'\n'):
    pass
import subprocess
# gather all three Ks from crack3 output file? just recompute quickly is costly; use known
K3=bytes.fromhex('828dbfca30b766ffc415557ff104622f9b12e2e6e36517c3afc7012f21f68752')
K9=bytes.fromhex('36e7fea83004e07efab17f22d3cb0a4cd0bc4269a8c1d91dd188e197c4ac8674')
K14=bytes.fromhex('eff8e5fd3789a2bc863dc9212fcdf54d07aab3f0008682f463c9d36a3d3185c6')
Ks=[K3,K9,K14]

def kdf_variants(K):
    outs={}
    cands={
      'K':K,
      'sha256(K)':hashlib.sha256(K).digest(),
      'sha256(p||K)':hashlib.sha256(PREFIX+K).digest(),
      'sha256(K||p)':hashlib.sha256(K+PREFIX).digest(),
      'sha3(p||K)':hashlib.sha3_256(PREFIX+K).digest(),
      'sha3(K||p)':hashlib.sha3_256(K+PREFIX).digest(),
      'shake(p||K)':hashlib.shake_256(PREFIX+K).digest(32),
      'shake(K||p)':hashlib.shake_256(K+PREFIX).digest(32),
      'shake(p|K|AAD)':hashlib.shake_256(PREFIX+K+AAD).digest(32),
      'sha256(p|K|AAD)':hashlib.sha256(PREFIX+K+AAD).digest(),
    }
    try:
        outs['hkdf(p,salt=K)']=hmac.new(K,PREFIX+b'\x01',hashlib.sha256).digest()
    except Exception: pass
    outs.update(cands)
    return outs

def try_dec(key, nonce=None):
    ctpart=payload[:-16]; tagp=payload[-16:]
    res=[]
    if nonce is None: nonce=b'\x00'*12
    for aad in (AAD, b'', ACK, PREFIX):
        try:
            c=AES.new(key,AES.MODE_GCM,nonce=nonce)
            c.update(aad)
            pt=c.decrypt_and_verify(ctpart,tagp)
            res.append(('AESGCM',aad,pt))
        except Exception: pass
        try:
            c=ChaCha20_Poly1305.new(key=key,nonce=nonce)
            c.update(aad)
            pt=c.decrypt_and_verify(ctpart,tagp)
            res.append(('ChaCha',aad,pt))
        except Exception: pass
    return res

hits=[]
for Kx in Ks:
    for name,key in kdf_variants(Kx).items():
        nonces={'zero':b'\x00'*12,'K12':Kx[:12],'tag12':tag[:12],'Ktail':Kx[-12:]}
        for nname,nv in nonces.items():
            for kind,aad,pt in try_dec(key,nv):
                print('HIT',kind,name,nname,aad,pt)
                hits.append(pt)
print('hits',len(hits))
# also check tag relations
for Kx in Ks:
    for name,key in kdf_variants(Kx).items():
        if key[:32]==tag or hashlib.sha256(key).digest()==tag:
            print('TAG MATCH',name)
    for extra in (PREFIX,ACK,AAD,PREFIX+ACK,PREFIX+AAD,ACK+AAD):
        for pre in (Kx+extra, extra+Kx):
            if hashlib.sha256(pre).digest()==tag: print('tagmatch sha256', extra[:6])
            if hashlib.sha3_256(pre).digest()==tag: print('tagmatch sha3', extra[:6])
            if hashlib.shake_256(pre).digest(32)==tag: print('tagmatch shake', extra[:6])
