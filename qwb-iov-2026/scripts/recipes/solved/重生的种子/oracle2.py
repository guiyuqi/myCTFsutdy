import sys, pickle, hashlib, hmac, itertools, struct
sys.path.insert(0,'/tmp/kpylib')
from Crypto.Cipher import AES, ChaCha20_Poly1305
d=pickle.load(open('shared/known3.pkl','rb'))
info=d['info']
PREFIX=b'BCM-DIAG-KDF-v1'; AAD=b'BCM-DIAG-PAYLOAD'; ACK=b'BCM/DIAG/ACK/v1'
payload=bytes(pickle.load(open('work/diag.pkl','rb'))['payload'])
H={'sha256':lambda b: hashlib.sha256(b).digest(),
   'sha3_256':lambda b: hashlib.sha3_256(b).digest(),
   'sha512_32':lambda b: hashlib.sha512(b).digest()[:32],
   'sha512_32b':lambda b: hashlib.sha512(b).digest()[32:],
   'blake2s':lambda b: hashlib.blake2s(b).digest(),
   'blake2b32':lambda b: hashlib.blake2b(b).digest()[:32],
   'shake':lambda b: hashlib.shake_256(b).digest(32),
   'shake128':lambda b: hashlib.shake_128(b).digest(32),
   'md5x2':lambda b: hashlib.md5(hashlib.md5(b).digest()).digest()*2}
def aead_try(key):
    out=[]; ctpart=payload[:-16]; tg=payload[-16:]
    for nv in (b'\x00'*12, key[:12], payload[:12]):
        for aad in (AAD,b'',ACK):
            try:
                c=AES.new(key,AES.MODE_GCM,nonce=nv); c.update(aad)
                out.append(('AES',aad,c.decrypt_and_verify(ctpart,tg)))
            except Exception: pass
            try:
                c=ChaCha20_Poly1305.new(key=key,nonce=nv); c.update(aad)
                out.append(('ChaCha',aad,c.decrypt_and_verify(ctpart,tg)))
            except Exception: pass
    return out

taghits=[]; payhits=[]
for slot in (3,9,14):
    I=info[slot]
    base={'P':PREFIX,'K':I['K'],'m':I['m'],'ek':I['ek'],'ct':I['ct'],'A':AAD,'C':ACK,
          's':bytes([slot]),'t':struct.pack('>I',I['ts']),'h':I['tag']}
    names=[n for n in base if n!='h']
    for n in (1,2,3,4):
        for combo in itertools.permutations(names,n):
            data=b''.join(base[c] for c in combo)
            for hn,hf in H.items():
                h=hf(data)
                if h==I['tag']: taghits.append((slot,combo,hn))
                if hn in ('sha256','sha3_256','shake','shake128'):
                    for kind,aad,pt in aead_try(h): payhits.append((slot,combo,hn,kind,aad,pt))
            # HMAC forms
            for kname in names:
                if kname in combo: continue
                try:
                    h=hmac.new(base[kname],data,hashlib.sha256).digest()
                except Exception: continue
                if h==I['tag']: taghits.append((slot,combo+('hmac:',kname),'hmac'))
    print('slot',slot,'done; taghits',len(taghits))
print('TAGHITS',taghits[:20])
print('PAYHITS',payhits[:5])
