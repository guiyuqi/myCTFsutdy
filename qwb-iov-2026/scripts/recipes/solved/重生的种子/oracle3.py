import sys, pickle, hashlib, hmac, itertools, struct
sys.path.insert(0,'/tmp/kpylib')
from kyber_py.ml_kem import ML_KEM_768 as M
from Crypto.Cipher import AES, ChaCha20_Poly1305
d3=pickle.load(open('shared/known3.pkl','rb')); info=d3['info']
payload=bytes(pickle.load(open('work/diag.pkl','rb'))['payload'])
PREFIX=b'BCM-DIAG-KDF-v1'; AAD=b'BCM-DIAG-PAYLOAD'; ACK=b'BCM/DIAG/ACK/v1'
H={'sha256':lambda b: hashlib.sha256(b).digest(),
   'sha3_256':lambda b: hashlib.sha3_256(b).digest(),
   'sha512_32':lambda b: hashlib.sha512(b).digest()[:32],
   'blake2s':lambda b: hashlib.blake2s(b).digest(),
   'blake2b32':lambda b: hashlib.blake2b(b).digest()[:32],
   'shake':lambda b: hashlib.shake_256(b).digest(32),
   'shake128':lambda b: hashlib.shake_128(b).digest(32),
   'sha384_32':lambda b: hashlib.sha384(b).digest()[:32],
   'sha224x':lambda b: hashlib.sha224(b).digest()*2}
def aead_try(key):
    out=[]; cp=payload[:-16]; tg=payload[-16:]
    for nv in (b'\x00'*12, key[:12], payload[:12], payload[-28:-16]):
        for aad in (AAD,b'',ACK,PREFIX):
            for nm,cls in (('AES',AES),('ChaCha',ChaCha20_Poly1305)):
                try:
                    c=cls.new(key=key,nonce=nv) if nm=='ChaCha' else cls.new(key,AES.MODE_GCM,nonce=nv)
                    c.update(aad)
                    out.append((nm,nv.hex(),aad,c.decrypt_and_verify(cp,tg)))
                except Exception: pass
    return out
taghits=[];payhits=[]
for slot in (3,9,14):
    I=info[slot]; K=I['K']; ct=I['ct']; ek=I['ek']; m=I['m']
    Kfin=hashlib.shake_256(K+M._H(ct)).digest(32)
    Hct=M._H(ct)
    base={'P':PREFIX,'A':AAD,'C':ACK,'K':K,'Kf':Kfin,'Hc':Hct,'m':m,'ek':ek,'ct':ct,
          'r':M._G(m+M._H(ek))[1],'s':bytes([slot]),'t':struct.pack('>I',I['ts'])}
    names=list(base)
    for n in (1,2,3):
        for combo in itertools.permutations(names,n):
            data=b''.join(base[c] for c in combo)
            for hn,hf in H.items():
                h=hf(data)
                if h==I['tag']: taghits.append((slot,combo,hn))
                if hn in ('sha256','sha3_256','shake','shake128'):
                    payhits+= [(slot,combo,hn)+r for r in aead_try(h)]
            # HMAC
            for kname in names:
                h=hmac.new(base[kname],data,hashlib.sha256).digest()
                if h==I['tag']: taghits.append((slot,combo,'hmac:'+kname))
    # direct truncated keys
    for nm in names:
        v=base[nm]
        for L in (16,24,32):
            if len(v)>=L:
                payhits+=[(slot,nm,'trunc%d'%L)+r for r in aead_try(v[:L])]
    print('slot',slot,'ok taghits',len(taghits),'payhits',len(payhits))
print('TAGHITS',taghits[:10]); print('PAYHITS',[p for p in payhits][:5])
d3['Kfin']={s:hashlib.shake_256(info[s]['K']+M._H(info[s]['ct'])).digest(32) for s in info}
pickle.dump(d3,open('shared/known3.pkl','wb'))
