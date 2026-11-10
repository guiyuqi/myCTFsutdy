import sys,pickle,hashlib,hmac,itertools,struct
sys.path.insert(0,'/tmp/kpylib')
from kyber_py.ml_kem import ML_KEM_768 as M
from Crypto.Cipher import AES, ChaCha20_Poly1305
PREFIX=b'BCM-DIAG-KDF-v1'; AAD=b'BCM-DIAG-PAYLOAD'; ACK=b'BCM/DIAG/ACK/v1'
d=pickle.load(open('shared/known3.pkl','rb')); info=d['info']
payload=bytes(pickle.load(open('work/diag.pkl','rb'))['payload'])
CONFIG=pickle.load(open('work/diag.pkl','rb'))['config']

def hkdf(ikm,salt,inf,L=32):
    if salt is None: salt=b'\x00'*32
    prk=hmac.new(salt,ikm,hashlib.sha256).digest()
    okm=b'';t=b'';i=1
    while len(okm)<L:
        t=hmac.new(prk,t+inf+bytes([i]),hashlib.sha256).digest();okm+=t;i+=1
    return okm[:L]
H={'sha256':lambda b:hashlib.sha256(b).digest(),
   'sha3_256':lambda b:hashlib.sha3_256(b).digest(),
   'shake256':lambda b:hashlib.shake_256(b).digest(32),
   'shake128':lambda b:hashlib.shake_128(b).digest(32),
   'blake2s':lambda b:hashlib.blake2s(b).digest(),
   'blake2b32':lambda b:hashlib.blake2b(b).digest()[:32],
   'sha512_32':lambda b:hashlib.sha512(b).digest()[:32],
   'sha384_32':lambda b:hashlib.sha384(b).digest()[:32]}
def keys_for(X,label):
    ks={}
    for L in (16,24,32):
        if len(X)>=L: ks[f'{label}[:{L}]']=X[:L]
        ks[f'{label}[-{L}:]']=X[-L:]
    for hn,hf in H.items():
        for lbl,data in [('X',X),('P|X',PREFIX+X),('X|P',X+PREFIX),('P|X|A',PREFIX+X+AAD),
                         ('X|A',X+AAD),('A|X',AAD+X),('X|C',X+ACK),('C|X',ACK+X),
                         ('P|A|X',PREFIX+AAD+X),('P|X|C',PREFIX+X+ACK)]:
            ks[f'{hn}({lbl})']=hf(data)
    for lbl,data,ki in [('P',PREFIX,PREFIX),('A',AAD,AAD),('C',ACK,ACK)]:
        ks[f'hmac(X,{lbl})']=hmac.new(X,data,hashlib.sha256).digest()
        ks[f'hmac({lbl},X)']=hmac.new(data,X,hashlib.sha256).digest()
    ks['hkdf(X,salt=0,info=P)']=hkdf(X,None,PREFIX)
    ks['hkdf(X,salt=P,info=A)']=hkdf(X,PREFIX,AAD)
    ks['hkdf(X,salt=P,info=P)']=hkdf(X,PREFIX,PREFIX)
    ks['hkdf(X,salt=A,info=P)']=hkdf(X,AAD,PREFIX)
    ks['hkdf(X,salt=P,info=C)']=hkdf(X,PREFIX,ACK)
    ks['hkdf(X,salt=C,info=P)']=hkdf(X,ACK,PREFIX)
    ks['hkdf(X,salt=P|A,info=0)']=hkdf(X,PREFIX+AAD,b'')
    return ks

def layouts():
    out=[]
    # explicit
    out.append(('zero|ct59|tag16',b'\x00'*12,payload[:-16],payload[-16:]))
    out.append(('tag16|ct59|nonce0',b'\x00'*12,payload[16:],payload[:16]))
    for nlen in (8,12,16,24):
        clen=75-16-nlen
        if clen<=0: continue
        blocks={'N':payload[:nlen],'C':payload[nlen:nlen+clen],'T':payload[nlen+clen:]}
        for order in itertools.permutations('NCT'):
            N=blocks[order[0]]; C=blocks[order[1]]; T=blocks[order[2]]
            out.append((f'{"".join(order)}{nlen}',N,C,T))
    return out
LAY=layouts()
AADS=[AAD,b'',ACK,PREFIX,PREFIX+AAD,AAD+PREFIX,CONFIG]
print('keys x layouts x aads x ciphers =',len(LAY),len(AADS))
hits=[]
def test(key,N,C,T,meta):
    global hits
    if len(key) not in (16,24,32): return
    if len(T)!=16: return
    for aad in AADS:
        try:
            c=AES.new(key,AES.MODE_GCM,nonce=N);c.update(aad)
            pt=c.decrypt_and_verify(C,T)
            print('HIT AES',meta,aad,pt);hits.append((meta,aad,pt))
        except Exception: pass
        if len(N)==12:
            try:
                c=ChaCha20_Poly1305.new(key=key,nonce=N);c.update(aad)
                pt=c.decrypt_and_verify(C,T)
                print('HIT CHACHA',meta,aad,pt);hits.append((meta,aad,pt))
            except Exception: pass

for slot,I in info.items():
    Kf=hashlib.shake_256(I['K']+M._H(I['ct'])).digest(32)
    bases={'K':I['K'],'Kf':Kf,'m':I['m'],'tag':I['tag']}
    # xor combos of Kf
    s3=info[3];s9=info[9];s14=info[14]
    kf={s:hashlib.shake_256(info[s]['K']+M._H(info[s]['ct'])).digest(32) for s in info}
    bases['XOR3']=bytes(a^b^c for a,b,c in zip(kf[3],kf[9],kf[14]))
    bases['CAT3']=kf[3]+kf[9]+kf[14]
    bases['CAT3s']=bytes([3])+kf[3]+bytes([9])+kf[9]+bytes([14])+kf[14]
    allk=keys_for(Kf,f's{slot}.Kf')
    for bn,bv in bases.items():
        if bn!='Kf': allk.update(keys_for(bv,f's{slot}.{bn}'))
    for kn,key in allk.items():
        for lname,N,C,T in LAY:
            test(key,N,C,T,(slot,kn,lname))
    print('slot',slot,'done, hits',len(hits))
print('TOTAL HITS',len(hits))
