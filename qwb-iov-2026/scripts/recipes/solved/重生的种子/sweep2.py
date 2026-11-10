import sys,pickle,hashlib,hmac,itertools,struct
sys.path.insert(0,'/tmp/kpylib')
from kyber_py.ml_kem import ML_KEM_768 as M
from Crypto.Cipher import AES, ChaCha20_Poly1305, ChaCha20
PREFIX=b'BCM-DIAG-KDF-v1'; AAD=b'BCM-DIAG-PAYLOAD'; ACK=b'BCM/DIAG/ACK/v1'
d=pickle.load(open('shared/known3.pkl','rb')); info=d['info']
se=pickle.load(open('shared/se.pkl','rb'))
payload=bytes(pickle.load(open('work/diag.pkl','rb'))['payload'])
CONFIG=pickle.load(open('work/diag.pkl','rb'))['config']

H={'sha256':lambda b:hashlib.sha256(b).digest(),
   'sha3_256':lambda b:hashlib.sha3_256(b).digest(),
   'shake256':lambda b:hashlib.shake_256(b).digest(32),
   'shake128':lambda b:hashlib.shake_128(b).digest(32),
   'blake2s':lambda b:hashlib.blake2s(b).digest(),
   'blake2b32':lambda b:hashlib.blake2b(b).digest()[:32],
   'sha512_32':lambda b:hashlib.sha512(b).digest()[:32],
   'sha384_32':lambda b:hashlib.sha384(b).digest()[:32]}
def hkdf(ikm,salt,inf,L=32):
    if salt is None: salt=b'\x00'*32
    prk=hmac.new(salt,ikm,hashlib.sha256).digest()
    okm=b'';t=b'';i=1
    while len(okm)<L:
        t=hmac.new(prk,t+inf+bytes([i]),hashlib.sha256).digest();okm+=t;i+=1
    return okm[:L]

def deriv_keys(X,label):
    ks={}
    for L in (16,24,32):
        if len(X)>=L: ks[f'{label}[:{L}]']=X[:L]
        ks[f'{label}[-{L}:]']=X[-L:]
    for hn,hf in H.items():
        for lbl,data in [('X',X),('P|X',PREFIX+X),('X|P',X+PREFIX),('P|X|A',PREFIX+X+AAD),
                         ('X|A',X+AAD),('A|X',AAD+X),('X|C',X+ACK),('C|X',ACK+X),
                         ('P|X|C',PREFIX+X+ACK),('P|A|X',PREFIX+AAD+X),('A|X|P',AAD+X+PREFIX)]:
            ks[f'{hn}({lbl})']=hf(data)
    for lbl,msg in [('P',PREFIX),('A',AAD),('C',ACK)]:
        ks[f'hmac(X,{lbl})']=hmac.new(X,msg,hashlib.sha256).digest()
        ks[f'hmac({lbl},X)']=hmac.new(msg,X,hashlib.sha256).digest()
        ks[f'hmac(X,{lbl}|X)']=hmac.new(X,msg+X,hashlib.sha256).digest()
    for sn,salt in [('0',None),('P',PREFIX),('A',AAD),('C',ACK),('P+A',PREFIX+AAD)]:
        for inm,inf in [('0',b''),('P',PREFIX),('A',AAD),('C',ACK)]:
            ks[f'hkdf(X,salt={sn},info={inm})']=hkdf(X,salt,inf)
    return ks

def xor_bases(X,label):
    out={}
    for nm,stream in [('tagrep',None),('Krep',None)]:
        pass
    return out

hits=[]
def test(key,N,C,T,meta):
    if len(key) not in (16,24,32): return
    for aad in AADS:
        try:
            c=AES.new(key,AES.MODE_GCM,nonce=N);c.update(aad)
            pt=c.decrypt_and_verify(C,T)
            print('HIT AES',meta,repr(aad),pt);hits.append((meta,aad,pt))
        except Exception: pass
        if len(N)==12:
            try:
                c=ChaCha20_Poly1305.new(key=key,nonce=N);c.update(aad)
                pt=c.decrypt_and_verify(C,T)
                print('HIT CHACHA',meta,repr(aad),pt);hits.append((meta,aad,pt))
            except Exception: pass

AADS=[AAD,b'',ACK,PREFIX,PREFIX+AAD,CONFIG]
for slot,I in info.items():
    Kf=hashlib.shake_256(I['K']+M._H(I['ct'])).digest(32)
    sb=bytes([(x+2)&0xff for x in se['s_coeff']])
    s16=b''.join(struct.pack('<h',x) for x in se['s_coeff'])
    eb=bytes([(x+2)&0xff for x in se['e_coeff'][3][0]+se['e_coeff'][3][1]+se['e_coeff'][3][2]])
    e16=b''.join(struct.pack('<h',x) for x in se['e_coeff'][3][0]+se['e_coeff'][3][1]+se['e_coeff'][3][2])
    bases={'Kf':Kf,'K':I['K'],'m':I['m'],'tag':I['tag'],'sb':sb,'s16':s16,
           'eb':eb,'e16':e16,'sbeb':sb+eb,'Kf_sb':Kf+sb,'Kf_m':Kf+I['m']}
    keymap={}
    for bn,X in bases.items():
        keymap.update(deriv_keys(X,f'{slot}.{bn}'))
    print('slot',slot,'keys',len(keymap))
    layout=[('end',payload[:-16],payload[-16:]),('front',payload[16:],payload[:16])]
    for kn,key in keymap.items():
        # nonce candidates
        ns={'zero':b'\x00'*12,'p[:12]':payload[:12],'p[-12:]':payload[-12:],'p[12:24]':payload[12:24]}
        if len(key)>=12:
            ns['key[:12]']=key[:12]; ns['key[-12:]']=key[-12:]
        for hn,hf in H.items():
            ns[f'{hn}(key)[:12]']=hf(key)[:12]
        for fn,fv in [('Kf',Kf),('tag',I['tag']),('ct',I['ct']),('ek',I['ek'])]:
            ns[f'{fn}[:12]']=fv[:12]; ns[f'{fn}[-12:]']=fv[-12:]
            for hn,hf in H.items():
                ns[f'{hn}({fn})[:12]']=hf(fv)[:12]
        for nn,N in ns.items():
            for lname,C,T in layout:
                test(key,N,C,T,(slot,kn,nn,lname))
    # stream ciphers: key candidates with derived nonce, ct=whole payload
    for kn,key in keymap.items():
        if len(key) not in (16,24,32): continue
        # XOR keystreams
        for ksname,ksh in [('hkdfP',hkdf(key,None,PREFIX,75)),('sha256rep',(hashlib.sha256(key).digest()*3)[:75]),
                           ('sha3rep',(hashlib.sha3_256(key).digest()*3)[:75]),
                           ('shakerep',(hashlib.shake_256(key).digest(75)))]:
            pt=bytes(a^b for a,b in zip(payload,ksh))
            if b'flag{' in pt or all(32<=x<127 for x in pt): print('XORHIT',slot,kn,ksname,pt)
        for nn,N in [('zero',b'\x00'*12),('key12',key[:12] if len(key)>=12 else None)]:
            if N is None: continue
            try:
                pt=ChaCha20.new(key=key,nonce=N).decrypt(payload)
                if b'flag{' in pt: print('CC20HIT',slot,kn,nn,pt)
            except Exception: pass
            try:
                pt=AES.new(key,AES.MODE_CTR,nonce=N[:8],initial_value=0).decrypt(payload)
                if b'flag{' in pt: print('CTRHIT',slot,kn,nn,pt)
            except Exception: pass
    print('slot',slot,'done total hits',len(hits))
print('TOTAL',len(hits))
