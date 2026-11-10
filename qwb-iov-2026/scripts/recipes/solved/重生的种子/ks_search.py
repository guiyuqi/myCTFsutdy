"""Broad keystream search on the 75-byte payload of diag.bin.
Known-plaintext: assume plaintext contains b'flag{'. Tests AES-GCM keystream
(counter=2..6), AES-CTR (counter 0/1), ChaCha20-Poly1305 keystream (block>=1),
ChaCha20 (block>=0), for large key/nonce candidate sets derived from the
recovered ML-KEM secrets of slots 3/9/14.
"""
import sys, pickle, hashlib, hmac, itertools
import numpy as np
sys.path.insert(0,'/tmp/kpylib')

d=pickle.load(open('work/diag.pkl','rb'))
slots={s[1]:s for s in d['slots']}
hs={h[0]:h for h in d['hslots']}
pr=pickle.load(open('/tmp/probe16.pkl','rb'))
payload=d['payload']; CONFIG=d['config']
P=b'BCM-DIAG-KDF-v1'; A=b'BCM-DIAG-PAYLOAD'; C=b'BCM/DIAG/ACK/v1'
F=b'flag{'

# ---------- materials ----------
M={}
def add(n,v):
    if isinstance(v,int): v=str(v).encode()
    if isinstance(v,bytes) and len(v): M[n]=v

for s in (3,9,14):
    reenc,tok,m,K,Kfin=pr[s]
    ts,sl,ek=slots[s]
    ct,tag=hs[s][1],hs[s][2]
    for n,v in [('K',K),('Kfin',Kfin),('m',m),('tag',tag),('ct',ct),('ek',ek),
                ('rho',ek[-32:]),('ts_be',ts.to_bytes(4,'big')),('ts_le',ts.to_bytes(4,'little')),
                ('slot',bytes([sl])),('ts_ascii',('%08x'%ts).encode()),('ts_dec',str(ts).encode())]:
        add(f'{n}{s}',v)

se=pickle.load(open('shared/se.pkl','rb'))
import struct
def enc_coeff_u8(c):    # centered +2 offset
    return bytes((x+2)&0xff for x in c)
def enc_coeff_i16(c):
    return b''.join(struct.pack('<h',x) for x in c)
def enc_q16(c):
    return b''.join(struct.pack('<H',x%3329) for x in c)
sc=se['s_coeff']
ec=se['e_coeff'][3]
if isinstance(ec[0],list): ec=[x for poly in ec for x in poly]
add('s_u8',enc_coeff_u8(sc)); add('s_i16',enc_coeff_i16(sc)); add('s_q16',enc_q16(sc))
add('e_u8',enc_coeff_u8(ec)); add('e_i16',enc_coeff_i16(ec)); add('e_q16',enc_q16(ec))
add('s_ntt12',b''.join(struct.pack('<H',x%3329) for j in range(3) for x in se['s_ntt'][j]))
# global concatenations of the three fault slots
for nm in ('K','Kfin','m','tag'):
    add('cat_'+nm+'_3914',M[nm+'3']+M[nm+'9']+M[nm+'14'])
    add('cat_'+nm+'_1439',M[nm+'14']+M[nm+'3']+M[nm+'9'])
    add('xor_'+nm, bytes(a^b^c for a,b,c in zip(M[nm+'3'],M[nm+'9'],M[nm+'14'])))
    add('xor_'+nm+'_pair', bytes(a^b for a,b in zip(M[nm+'3'],M[nm+'9'])))
add('allKfin_sorted', b''.join(sorted([M['Kfin3'],M['Kfin9'],M['Kfin14']])))
add('P',P); add('A',A); add('C',C); add('config',CONFIG)
add('product',b'BCM-A3'); add('build',b'2.4.1')

# ---------- key candidates ----------
def hashes(x):
    out=[x]
    out.append(hashlib.sha256(x).digest())
    out.append(hashlib.sha3_256(x).digest())
    out.append(hashlib.shake_256(x).digest(32))
    out.append(hashlib.blake2s(x).digest())
    out.append(hashlib.blake2b(x,digest_size=32).digest())
    out.append(hashlib.sha512(x).digest()[:32])
    out.append(hashlib.sha3_512(x).digest()[:32])
    return out

def hkdf(ikm,salt,info,ln=32):
    if salt is None: salt=b'\0'*32
    prk=hmac.new(salt,ikm,hashlib.sha256).digest()
    okm=b''; t=b''; i=1
    while len(okm)<ln:
        t=hmac.new(prk,t+info+bytes([i]),hashlib.sha256).digest(); okm+=t; i+=1
    return okm[:ln]

keys={}
for n,x in M.items():
    for h in hashes(x):
        keys[f'{n}']=h if h is not x else x
        keys[f'{n}|h']=h
    keys[f'{n}|cmp']=hashlib.sha256(x+P).digest()
    keys[f'{n}|pre']=hashlib.sha256(P+x).digest()
    keys[f'{n}|cmpA']=hashlib.sha256(x+P+A).digest()
    keys[f'{n}|PAx']=hashlib.sha256(P+x+A).digest()
    keys[f'{n}|hm']=hmac.new(x,P,hashlib.sha256).digest()
    keys[f'{n}|hmA']=hmac.new(x,A,hashlib.sha256).digest()
    keys[f'{n}|hmAC']=hmac.new(x,A+C,hashlib.sha256).digest()
    keys[f'{n}|hmPA']=hmac.new(x,P+A,hashlib.sha256).digest()
    keys[f'{n}|hmC']=hmac.new(x,C,hashlib.sha256).digest()
    keys[f'{n}|HK1']=hkdf(x,P,A)
    keys[f'{n}|HK2']=hkdf(x,None,A)
    keys[f'{n}|HK3']=hkdf(x,P,b'')
    keys[f'{n}|HK4']=hkdf(x,A,P)
    if len(x)>=16:
        keys[f'{n}|k16']=x[:16]
# HMAC with key = prefix
for n,x in M.items():
    keys[f'hmP|{n}']=hmac.new(P,x,hashlib.sha256).digest()
    keys[f'hmA|{n}']=hmac.new(A,x,hashlib.sha256).digest()

# ---------- nonce candidates ----------
N=[]
def addn(v,label=''):
    if isinstance(v,int): v=str(v).encode()
    if isinstance(v,bytes) and v:
        N.append(v[:12] if len(v)>=12 else v+b'\0'*(12-len(v)))
addn(b'\0'*12); addn(b'\x01'*12); addn(bytes(range(12))); addn(b'\0'*16); addn(b'\0'*24)
npool=[M[k] for k in M]
for x in npool:
    addn(x[:12]); addn(x[-12:]); addn(hashlib.sha256(x).digest()[:12]); addn(hashlib.sha3_256(x).digest()[:12])
    addn(hashlib.shake_256(x).digest(12))
    addn(x[:8]+b'\0'*4); addn(b'\0'*4+x[:8])
for s in (3,9,14):
    ts=M[f'ts_be{s}']; tsl=M[f'ts_le{s}']; sl=M[f'slot{s}']
    for base in (ts,tsl):
        addn(base+b'\0'*8); addn(b'\0'*8+base); addn(base*3)
        addn(base+b'\0'*4+b'\0'*4)
    addn(M[f'ts_ascii{s}']+b'\0'*4); addn(b'\0'*4+M[f'ts_ascii{s}'])
    addn(sl+b'\0'*11); addn(sl*12)
# ek/ct slices (all offsets) for fault slots
for s in (3,9,14):
    ek=M[f'ek{s}']; ct=M[f'ct{s}']
    for i in range(0,len(ek)-11): addn(ek[i:i+12])
    for i in range(0,len(ct)-11): addn(ct[i:i+12])
# payload slices
for i in range(0,75-11): addn(payload[i:i+12])
# dedupe
N=list(dict.fromkeys(N))
Klist=[(n,k) for n,k in keys.items() if len(k)>=16]
print('materials',len(M),'keys',len(Klist),'nonces',len(N),flush=True)

# ---------- fast AES keystream ----------
PAY=np.frombuffer(payload,dtype=np.uint8)
L=len(PAY)  # 75
BLK=8  # counters 0..7 cover bytes 0..127
Narr=np.frombuffer(b''.join(N),dtype=np.uint8).reshape(len(N),12)
def ctrs(start):
    return np.arange(start,start+BLK)

hits=[]
from Crypto.Cipher import AES
def test_keystream(ks, label):
    # ks: (n, BLK*16) uint8
    for b in (0,12,16,24):
        if b>=L: continue
        pt=PAY[b:]^ks[:, :L-b]
        # search F anywhere
        W=len(F)
        if pt.shape[1]<W: continue
        m=pt[:,0:pt.shape[1]-W+1]==F[0]
        for i in range(1,W):
            m &= pt[:,i:pt.shape[1]-W+i+1]==F[i]
        idx=np.argwhere(m)
        for r,c in idx[:5]:
            hits.append((label,b,int(r),int(c),bytes(pt[r])))
            print('HIT',label,'nonceidx',int(r),'offs',b,int(c),N[int(r)].hex(),flush=True)
    return

for name,key in Klist:
    try:
        aes=AES.new(key[:32].ljust(32,b'\0'),AES.MODE_ECB)
    except Exception:
        continue
    buf=np.concatenate([np.concatenate([Narr, np.full((len(N),1),0,dtype=np.uint8)],axis=1)]*1)
    # build blocks for counters 0..BLK-1
    blk=np.empty((len(N),BLK,16),dtype=np.uint8)
    for c in range(BLK):
        blk[:,c,:12]=Narr
        blk[:,c,12:16]=np.array([(c>>24)&0xff,(c>>16)&0xff,(c>>8)&0xff,c&0xff],dtype=np.uint8)
    enc=aes.encrypt(blk.tobytes())
    ks=np.frombuffer(enc,dtype=np.uint8).reshape(len(N),BLK*16)
    for start_start in (2,1,0):
        sh=(start_start)*16
        test_keystream(ks[:,sh:sh+80], f'AES[{start_start}]|{name}')
print('AES done, hits',len(hits),flush=True)
pickle.dump(hits,open('/tmp/ks_hits.pkl','wb'))
