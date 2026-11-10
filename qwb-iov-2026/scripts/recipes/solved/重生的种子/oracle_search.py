import sys, pickle, hashlib, hmac, itertools, struct
sys.path.insert(0,'/tmp/kpylib')
from kyber_py.ml_kem import ML_KEM_768 as M
from kyber_py.polynomials.polynomials import PolynomialNTT
from Crypto.Cipher import AES, ChaCha20_Poly1305
exec(open('shared/cross_slot.py').read().split("if __name__")[0])
Q=3329; R=M.R
d=pickle.load(open('work/diag.pkl','rb'))
slots=d['slots']; hs={h[0]:h for h in d['hslots']}; payload=bytes(d['payload'])
eks={s[1]:bytes(s[2]) for s in slots}; tss={s[1]:s[0] for s in slots}
T=[];A=[]
for k in range(16):
    t,rho=pack_t(eks[k]); T.append(t)
    A.append([[coeffs(M._generate_matrix_from_seed(rho)[m_,n]) for n in range(3)] for m_ in range(3)])
Ac=[[[ (A[3][m_][n][kk]-A[9][m_][n][kk])%Q for kk in range(256)] for n in range(3)] for m_ in range(3)]
tc=[[ (T[3][m_][kk]-T[9][m_][kk])%Q for kk in range(256)] for m_ in range(3)]
s3=solve_from(Ac,tc)
cf=invntt_normal(s3)
print('maxsmall',max(abs(x) for x in cf))
dk=encode_vec(s3)
info={}
for slot in (3,9,14):
    h=hs[slot]; ct=bytes(h[1]); tag=bytes(h[2])
    m=M._k_pke_decrypt(dk,ct); K,r=M._G(m+M._H(eks[slot]))
    ok=M._k_pke_encrypt(eks[slot],m,r)==ct
    info[slot]=dict(ct=ct,tag=tag,m=m,K=K,ek=eks[slot],ok=ok,ts=tss[slot])
    print('slot',slot,'reenc',ok,'tag',tag.hex())
pickle.dump({'info':info,'s_ntt':s3,'s_coeff':cf},open('shared/known3.pkl','wb'))

PREFIX=b'BCM-DIAG-KDF-v1'; AAD=b'BCM-DIAG-PAYLOAD'; ACK=b'BCM/DIAG/ACK/v1'
# s encodings
s_enc={}
s_enc['s_ntt12']=dk
s_enc['s_coeff_bytes']=bytes([(x+2)&0xff for x in cf])   # 0..4
try:
    s_enc['s_coeff_neg']=bytes([(x%256) for x in cf])
except Exception: pass
s_enc['s_norm12']=b''.join(PolynomialNTT(R,s3[j]).from_ntt().encode(12) for j in range(3))
hashes={'sha256':lambda b: hashlib.sha256(b).digest(),
        'sha3_256':lambda b: hashlib.sha3_256(b).digest(),
        'sha512_32':lambda b: hashlib.sha512(b).digest()[:32],
        'blake2s':lambda b: hashlib.blake2s(b).digest(),
        'shake':lambda b: hashlib.shake_256(b).digest(32)}
def aead(key,tag_hex=True):
    out=[]
    ctpart=payload[:-16]; tagp=payload[-16:]
    for nname,nv in (('zero',b'\x00'*12),):
        for aad in (AAD,b''):
            try:
                c=AES.new(key,AES.MODE_GCM,nonce=nv); c.update(aad)
                out.append(('AES',aad,c.decrypt_and_verify(ctpart,tagp)))
            except Exception: pass
            try:
                c=ChaCha20_Poly1305.new(key=key,nonce=nv); c.update(aad)
                out.append(('ChaCha',aad,c.decrypt_and_verify(ctpart,tagp)))
            except Exception: pass
    return out

slot=3; I=info[slot]
base={'P':PREFIX,'K':I['K'],'m':I['m'],'ek':I['ek'],'ct':I['ct'],'A':AAD,'C':ACK,
      'S12':s_enc['s_ntt12'],'Sc':s_enc['s_coeff_bytes'],'Sn':s_enc['s_norm12'],
      'slot':bytes([slot]),'ts':struct.pack('>I',I['ts'])}
names=list(base)
taghits=[]
for n in (1,2,3):
    for combo in itertools.permutations(names,n):
        data=b''.join(base[c] for c in combo)
        for hn,hf in hashes.items():
            h=hf(data)
            for tgt_slots in (3,9,14):
                if h==info[tgt_slots]['tag']:
                    taghits.append((combo,hn,tgt_slots))
            for kind,aad,pt in aead(h):
                print('PAYLOAD HIT',combo,hn,kind,aad,pt)
print('taghits',taghits[:10], len(taghits))
