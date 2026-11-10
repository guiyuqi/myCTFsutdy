import sys, pickle, itertools, hashlib, hmac, struct
sys.path.insert(0,'/tmp/kpylib')
from kyber_py.ml_kem import ML_KEM_768 as M
from kyber_py.polynomials.polynomials import PolynomialNTT
src=open('shared/cross_slot.py').read().split("if __name__")[0]
exec(src)
Q=3329; R=M.R

d=pickle.load(open('work/diag.pkl','rb'))
slots=d['slots']; hs=d['hslots']; payload=d['payload']; cfg=d['config']
print('hs slots order:', [h[0] for h in hs], '| keylog slots:', [s[1] for s in slots])
eks=[bytes(s[2]) for s in slots]
T=[];A=[]
for ek in eks:
    t,rho=pack_t(ek); T.append(t)
    A.append([[coeffs(M._generate_matrix_from_seed(rho)[m,n]) for n in range(3)] for m in range(3)])

i,j=3,9
Ac=[[[ (A[i][m][n][k]-A[j][m][n][k])%Q for k in range(256)] for n in range(3)] for m in range(3)]
tc=[[ (T[i][m][k]-T[j][m][k])%Q for k in range(256)] for m in range(3)]
s3=solve_from(Ac,tc)
dk=encode_vec(s3)
print('dk', len(dk))
for idx,h in enumerate(hs):
    slotnum,ct,tag=h
    m=M._k_pke_decrypt(dk,ct)
    K,r=M._G(m+M._H(eks[slotnum]))
    try:
        c2=M._k_pke_encrypt(eks[slotnum],m,r)
    except Exception as e:
        c2=None
    print(idx,'slot',slotnum,'reenc',c2==ct,'m',m.hex() if isinstance(m,bytes) else m)
    if c2==ct:
        print('  K=',K.hex(),'tag=',tag.hex())
        open('shared/found_K.bin','wb').write(bytes(K)+b'|'+bytes(tag)+b'|'+bytes(m)+b'|'+bytes(ct)+b'|'+eks[slotnum])
PY=1
