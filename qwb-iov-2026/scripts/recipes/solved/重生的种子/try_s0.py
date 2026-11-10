import numpy as np, pickle, hashlib, sys
sys.path.insert(0,'shared')
from mlkem import *
from decaps import *
hs = pickle.load(open('shared/hs.pkl','rb'))
d = open('work/ext_etc_bcm_diag.bin','rb').read()
R = d[0xc0:0xc0+19068]; off=12; eks={}
for i in range(16):
    s2=R[off+4]; el=int.from_bytes(R[off+5:off+7],'big'); eks[s2]=R[off+7:off+7+el]; off+=7+el
zero = [np.zeros(256,dtype=np.int64) for _ in range(3)]
def enc1(x):
    return hashlib.shake_256(x).digest(32)
for slot, ct, tag in hs:
    m,Kp,K = decaps(zero, eks[slot], ct)
    cands = {'K':K,'Kp[:32]':Kp[:32],'sha256K':hashlib.sha256(K).digest(),
             'm':m, 'sha256m':hashlib.sha256(m).digest(), 'shakeK':enc1(K)}
    hit = [n for n,v in cands.items() if v==tag]
    print(f"slot{slot:2d} s=0 -> tag match: {hit}  K={K.hex()[:16]} m={m.hex()[:16]}")
