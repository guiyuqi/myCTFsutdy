import numpy as np
d=open('work/ext_etc_bcm_diag.bin','rb').read()
H=d[0x4b3c:0x4b3c+18124]
cnt=int.from_bytes(H[8:12],'little')
off=12; hs=[]
for i in range(cnt):
    slot=H[off]; cl=int.from_bytes(H[off+4:off+8],'little')
    ct=H[off+8:off+8+cl]; off2=off+8+cl
    tl=int.from_bytes(H[off2:off2+4],'little'); tag=H[off2+4:off2+4+tl]
    off=off2+4+tl
    hs.append((slot,ct,tag))
def decomp(b,d,n):
    v=np.zeros(n,dtype=np.int32); acc=0;bits=0;k=0;mask=(1<<d)-1
    for byte in b:
        acc |= byte<<bits; bits+=8
        while bits>=d and k<n:
            v[k]=acc&mask; k+=1; acc>>=d; bits-=d
    return v
import pickle
pickle.dump(hs,open('shared/hs.pkl','wb'))
for slot,ct,tag in hs:
    u=decomp(ct[:960],10,768); v=decomp(ct[960:],4,256)
    print(f"slot{slot:2d} u:max={u.max():4d} mean={u.mean():7.1f} n0={np.sum(u==0):4d}/768 | v:max={v.max():2d} mean={v.mean():5.1f} n0={np.sum(v==0):3d}/256 | tag={tag.hex()[:24]}")
