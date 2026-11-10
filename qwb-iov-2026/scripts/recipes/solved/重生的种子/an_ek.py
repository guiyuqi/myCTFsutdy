import numpy as np
d=open('work/ext_etc_bcm_diag.bin','rb').read()
R=d[0xc0:0xc0+19068]
cnt=int.from_bytes(R[8:12],'big')
off=12; eks=[]
for i in range(cnt):
    ts=int.from_bytes(R[off:off+4],'big'); slot=R[off+4]; el=int.from_bytes(R[off+5:off+7],'big')
    eks.append((slot,ts,R[off+7:off+7+el])); off+=7+el
def decompress12(b):
    b=np.frombuffer(b,dtype=np.uint8).astype(np.int32).reshape(128,3)
    v=np.zeros((128,2),dtype=np.int32)
    v[:,0]=b[:,0] | ((b[:,1]&0x0f)<<8)
    v[:,1]=(b[:,1]>>4) | (b[:,2]<<4)
    return v.reshape(-1)
for slot,ts,ek in eks:
    t=ek[:1152]; rho=ek[1152:]
    vals=np.concatenate([decompress12(t[i*384:(i+1)*384]) for i in range(3)])
    print(f"slot{slot:2d} n={vals.size} n0={np.sum(vals==0):4d} max={vals.max():5d} mean={vals.mean():8.1f} std={vals.std():7.1f} uniq={len(np.unique(vals)):5d} rho={rho.hex()[:12]}")
