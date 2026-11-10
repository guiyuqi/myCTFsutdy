import sys, struct, hashlib
sys.path.append('/tmp/kpylib')
from kyber_py.ml_kem import ML_KEM_768 as K
exec(open('shared/t1.py').read().split('for (ts,slot,ek) in slots:\n    rho=')[0])
def unpack_raw12(b):
    v=[]
    for i in range(0,len(b),3):
        b0,b1,b2=b[i],b[i+1],b[i+2]
        v.append(b0|((b1&0xF)<<8)); v.append((b1>>4)|(b2<<4))
    return v
def pack12_std(vals):
    bits=0;nbits=0;out=bytearray()
    for v in vals:
        bits|=(v&0xFFF)<<nbits; nbits+=12
        while nbits>=8: out.append(bits&0xFF); bits>>=8; nbits-=8
    return bytes(out)
def std_ek(ek): return pack12_std(unpack_raw12(ek[:1152]))+ek[1152:]
hsd={s:(ct,tag) for s,ct,tag in hslots}
ms={'zero':bytes(32),'11':bytes([0x11])*32,'range':bytes(range(32))}
for (ts,slot,ek) in slots:
    e=std_ek(ek)
    for nm,m in ms.items():
        Kk,ct=K._encaps_internal(e,m)
        if ct==hsd[slot][0]:
            print("CT MATCH",slot,nm,Kk.hex())
            open(f'shared/hit_{slot}_{nm}.txt','w').write(Kk.hex()+'\n')
print('done')
