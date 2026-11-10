import sys, struct, hashlib, random
sys.path.append('/tmp/kpylib')
from kyber_py.ml_kem import ML_KEM_768 as K
exec(open('shared/t1.py').read().split("def unpack_raw12")[0])
rhos=[ek[1152:] for ts,slot,ek in slots]
rho_set=set(rhos)
def G(x): return hashlib.sha3_512(x).digest()
hits=0
def check(buf, tag):
    global hits
    for off in range(0, min(len(buf),256)-32+1, 32):
        w=buf[off:off+32]
        if w in rho_set:
            print("DIRECT RHO HIT", tag, off, w.hex()); hits+=1
        r=G(w+bytes([K.k]))[:32]
        if r in rho_set:
            print("RHO-from-d HIT", tag, off, w.hex()); hits+=1
for s in range(0, 300000):
    rr=random.Random(s)
    check(rr.randbytes(256), f'random.seed({s}).randbytes')
print("py random sweep done hits",hits)
