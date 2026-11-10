import sys, struct, hashlib
sys.path.append('/tmp/kpylib')
from kyber_py.ml_kem import ML_KEM_768 as K
exec(open('shared/t1.py').read().split("for (ts,slot,ek) in slots:\n    rho=")[0])
hid={s:(ct,tag) for s,ct,tag in hslots}
def residual(dk,ct):
    n=K.k*K.du*32
    c1,c2=ct[:n],ct[n:]
    u=K.M.decode_vector(c1,K.k,K.du).decompress(K.du)
    v=K.R.decode(c2,K.dv).decompress(K.dv)
    s_hat=K.M.decode_vector(dk,K.k,12,is_ntt=True)
    u_hat=u.to_ntt()
    w=v-(s_hat.dot(u_hat)).from_ntt()
    m=w.compress(1).encode(1)
    mu=K.R.decode(m,1).decompress(1)
    res=[(a-b)%3329 for a,b in zip(w.coeffs,mu.coeffs)]
    resc=[min(x,3329-x) for x in res]
    return m,max(resc),sum(1 for x in resc if x<100),sum(x*x for x in resc)
for ts,slot,ek in slots:
    ct,tag=hid[slot]
    dk=ek[:1152]
    ro=ek[1152:]
    m,mx,near,ss=residual(dk,ct)
    print(slot,'maxres',mx,'near<100',near,'ss',ss,'m',m.hex()[:16])
