import sys, struct, hashlib
sys.path.append('/tmp/kpylib')
from kyber_py.ml_kem import ML_KEM_768 as K
exec(open('shared/t1.py').read().split("for (ts,slot,ek) in slots:\n    rho=")[0])
def unpack_raw12(b):
    v=[]
    for i in range(0,len(b),3):
        v.append(b[i]|((b[i+1]&0xF)<<8)); v.append((b[i+1]>>4)|(b[i+2]<<4))
    return v
hid={s:(ct,tag) for s,ct,tag in hslots}
def t_from_sigma(rho,sigma):
    A=K._generate_matrix_from_seed(rho)
    s,N=K._generate_error_vector(sigma,K.eta_1,0)
    e,N=K._generate_error_vector(sigma,K.eta_1,N)
    s_hat=s.to_ntt(); e_hat=e.to_ntt()
    t=A@s_hat+e_hat
    out=[]
    for row in t._data:
        for ele in row: out+=ele.coeffs
    return out
def sigcands(ts,slot,rho):
    t4b=struct.pack('>I',ts); t4l=struct.pack('<I',ts)
    c={
    'zero':bytes(32),'11':bytes([0x11])*32,'range':bytes(range(32)),
    'ts_be_rep':(t4b*8),'ts_le_rep':(t4l*8),
    'sha256_ts_be':hashlib.sha256(t4b).digest(),
    'sha3_ts_be':hashlib.sha3_256(t4b).digest(),
    'sha3_512_ts_be':hashlib.sha3_512(t4b).digest()[:32],
    'sha256_ts_ascii':hashlib.sha256(str(ts).encode()).digest(),
    'rho':rho,
    'slot_rep':bytes([slot])*32,
    'rho_sha256':hashlib.sha256(rho).digest(),
    }
    return c
for ts,slot,ek in slots:
    rho=ek[1152:]; tstored=unpack_raw12(ek[:1152])
    for nm,sig in sigcands(ts,slot,rho).items():
        t=t_from_sigma(rho,sig)
        if t==tstored:
            print("T MATCH",slot,nm)
    if slot in (3,9,14): print('tested fault slot',slot)
print('done')
