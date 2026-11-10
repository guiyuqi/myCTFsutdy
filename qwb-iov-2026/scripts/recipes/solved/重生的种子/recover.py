"""Recover ML-KEM-768 secret from fault slots 3/9/14 (shared s AND shared e).
Helpers reusable: parse(), Amat(), tvec(), solve_per_quad(), build_dk()"""
import sys, struct
sys.path.append('/tmp/kpylib')
from kyber_py.ml_kem import ML_KEM_768 as M
Q=3329; R=M.R; Z=R.ntt_zetas

def parse(path='work/ext_etc_bcm_diag.bin'):
    d=open(path,'rb').read()
    ver,flags,count,hdr=struct.unpack('<IIII',d[8:24])
    recs={}
    for i in range(count):
        o=hdr+i*0x20; rid,roff,rlen=struct.unpack('<III',d[o:o+12]); recs[rid]=d[roff:roff+rlen]
    kl=recs[1]; hs=recs[2]
    n=struct.unpack('>I',kl[8:12])[0]; p=12; slots=[]
    for i in range(n):
        ts=struct.unpack('>I',kl[p:p+4])[0]; slot=kl[p+4]; ekl=struct.unpack('>H',kl[p+5:p+7])[0]
        slots.append((ts,slot,kl[p+7:p+7+ekl])); p+=7+ekl
    hn=struct.unpack('<I',hs[8:12])[0]; p=12; hslots={}
    for i in range(hn):
        slot=hs[p]; cl=struct.unpack('<I',hs[p+4:p+8])[0]; ct=hs[p+8:p+8+cl]; qq=p+8+cl
        tl=struct.unpack('<I',hs[qq:qq+4])[0]; tag=hs[qq+4:qq+4+tl]
        hslots[slot]=(ct,tag)
    return {'slots':slots,'hslots':hslots,'payload':recs[3],'config':recs[4]}

def tvec(ek):
    v=M.M.decode_vector(ek[:-32],3,12,is_ntt=True)
    return [[c%Q for c in v[i,0].coeffs] for i in range(3)]

def Amat(rho):
    A=M._generate_matrix_from_seed(rho)
    return [[[c%Q for c in A[i,j].coeffs] for j in range(3)] for i in range(3)]

def solve_per_quad(D, dt, k=3):
    out=[[0]*256 for _ in range(k)]
    n=k*2
    for p in range(128):
        z = Z[64+p//2]%Q if p%2==0 else (-Z[64+p//2])%Q
        Aug=[[0]*(n+1) for _ in range(n)]
        for i in range(k):
            for j in range(k):
                a0=D[i][j][2*p]; a1=D[i][j][2*p+1]
                Aug[2*i][2*j]=(Aug[2*i][2*j]+a0)%Q
                Aug[2*i][2*j+1]=(Aug[2*i][2*j+1]+z*a1)%Q
                Aug[2*i+1][2*j]=(Aug[2*i+1][2*j]+a1)%Q
                Aug[2*i+1][2*j+1]=(Aug[2*i+1][2*j+1]+a0)%Q
            Aug[2*i][n]=dt[i][2*p]; Aug[2*i+1][n]=dt[i][2*p+1]
        r=0
        for c in range(n):
            pr=None
            for i2 in range(r,n):
                if Aug[i2][c]%Q: pr=i2; break
            if pr is None: return None
            Aug[r],Aug[pr]=Aug[pr],Aug[r]
            inv=pow(Aug[r][c],-1,Q)
            Aug[r]=[(x*inv)%Q for x in Aug[r]]
            for i2 in range(n):
                if i2!=r and Aug[i2][c]%Q:
                    f=Aug[i2][c]
                    Aug[i2]=[(Aug[i2][t]-f*Aug[r][t])%Q for t in range(n+1)]
            r+=1
        for j in range(k):
            out[j][2*p]=Aug[2*j][n]; out[j][2*p+1]=Aug[2*j+1][n]
    return out

def recover_s(i,j,As,Ts):
    D=[[[(As[i][r][c][k]-As[j][r][c][k])%Q for k in range(256)] for c in range(3)] for r in range(3)]
    dt=[[(Ts[i][r][k]-Ts[j][r][k])%Q for k in range(256)] for r in range(3)]
    return solve_per_quad(D,dt)

def to_normal(shot):
    """s_hat -> list of 768 signed-small coefficients (centered)"""
    c=[]
    for j in range(3):
        rec=R(shot[j], is_ntt=True).from_ntt().coeffs
        c += [x%Q if x%Q<Q//2+1 else x%Q-Q for x in rec]
    return c

def build_sk(shot, ek, seed=b'\x00'*32):
    """assemble dk = dk_pke || ek || H(ek) || z"""
    dk_pke=b''.join(M.M.PolynomialNTT.encode(p,12) for p in [R(shot[j],is_ntt=True) for j in range(3)])
    from kyber_py.hashes import H as Hfun
    return dk_pke + ek + bytes(Hfun(ek)) + seed
