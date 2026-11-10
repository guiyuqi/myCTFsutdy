import sys, struct, itertools
sys.path.append('/tmp/kpylib')
from kyber_py.ml_kem import ML_KEM_768 as M
Q=3329
R=M.R
Z=R.ntt_zetas
exec(open('shared/t1.py').read().split("def unpack_raw12")[0])

def tvec(ek):
    v=M.M.decode_vector(ek[:-32],3,12,is_ntt=True)
    return [[c%Q for c in v[i,0].coeffs] for i in range(3)]

def Amat(rho):
    A=M._generate_matrix_from_seed(rho)
    return [[[c%Q for c in A[i,j].coeffs] for j in range(3)] for i in range(3)]

def solve_per_quad(D, dt, k=3):
    """solve sum_j D[i][j] * s_j = dt[i] per coefficient pair; D[i][j] = 256 coeff list"""
    out=[[0]*256 for _ in range(k)]
    for p in range(128):
        z = Z[64+p//2] % Q if p%2==0 else (-Z[64+p//2])%Q
        n=k*2
        Aug=[[0]*(n+1) for _ in range(n)]
        for i in range(k):
            for j in range(k):
                a0=D[i][j][2*p]; a1=D[i][j][2*p+1]
                Aug[2*i][2*j]=(Aug[2*i][2*j]+a0)%Q
                Aug[2*i][2*j+1]=(Aug[2*i][2*j+1]+z*a1)%Q
                Aug[2*i+1][2*j]=(Aug[2*i+1][2*j]+a1)%Q
                Aug[2*i+1][2*j+1]=(Aug[2*i+1][2*j+1]+a0)%Q
            Aug[2*i][n]=dt[i][2*p]
            Aug[2*i+1][n]=dt[i][2*p+1]
        # gauss
        r=0; piv=[]
        for c in range(n):
            pr=None
            for i2 in range(r,n):
                if Aug[i2][c]%Q: pr=i2;break
            if pr is None: return None
            Aug[r],Aug[pr]=Aug[pr],Aug[r]
            inv=pow(Aug[r][c],-1,Q)
            Aug[r]=[(x*inv)%Q for x in Aug[r]]
            for i2 in range(n):
                if i2!=r and Aug[i2][c]%Q:
                    f=Aug[i2][c]
                    Aug[i2]=[(Aug[i2][t]-f*Aug[r][t])%Q for t in range(n+1)]
            piv.append(c); r+=1
        for j in range(k):
            out[j][2*p]=Aug[2*j][n]; out[j][2*p+1]=Aug[2*j+1][n]
    return out

def maxsmall(s_coeffs):
    m=0; vals=[]
    for poly in s_coeffs:
        rec=R(poly, is_ntt=True).from_ntt().coeffs
        c=[x%Q for x in rec]
        c=[x if x<Q//2+1 else x-Q for x in c]
        vals.append((max(abs(x) for x in c), c))
    return max(v[0] for v in vals), vals

As={}; Ts={}
for ts,slot,ek in slots:
    As[slot]=Amat(ek[-32:]); Ts[slot]=tvec(ek)
print("loaded")
results=[]
for i,j in itertools.combinations(range(16),2):
    D=[[[(As[i][r][c][k]-As[j][r][c][k])%Q for k in range(256)] for c in range(3)] for r in range(3)]
    dt=[[(Ts[i][r][k]-Ts[j][r][k])%Q for k in range(256)] for r in range(3)]
    s=solve_per_quad(D,dt)
    if s is None:
        print(f"pair {i},{j}: singular"); continue
    ms,vals=maxsmall(s)
    results.append((ms,i,j,vals))
    if ms<=4:
        print(f"*** pair {i},{j} maxsmall={ms}")
results.sort()
for ms,i,j,_ in results[:6]: print(f"pair {i:2d},{j:2d} maxsmall={ms}")
