import sys, struct, itertools
sys.path.append('/tmp/kpylib')
from kyber_py.ml_kem import ML_KEM_768 as K
exec(open('shared/t1.py').read().split("def unpack_raw12")[0])
q=3329
R=K.R
Z=R.ntt_zetas
def zeta_p(p):
    quad=p//2
    z=Z[64+quad]
    return z%q if p%2==0 else (-z)%q
def unpack_raw12(b):
    v=[]
    for i in range(0,len(b),3):
        v.append(b[i]|((b[i+1]&0xF)<<8)); v.append((b[i+1]>>4)|(b[i+2]<<4))
    return v
def ek_t_polys(ek):
    t=unpack_raw12(ek[:1152])
    return [t[256*i:256*(i+1)] for i in range(3)]
# ---- self test of the linear algebra ----
def solve6(M66, b6):
    # M66: 6x6 list of lists mod q ; b6 list ; returns solution or None
    A=[row[:]+[b6[i]] for i,row in enumerate(M66)]
    n=6
    for c in range(n):
        piv=None
        for r in range(c,n):
            if A[r][c]%q:
                piv=r;break
        if piv is None: return None
        A[c],A[piv]=A[piv],A[c]
        inv=pow(A[c][c],-1,q)
        A[c]=[(x*inv)%q for x in A[c]]
        for r in range(n):
            if r!=c and A[r][c]%q:
                f=A[r][c]
                A[r]=[(A[r][k]-f*A[c][k])%q for k in range(n+1)]
    return [A[i][n]%q for i in range(n)]
def solve_module(A_hat_coeffs, t_hat_coeffs, k=3):
    """A_hat_coeffs[i][j][256], t_hat_coeffs[i][256] -> s_hat coeffs [k][256] or None"""
    s_out=[[0]*256 for _ in range(k)]
    solvable=0
    for p in range(128):
        z=zeta_p(p)
        Mm=[[0]*6 for _ in range(6)]
        bb=[0]*6
        for i in range(k):
            for j in range(k):
                a0=A_hat_coeffs[i][j][2*p]; a1=A_hat_coeffs[i][j][2*p+1]
                Mm[2*i][2*j]=(Mm[2*i][2*j]+a0)%q
                Mm[2*i][2*j+1]=(Mm[2*i][2*j+1]+z*a1)%q
                Mm[2*i+1][2*j]=(Mm[2*i+1][2*j]+a1)%q
                Mm[2*i+1][2*j+1]=(Mm[2*i+1][2*j+1]+a0)%q
            bb[2*i]=t_hat_coeffs[i][2*p]
            bb[2*i+1]=t_hat_coeffs[i][2*p+1]
        sol=solve6(Mm,bb)
        if sol is None:
            return None
        solvable+=1
        for j in range(k):
            s_out[j][2*p]=sol[2*j]; s_out[j][2*p+1]=sol[2*j+1]
    return s_out
def maxsmall(coeffs):
    out=[]
    for c in coeffs:
        c%=q
        out.append(c if c<1665 else c-q)
    return max(abs(x) for x in out), out
# sanity: homomorphism check
import random as pyrand
a=[pyrand.randrange(q) for _ in range(256)]; b=[pyrand.randrange(q) for _ in range(256)]
pa=R(a); pb=R(b)
prod=pa*pb  # normal mul (schoolbook)
pa_hat=pa.to_ntt(); pb_hat=pb.to_ntt()
prod2=pa_hat*pb_hat
print("hom check:", prod.coeffs==prod2.from_ntt().coeffs)
# test solve on synthetic keygen with e=0
d=bytes(range(32)); zz=bytes(32)
rho,sigma=K._G(d+bytes([3]))
A_hat=K._generate_matrix_from_seed(rho)
s,N=K._generate_error_vector(sigma,K.eta_1,0)
e,N=K._generate_error_vector(sigma,K.eta_1,N)
s_hat=s.to_ntt(); e_hat=e.to_ntt()
# noiseless t = A s (normal domain)
t_polys=[ R([ (A_hat[i,0].coeffs[k]*s_hat[0,0].coeffs[k]) for k in range(1)] ) for i in range(3)]
th=[]
for i in range(3):
    acc=[0]*256
    for j in range(3):
        a=A_hat[i,j].coeffs; b=s_hat[j,0].coeffs
        # elementwise in NTT domain via basemul
        for pp in range(128):
            z=zeta_p(pp)
            a0,a1=a[2*pp],a[2*pp+1]; b0,b1=b[2*pp],b[2*pp+1]
            acc[2*pp]=(acc[2*pp]+a0*b0+z*a1*b1)%q
            acc[2*pp+1]=(acc[2*pp+1]+a1*b0+a0*b1)%q
    th.append(acc)
Ah=[[A_hat[i,j].coeffs for j in range(3)] for i in range(3)]
sol=solve_module(Ah,th)
print("synthetic e=0 solve ok:", sol is not None)
if sol:
    rec=[]
    for j in range(3):
        rec+=R(sol[j], is_ntt=True).from_ntt().coeffs
    true=[]
    for j in range(3): true+=s[j,0].coeffs
    print("recovered==true:", [x%q for x in rec]==[x%q for x in true])
    print("maxsmall recovered:", maxsmall(rec)[0])
