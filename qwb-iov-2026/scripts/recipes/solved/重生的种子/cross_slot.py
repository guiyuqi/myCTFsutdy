"""Hypothesis (Campaign-B g6): voltage droop at keygen -> RNG sigma reused across
fault slots, so several slots share the SAME secret s (and same e).  Then for any
pair (i,j):  t_i - t_j = (A_i - A_j) . s   (noise cancels exactly).
Solve per NTT-coefficient-pair 6x6 linear system and check InvNTT coeffs are CBD-sized.
"""
import sys, pickle, itertools
sys.path.insert(0,'/tmp/kpylib')
from kyber_py.ml_kem import ML_KEM_768 as M
from kyber_py.polynomials.polynomials import PolynomialNTT, Polynomial
Q=3329
R=M.R
Z=R.ntt_zetas

def coeffs(p): return list(p.coeffs)

def solve_mod(Amat,bvec,q=Q):
    n=len(bvec); Aug=[row[:]+[bvec[i]%q] for i,row in enumerate(Amat)]
    piv=[]; r=0
    for c in range(n):
        p=None
        for i in range(r,n):
            if Aug[i][c]%q: p=i;break
        if p is None: continue
        Aug[r],Aug[p]=Aug[p],Aug[r]
        inv=pow(Aug[r][c],-1,q)
        Aug[r]=[(x*inv)%q for x in Aug[r]]
        for i in range(n):
            if i!=r and Aug[i][c]%q:
                f=Aug[i][c]
                Aug[i]=[(x-f*y)%q for x,y in zip(Aug[i],Aug[r])]
        piv.append(c); r+=1
        if r==n: break
    if len(piv)<n: return None
    x=[0]*n
    for i,c in enumerate(piv): x[c]=Aug[i][n]
    return x

def centered(x):
    x%=Q
    return x-Q if x>Q//2 else x

def solve_from(Ac, tc):
    """Ac[m][n][256] in NTT domain, tc[m][256] -> s coeffs (NTT domain) [3][256]"""
    s=[[0]*256 for _ in range(3)]
    for qi in range(64):
        base=4*qi
        for half in range(2):
            z = Z[64+qi] if half==0 else (-Z[64+qi])%Q
            rows=[];b=[]
            for m in range(3):
                row=[0]*6
                for j in range(3):
                    a0=Ac[m][j][base+2*half]; a1=Ac[m][j][base+2*half+1]
                    row[2*j]=(row[2*j]+a0)%Q
                    row[2*j+1]=(row[2*j+1]+z*a1)%Q
                rows.append(row); b.append(tc[m][base+2*half])
                row=[0]*6
                for j in range(3):
                    a0=Ac[m][j][base+2*half]; a1=Ac[m][j][base+2*half+1]
                    row[2*j]=(row[2*j]+a1)%Q
                    row[2*j+1]=(row[2*j+1]+a0)%Q
                rows.append(row); b.append(tc[m][base+2*half+1])
            sol=solve_mod(rows,b)
            if sol is None: return None
            for j in range(3):
                s[j][base+2*half]=sol[2*j]
                s[j][base+2*half+1]=sol[2*j+1]
    return s

def pack_t(ek):
    tb,rho=ek[:-32],ek[-32:]
    th=M.M.decode_vector(tb,3,12,is_ntt=True)
    return [coeffs(th[m,0]) for m in range(3)], rho

def encode_vec(coeffs_ntt):
    return b''.join(PolynomialNTT(R,c).encode(12) for c in coeffs_ntt)

def invntt_normal(s_hat):
    out=[]
    for j in range(3):
        p=PolynomialNTT(R,list(s_hat[j])).from_ntt()
        out+= [centered(x) for x in p.coeffs]
    return out

if __name__=='__main__':
    d=pickle.load(open('work/diag.pkl','rb'))
    slots=d['slots']; hs=d['hslots']
    print('slot entry example:', slots[0][0], slots[0][1], len(slots[0][2]))
    eks=[]
    for st in slots:
        ek = st[2] if not isinstance(st[2],(bytes,bytearray)) else st[2]
        eks.append(bytes(ek))
    print('ek lens', {len(e) for e in eks})
    T=[]; RHO=[]; A=[]
    for ek in eks:
        t,rho=pack_t(ek); T.append(t); RHO.append(rho)
        A.append([[coeffs(M._generate_matrix_from_seed(rho)[m,n]) for n in range(3)] for m in range(3)])
    print('rho distinct:', len(set(RHO)))
    res={}
    for i,j in itertools.combinations(range(16),2):
        Ac=[[[ (A[i][m][n][k]-A[j][m][n][k])%Q for k in range(256)] for n in range(3)] for m in range(3)]
        tc=[[ (T[i][m][k]-T[j][m][k])%Q for k in range(256)] for m in range(3)]
        s=solve_from(Ac,tc)
        if s is None:
            res[(i,j)]=None; continue
        cf=invntt_normal(s)
        mx=max(abs(x) for x in cf)
        ns=sum(1 for x in cf if abs(x)>2)
        res[(i,j)]=(mx,ns,s)
        if mx<=2:
            print('*** HIT pair',i,j,'maxsmall',mx)
        elif (i,j) in [(3,9),(3,14),(9,14),(0,3),(0,9),(0,14)]:
            print('pair',i,j,'maxsmall',mx,'nbig',ns)
    vals=sorted(v[0] for v in res.values() if v)
    print('maxsmall over all 120 pairs: min',vals[0],'median',vals[len(vals)//2],'max',vals[-1])
    pickle.dump({'res':{k:(v[0],v[1]) for k,v in res.items()}},open('shared/cross_slot_res.pkl','wb'))
