import sys, pickle, itertools
sys.path.insert(0,'/tmp/kpylib')
from kyber_py.ml_kem import ML_KEM_768 as M
Q=3329
R=M.R
Z=R.ntt_zetas

def getc(p): return list(p.coeffs)

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
                f=Aug[i][c]%q
                Aug[i]=[(x-f*y)%q for x,y in zip(Aug[i],Aug[r])]
        piv.append(c); r+=1
        if r==n: break
    if len(piv)<n: return None
    x=[0]*n
    for i,c in enumerate(piv): x[c]=Aug[i][n]
    return x

def solve_s_hat(ek, model='e0'):
    """model: 'e0' t=A s ; 'es' t=(A+I) s (e=s, nonce-stuck); 'e0_sdup' t=A*s with s0=s1=s2"""
    tb,rho=ek[:-32],ek[-32:]
    t_hat=M.M.decode_vector(tb,3,12,is_ntt=True)
    A=M._generate_matrix_from_seed(rho)  # A[i,j] with xof rho||j||i
    Ac=[[getc(A[i,j]) for j in range(3)] for i in range(3)]
    tc=[getc(t_hat[i,0]) for i in range(3)]
    s_coeffs=[[0]*256 for _ in range(3)]
    singular=0
    for qi in range(64):
        base=4*qi
        for half in range(2):
            z = Z[64+qi] if half==0 else (-Z[64+qi])%Q
            # unknowns x[3*2] = s_j[h][0],s_j[h][1]
            rows=[]; b=[]
            for m in range(3):
                # real equation
                row=[0]*6
                for j in range(3):
                    a0=Ac[m][j][base+2*half]; a1=Ac[m][j][base+2*half+1]
                    row[2*j]=(row[2*j]+a0)%Q
                    row[2*j+1]=(row[2*j+1]+z*a1)%Q
                if model=='es' and m==m:  # + s_i coefficientwise (identity) for output poly m: add s_m
                    row[2*m]=(row[2*m]+1)%Q
                rows.append(row); b.append(tc[m][base+2*half])
                # imag equation
                row=[0]*6
                for j in range(3):
                    a0=Ac[m][j][base+2*half]; a1=Ac[m][j][base+2*half+1]
                    row[2*j]=(row[2*j]+a1)%Q
                    row[2*j+1]=(row[2*j+1]+a0)%Q
                if model=='es':
                    row[2*m+1]=(row[2*m+1]+1)%Q
                rows.append(row); b.append(tc[m][base+2*half+1])
            sol=solve_mod(rows,b)
            if sol is None: singular+=1; continue
            for j in range(3):
                s_coeffs[j][base+2*half]=sol[2*j]
                s_coeffs[j][base+2*half+1]=sol[2*j+1]
    return s_coeffs, singular, (tb,rho,t_hat,A)

def encode_vec(coeffs):
    from kyber_py.polynomials.polynomials import PolynomialNTT
    ps=[PolynomialNTT(R,c) for c in coeffs]
    return b''.join(p.encode(12) for p in ps)

def try_key(ek, dk_pke, ct):
    """return (m,K,reenc_match)"""
    m=M._k_pke_decrypt(dk_pke, ct)
    K,r=M._G(m+M._H(ek))
    try:
        c2=M._k_pke_encrypt(ek,m,r)
    except Exception as e:
        return m,None,False
    return m,K,c2==ct

if __name__=='__main__':
    d=pickle.load(open('work/diag.pkl','rb'))
    slots=d['slots']; hs=d['hslots']
    # first validate on synthetic keypair
    import os
    kd=bytes(range(32)); kz=bytes(range(32,64))
    sek,sdk=M._keygen_internal(kd,kz)
    sdk_pke=sdk[:1152]
    sct=bytes.fromhex('00'*0)  # no
    # generate a ct
    m0=bytes(range(200,232))
    K0,ct0=M._encaps_internal(sek,m0)
    sc,sing,info=solve_s_hat(sek,'e0')
    dkp=encode_vec(sc)
    mm,KK,ok=try_key(sek,dkp,ct0)
    print('SYNTH e0-solve on real keypair: reenc match (should be False):',ok)
    # now synthetic e=0 keypair: build keygen manually with e=0
    # Use internal: compute rho,sigma, s, e, set e=0
    rho,sigma=M._G(kd+bytes([3]))
    A=M._generate_matrix_from_seed(rho)
    s,N=M._generate_error_vector(sigma,2,0)
    s_hat=s.to_ntt()
    t_hat=A@s_hat  # e=0
    ek_fault=t_hat.encode(12)+rho
    K0b,ct0b=M._encaps_internal(ek_fault,m0)
    sc2,sing2,_=solve_s_hat(ek_fault,'e0')
    dkp2=encode_vec(sc2)
    mm2,KK2,ok2=try_key(ek_fault,dkp2,ct0b)
    print('SYNTH e0 fault: reenc match (should be True):',ok2,'K match',KK2==K0b,'m match',mm2==m0)
    # s=0 test: ek with s=0 => t=e
    e,N=M._generate_error_vector(sigma,2,3)
    e_hat=e.to_ntt()
    ek_s0=e_hat.encode(12)+rho
    K0c,ct0c=M._encaps_internal(ek_s0,m0)
    # decrypt with zero dk
    mm3=M._k_pke_decrypt(bytes(1152),ct0c)
    print('SYNTH s=0: m recover via zero-dk?',mm3==m0)
    _,KK3,ok3=try_key(ek_s0,bytes(1152),ct0c)
    print('SYNTH s=0: reenc match',ok3,'K',KK3==K0c)

def real_scan():
    d=pickle.load(open('work/diag.pkl','rb'))
    slots=d['slots']; hs=d['hslots']
    for (ts,slot,ek),(hslot,ct,tag) in zip(slots,hs):
        res={}
        for model in ('e0','es'):
            sc,sing,info=solve_s_hat(ek,model)
            dkp=encode_vec(sc)
            m,K,ok=try_key(ek,dkp,ct)
            res[model]=(ok,K.hex() if K else None,sing)
        # s=0
        m,K,ok=try_key(ek,bytes(1152),ct)
        res['s0']=(ok,K.hex() if K else None,0)
        print('slot',slot,{k:(v[0],v[2]) for k,v in res.items()})
        if any(v[0] for v in res.values()):
            print('  *** HIT', {k:v for k,v in res.items() if v[0]})
            for k,v in res.items():
                if v[0]: print('  model',k,'K',v[1],'tag',tag.hex())
