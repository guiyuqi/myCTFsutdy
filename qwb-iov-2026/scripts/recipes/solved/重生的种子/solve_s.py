import sys, pickle
sys.path.insert(0,'~/.ctfagent/state/sessions/run-37596/workspace/shared')
import kyber as kb
Q=kb.Q

def solve_mod(Amat, bvec):
    n=len(bvec); M=[row[:]+[bvec[i]%Q] for i,row in enumerate(Amat)]
    piv=[]
    r=0
    for c in range(n):
        p=None
        for i in range(r,n):
            if M[i][c]%Q: p=i;break
        if p is None: continue
        M[r],M[p]=M[p],M[r]
        inv=pow(M[r][c],-1,Q)
        M[r]=[(x*inv)%Q for x in M[r]]
        for i in range(n):
            if i!=r and M[i][c]%Q:
                f=M[i][c]%Q
                M[i]=[(x-f*y)%Q for x,y in zip(M[i],M[r])]
        piv.append(c); r+=1
        if r==n: break
    if len(piv)<n: return None  # singular
    x=[0]*n
    for i,c in enumerate(piv): x[c]=M[i][n]
    return x

def build_quads(A, use_tomont, transposed):
    """Return per-quad (64 quads) 12x12 linear map from s-coeff vector -> (tomont? basemul) t vector."""
    zetas=[kb.ZETAS[64+i] for i in range(64)]
    quads=[]
    for qi in range(64):
        base=4*qi
        M=[[0]*12 for _ in range(12)]
        for col in range(12):
            # unit vector: poly j=col//4, coord=col%4
            j=col//4; coord=col%4
            out=[0]*12  # 3 output polys x 4 coords
            for m in range(3):
                acc=[0]*4
                for jj in range(3):
                    a=A[m][jj] if not transposed else A[jj][m]
                    b=[0,0,0,0]
                    if jj==j: b[coord]=1
                    z=zetas[qi]
                    r0,r1=kb.basemul(a[base],a[base+1],b[0],b[1],z)
                    r2,r3=kb.basemul(a[base+2],a[base+3],b[2],b[3],(-z)%Q)
                    acc=[(acc[0]+r0)%Q,(acc[1]+r1)%Q,(acc[2]+r2)%Q,(acc[3]+r3)%Q]
                if use_tomont:
                    acc=kb.poly_tomont(acc)
                for c4 in range(4):
                    out[m*4+c4]=acc[c4]
            for row in range(12):
                M[row][col]=out[row]
        quads.append(M)
    return quads

def solve_slot(ek, use_tomont=True, transposed=False):
    tpart=ek[:1152]; rho=ek[1152:1184]
    tvals=kb.unpack12_std(tpart)
    A=kb.gen_matrix(rho, transposed=transposed)
    quads=build_quads(A, use_tomont, transposed)
    spolys=[[0]*256 for _ in range(3)]
    sing=0
    for qi in range(64):
        base=4*qi
        bvec=[]
        for m in range(3):
            bvec += tvals[m*256+base:m*256+base+4]
        x=solve_mod(quads[qi], bvec)
        if x is None:
            sing+=1; continue
        for col in range(12):
            j=col//4; c=col%4
            spolys[j][base+c]=x[col]
    return spolys, sing, len(tvals)

if __name__=='__main__':
    d=pickle.load(open('work/diag.pkl','rb'))
    slots=d['slots']
    for (ts,slot,ek) in slots:
        if slot not in (3,9,14,0): continue
        for use_tomont in (True,False):
            for transposed in (False,True):
                sp, sing, _ = solve_slot(ek, use_tomont, transposed)
                s=kb.invntt(sp[0]); s=[x if x<Q//2 else x-Q for x in s]
                # scale-aware smallness check: allow global scalar
                bad=sum(1 for x in s if abs(x)>2)
                maxv=max(abs(x) for x in s)
                print(f'slot {slot} tomont={use_tomont} transp={transposed} singular={sing} bad={bad} max={maxv} head={s[:8]}')
