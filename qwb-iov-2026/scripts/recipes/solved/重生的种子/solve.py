import numpy as np, sys, hashlib
sys.path.insert(0,'shared')
from mlkem import *

# find sqrt(-1) mod Q
z = None
for g in range(2, Q):
    c = pow(g, (Q-1)//4, Q)
    if c*c % Q == Q-1:
        z = c; break
print("sqrt(-1) =", z, "check", z*z % Q == Q-1)
INV2 = pow(2,-1,Q); INV2Z = pow(2*z % Q,-1,Q)

def solve_sys3(M, T):
    """3x3 over Z_q; M list of lists ints, T list ints. returns list or None"""
    A = [[int(x)%Q for x in row]+[int(T[i])%Q] for i,row in enumerate(M)]
    n = 3
    for col in range(n):
        piv = None
        for r in range(col,n):
            if A[r][col] % Q: piv = r; break
        if piv is None: return None
        A[col],A[piv] = A[piv],A[col]
        inv = pow(A[col][col],-1,Q)
        A[col] = [x*inv % Q for x in A[col]]
        for r in range(n):
            if r != col and A[r][col]:
                f = A[r][col]
                A[r] = [(A[r][k] - f*A[col][k]) % Q for k in range(n+1)]
    return [A[i][n] for i in range(n)]

def recover_sk(ek, order=(0,1)):
    """order: which byte order in SampleNTT index, (a,b) meaning Â[i][j]=SampleNTT(rho||?||?)"""
    rho = ek[1152:1184]
    th = [decode12(ek[i*384:(i+1)*384]) for i in range(3)]
    Ah = [[None]*3 for _ in range(3)]
    for i in range(3):
        for j in range(3):
            if order == (0,1):   # A[i][j] = SampleNTT(rho||j||i)
                Ah[i][j] = sample_ntt(rho, j, i)
            else:                # A[i][j] = SampleNTT(rho||i||j)
                Ah[i][j] = sample_ntt(rho, i, j)
    sh = [np.zeros(256, dtype=np.int64) for _ in range(3)]
    for p in range(128):
        for lam in (z, (-z) % Q):
            M = [[ (int(Ah[i][j][2*p]) + int(Ah[i][j][2*p+1])*lam) % Q for j in range(3)] for i in range(3)]
            T = [ (int(th[i][2*p]) + int(th[i][2*p+1])*lam) % Q for i in range(3)]
            S = solve_sys3(M, T)
            if S is None:
                return None
            if lam == z: Sp = S
            else: Sm = S
        for j in range(3):
            sh[j][2*p]   = (Sp[j] + Sm[j]) * INV2 % Q
            sh[j][2*p+1] = (Sp[j] - Sm[j]) * INV2Z % Q
    s = [invntt(x) for x in sh]
    return th, sh, s

def check_ek(ek, order=(0,1), verbose=True):
    th, sh, s = recover_sk(ek, order)
    cs = [np.array([center(x) for x in p]) for p in s]
    small = all(np.max(np.abs(c)) <= 2 for c in cs)
    # forward check
    t2 = []
    for i in range(3):
        acc = np.zeros(256, dtype=np.int64)
        for j in range(3):
            acc = (acc + basemul_ntt(sh[j].copy(), np.zeros(0) if False else None) if False else acc)
        t2.append(acc)
    return th, sh, cs, small

if __name__ == "__main__":
    d = open('work/ext_etc_bcm_diag.bin','rb').read()
    R = d[0xc0:0xc0+19068]
    cnt = int.from_bytes(R[8:12],'big'); off = 12; eks=[]
    for i in range(cnt):
        slot = R[off+4]; el = int.from_bytes(R[off+5:off+7],'big')
        eks.append((slot, R[off+7:off+7+el])); off += 7+el
    for slot, ek in eks:
        for order in [(0,1),(1,0)]:
            th, sh, s = recover_sk(ek, order)
            cs = [np.array([center(x) for x in p]) for p in s]
            mx = max(int(np.max(np.abs(c))) for c in cs)
            # forward verify t = A∘s
            ok = True
            for i in range(3):
                acc = np.zeros(256, dtype=np.int64)
                for j in range(3):
                    Aij = sample_ntt(ek[1152:1184], j, i) if order==(0,1) else sample_ntt(ek[1152:1184], i, j)
                    acc = (acc + basemul_ntt(sh[j], Aij)) % Q
                if not np.array_equal(acc, th[i]): ok = False
            print(f"slot{slot:2d} order={order} maxcoef={mx:3d} forward_match={ok}")
