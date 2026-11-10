"""Fresh (Campaign B g3) hypothesis: fault hit the ENCAPS side (e1/e2 or the message
randomness), not keygen.  Uses ONLY public data -> public-key attack.

FIPS 203 K-PKE.Encrypt:
    u = InvNTT( A^T o y ) + e1 ,   v = InvNTT( t^T o y ) + e2 + mu
e1 == 0            ->  y = (A^T)^{-1} u   (exact, no secret needed)
e1 == 0 and e2==0  ->  v - InvNTT(t^T o y) == mu  (mu in {0,1665}) -> m public
"""
import numpy as np, hashlib, pickle, sys
sys.path.insert(0, 'shared')
from mlkem import Q, ZETAS, ntt, invntt, basemul_ntt, sample_ntt

d = open('work/ext_etc_bcm_diag.bin', 'rb').read()
R = d[0xc0:0xc0+19068]
off = 12; EKS = {}
for i in range(16):
    s2 = R[off+4]; el = int.from_bytes(R[off+5:off+7], 'big')
    EKS[s2] = R[off+7:off+7+el]; off += 7+el
Hrec = d[0x4b3c:0x4b3c+18124]
cnt = int.from_bytes(Hrec[8:12], 'little'); off = 12; HS = {}
order = []
for i in range(cnt):
    slot = Hrec[off]; cl = int.from_bytes(Hrec[off+4:off+8], 'little')
    ct = Hrec[off+8:off+8+cl]; o2 = off+8+cl
    tl = int.from_bytes(Hrec[o2:o2+4], 'little'); tag = Hrec[o2+4:o2+4+tl]
    HS[slot] = (ct, tag); order.append(slot); off = o2+4+tl
PAYLOAD = d[0x9208:0x9208+75]

def decomp(b, dd, n):
    v = np.zeros(n, dtype=np.int64); acc = 0; bits = 0; k = 0; mask = (1 << dd) - 1
    for byte in b:
        acc |= int(byte) << bits; bits += 8
        while bits >= dd and k < n:
            v[k] = acc & mask; k += 1; acc >>= dd; bits -= dd
    return v

def enc_d(vals, dd):
    out = bytearray(); acc = 0; bits = 0
    for x in vals:
        acc |= (int(x) % (1 << dd)) << bits; bits += dd
        while bits >= 8:
            out.append(acc & 0xff); acc >>= 8; bits -= 8
    if bits: out.append(acc & 0xff)
    return bytes(out)

def dexpand(y, dd):
    return ((np.asarray(y, dtype=np.int64) * Q + (1 << (dd-1))) >> dd) % Q

def compress(x, dd):
    x = np.asarray(x, dtype=np.int64) % Q
    return ((x << dd) + Q//2) // Q % (1 << dd)

def decode12(b):
    out = np.zeros(256, dtype=np.int64)
    for i in range(0, 384, 3):
        v = b[i] | (b[i+1] << 8) | (b[i+2] << 16)
        out[(i//3)*2] = v & 0xfff
        out[(i//3)*2+1] = v >> 12
    return out

def encode12(p):
    out = bytearray(); p = [int(x) % Q for x in p]
    for i in range(0, 256, 2):
        v = p[i] | (p[i+1] << 12)
        out += bytes([v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff])
    return bytes(out)

def cbd2(bs):
    bits = []
    for b in bs:
        for k in range(8):
            bits.append((b >> k) & 1)
    c = [((bits[4*i] + bits[4*i+1]) - (bits[4*i+2] + bits[4*i+3])) % Q for i in range(256)]
    return np.array(c, dtype=np.int64)

def prf(seed, n):
    # eta=2 -> 64*eta = 128 bytes
    return hashlib.shake_128(seed + bytes([n])).digest(128)

def genA(rho, order='ji'):
    A = [[None]*3 for _ in range(3)]
    for i in range(3):
        for j in range(3):
            seed = rho + (bytes([j, i]) if order == 'ji' else bytes([i, j]))
            A[i][j] = sample_ntt(seed, 0, 0)
    return A

def solve_pair(blocks, rhs):
    n = 6
    M = []
    for i in range(3):
        row0 = [0]*n; row1 = [0]*n
        for j in range(3):
            c = blocks[i][j]
            for s in range(2):
                row0[2*j+s] = int(c[0][s]) % Q
                row1[2*j+s] = int(c[1][s]) % Q
        M.append(row0 + [int(rhs[i][0]) % Q])
        M.append(row1 + [int(rhs[i][1]) % Q])
    for col in range(n):
        piv = next((r for r in range(col, n) if M[r][col] % Q), None)
        if piv is None: return None
        M[col], M[piv] = M[piv], M[col]
        inv = pow(M[col][col] % Q, Q-2, Q)
        M[col] = [(x*inv) % Q for x in M[col]]
        for r in range(n):
            if r != col and M[r][col] % Q:
                f = M[r][col]
                M[r] = [(M[r][c] - f*M[col][c]) % Q for c in range(n+1)]
    sol = [M[i][n] for i in range(n)]
    return [(sol[2*i], sol[2*i+1]) for i in range(3)]

def pair_blocks(A, transpose, p):
    bl = [[None]*3 for _ in range(3)]
    z = int(ZETAS[64 + p//2])
    if p % 2: z = (-z) % Q
    for i in range(3):
        for j in range(3):
            a = A[j][i] if transpose else A[i][j]
            a0 = int(a[2*p]); a1 = int(a[2*p+1])
            bl[i][j] = [[a0, (a1*z) % Q], [a1, a0]]
    return bl

def solve_y(u, A, transpose=True):
    uh = [ntt(x) for x in u]
    y = [np.zeros(256, dtype=np.int64) for _ in range(3)]
    for p in range(128):
        bl = pair_blocks(A, transpose, p)
        rhs = [(int(uh[i][2*p]), int(uh[i][2*p+1])) for i in range(3)]
        sol = solve_pair(bl, rhs)
        if sol is None: return None
        for i in range(3):
            y[i][2*p] = sol[i][0] % Q; y[i][2*p+1] = sol[i][1] % Q
    return y

def cd(a, b):
    dd = abs(int(a) - int(b)) % Q
    return min(dd, Q-dd)

def residual(w):
    return np.array([min(cd(x, 0), cd(x, 1665)) for x in (np.asarray(w) % Q)])

def t_dot_y(that, y, scale=1):
    acc = np.zeros(256, dtype=np.int64)
    for i in range(3):
        acc = (acc + basemul_ntt((that[i]*scale) % Q, y[i])) % Q
    return acc

def bits_to_m(w):
    mb = compress(w, 1)
    out = bytearray(32)
    for i in range(256):
        out[i//8] |= int(mb[i]) << (i % 8)
    return bytes(out)

def selftest():
    rng = np.random.default_rng(7)
    rho = bytes(rng.integers(0, 256, 32, dtype=np.uint8))
    sig = bytes(rng.integers(0, 256, 32, dtype=np.uint8))
    A = genA(rho, 'ji')
    sh = [ntt(cbd2(prf(sig, i))) for i in range(3)]
    eh = [ntt(cbd2(prf(sig, 3+i))) for i in range(3)]
    that = []
    for i in range(3):
        acc = np.zeros(256, dtype=np.int64)
        for j in range(3):
            acc = (acc + basemul_ntt(A[i][j], sh[j])) % Q
        that.append((acc + eh[i]) % Q)
    m = bytes(rng.integers(0, 256, 32, dtype=np.uint8))
    rbytes = bytes(rng.integers(0, 256, 32, dtype=np.uint8))
    y = [ntt(cbd2(prf(rbytes, i))) for i in range(3)]
    e1 = [cbd2(prf(rbytes, 3+i)) for i in range(3)]
    e2 = cbd2(prf(rbytes, 6))
    mu = dexpand(np.array([(m[i//8] >> (i % 8)) & 1 for i in range(256)], dtype=np.int64), 1)
    for tag, n1, n2 in (('normal', True, True), ('noiseless', False, False)):
        u = []
        for i in range(3):
            acc = np.zeros(256, dtype=np.int64)
            for j in range(3):
                acc = (acc + basemul_ntt(A[j][i], y[j])) % Q
            u.append((invntt(acc) + (e1[i] if n1 else 0)) % Q)
        acc = np.zeros(256, dtype=np.int64)
        for i in range(3):
            acc = (acc + basemul_ntt(that[i], y[i])) % Q
        v = (invntt(acc) + (e2 if n2 else 0) + mu) % Q
        ct = b''.join([enc_d(compress(x, 10), 10) for x in u]) + enc_d(compress(v, 4), 4)
        uu = [dexpand(decomp(ct[i*320:(i+1)*320], 10, 256), 10) for i in range(3)]
        vv = dexpand(decomp(ct[960:1088], 4, 256), 4)
        yrec = solve_y(uu, A, transpose=True)
        wt = (vv - invntt(t_dot_y(that, yrec))) % Q
        res = residual(wt)
        mrec = bits_to_m(wt)
        print(f'SELFTEST[{tag}] residual max={int(res.max()):5d} mean={res.mean():7.1f} m_ok={mrec==m}')
        # also verify decrypt with secret s works
        acc = np.zeros(256, dtype=np.int64)
        for i in range(3):
            acc = (acc + basemul_ntt(ntt(uu[i]), sh[i])) % Q
        w = (vv - invntt(acc)) % Q
        print(f'   decaps-with-s m_ok={bits_to_m(w)==m}  resmax={int(residual(w).max())}')

if __name__ == '__main__':
    selftest()
