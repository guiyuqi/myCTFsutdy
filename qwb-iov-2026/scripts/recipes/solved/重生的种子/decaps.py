import numpy as np, pickle, hashlib, sys
sys.path.insert(0,'shared')
from mlkem import *

def decompress(b, d, n):
    v=np.zeros(n,dtype=np.int64); acc=0; bits=0; k=0; mask=(1<<d)-1
    for byte in b:
        acc |= int(byte)<<bits; bits+=8
        while bits>=d and k<n:
            v[k]=acc&mask; k+=1; acc>>=d; bits-=d
    return v

def compress_int(x, d):
    x = int(x) % Q
    return ((x << d) + Q//2) // Q % (1<<d)

def H(x): return hashlib.sha3_256(x).digest()
def G(x): return hashlib.sha3_512(x).digest()

def dexpand(y, d):
    return ((y.astype(np.int64) * Q + (1 << (d-1))) >> d) % Q

def pke_decrypt(sh, ct):
    """sh: list of 3 NTT-domain polys = s_hat"""
    u = [dexpand(decompress(ct[i*320:(i+1)*320], 10, 256), 10) for i in range(3)]
    v = dexpand(decompress(ct[960:1088], 4, 256), 4)
    acc = np.zeros(256, dtype=np.int64)
    for i in range(3):
        acc = (acc + basemul_ntt(u[i], sh[i])) % Q
    w = (v - invntt(acc)) % Q
    mbits = np.array([compress_int(x,1) for x in w], dtype=np.uint8)
    # pack 256 bits -> 32 bytes
    mbyte = bytearray(32)
    for i in range(256):
        mbyte[i//8] |= int(mbits[i]) << (i%8)
    return bytes(mbyte)

def decaps(sh, ek, ct):
    m = pke_decrypt(sh, ct)
    Kp = G(m + H(ek))
    K = hashlib.shake_256(Kp + H(ct)).digest(32)
    return m, Kp, K
