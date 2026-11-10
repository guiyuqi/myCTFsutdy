import hashlib
import numpy as np

Q = 3329
K = 3
N = 256

def brv7(x):
    r = 0
    for i in range(7):
        r |= ((x >> i) & 1) << (6 - i)
    return r

ZETAS = np.array([pow(17, brv7(i), Q) for i in range(128)], dtype=np.int64)

def ntt(a):
    r = np.array(a, dtype=np.int64) % Q
    k = 1
    ln = 128
    while ln >= 2:
        for start in range(0, 256, 2 * ln):
            zeta = int(ZETAS[k]); k += 1
            for j in range(start, start + ln):
                t = zeta * r[j + ln] % Q
                r[j + ln] = (r[j] - t) % Q
                r[j] = (r[j] + t) % Q
        ln //= 2
    return r

def invntt(a):
    r = np.array(a, dtype=np.int64) % Q
    k = 127
    ln = 2
    while ln <= 128:
        for start in range(0, 256, 2 * ln):
            zeta = int(ZETAS[k]); k -= 1
            for j in range(start, start + ln):
                t = r[j]
                r[j] = (t + r[j + ln]) % Q
                r[j + ln] = (r[j + ln] - t) * zeta % Q
        ln *= 2
    f = pow(128, -1, Q)
    return r * f % Q

def basemul_ntt(a, b):
    """multiply two polys in NTT domain (FIPS203 MultiplyNTTs), returns NTT-domain"""
    a = np.asarray(a, dtype=np.int64); b = np.asarray(b, dtype=np.int64)
    out = np.zeros(256, dtype=np.int64)
    for i in range(64):
        z = int(ZETAS[64 + i])
        # pair 2i, 2i+1  with zeta
        a0, a1 = a[4*i], a[4*i+1]; b0, b1 = b[4*i], b[4*i+1]
        out[4*i]   = (a0*b0 + a1*b1*z) % Q
        out[4*i+1] = (a0*b1 + a1*b0) % Q
        # pair 2i+2, 2i+3 with -zeta
        a0, a1 = a[4*i+2], a[4*i+3]; b0, b1 = b[4*i+2], b[4*i+3]
        zn = (-z) % Q
        out[4*i+2] = (a0*b0 + a1*b1*zn) % Q
        out[4*i+3] = (a0*b1 + a1*b0) % Q
    return out

def naive_negacyclic_mul(a, b):
    a = [int(x) % Q for x in a]; b = [int(x) % Q for x in b]
    res = [0]*256
    for i in range(256):
        if a[i] == 0: continue
        for j in range(256):
            t = i + j
            if t < 256: res[t] = (res[t] + a[i]*b[j]) % Q
            else: res[t-256] = (res[t-256] - a[i]*b[j]) % Q
    return res

def sample_ntt(rho, a, b):
    stream = hashlib.shake_128(bytes(rho) + bytes([a, b])).digest(4096)
    out = []
    i = 0
    while len(out) < 256 and i + 3 <= len(stream):
        b0, b1, b2 = stream[i], stream[i+1], stream[i+2]
        d1 = b0 + 256 * (b1 % 16)
        d2 = (b1 // 16) + 16 * b2
        if d1 < Q: out.append(d1)
        if d2 < Q and len(out) < 256: out.append(d2)
        i += 3
    assert len(out) == 256, len(out)
    return np.array(out, dtype=np.int64)

def encode12(p):
    p = [int(x) % Q for x in p]
    out = bytearray()
    for i in range(0, 256, 2):
        v = p[i] | (p[i+1] << 12)
        out += bytes([v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff])
    return bytes(out)

def decode12(b):
    out = []
    for i in range(0, 384, 3):
        v = b[i] | (b[i+1] << 8) | (b[i+2] << 16)
        out.append(v & 0xfff); out.append(v >> 12)
    return np.array(out, dtype=np.int64)

def center(x):
    x = int(x) % Q
    return x - Q if x > Q // 2 else x
