import hashlib, struct
Q=3329; N=256; K=3
QINV=62209
def brv7(x):
    r=0
    for i in range(7):
        r=(r<<1)|((x>>i)&1)
    return r
ZETAS=[(pow(17,brv7(i),Q)*(1<<16))%Q for i in range(128)]
ZETAS_SIGNED=[z if z<Q//2 else z-Q for z in ZETAS]
def mont(a):
    t=(a*QINV)&0xFFFF
    return (a-t*Q)>>16
def fqmul(a,b): return mont(a*b)
def barrett(a):
    # standard reduce to [-q/2,q/2]-ish; here just mod
    return a%Q
R=(1<<16)%Q
F=((1<<32)%Q)
def poly_tomont(r):
    return [mont(x*F)%Q for x in r]
def ntt(r):
    r=[x%Q for x in r]; k=1; length=128
    while length>=2:
        start=0
        while start<256:
            zeta=ZETAS[k]; k+=1
            for j in range(start,start+length):
                t=mont(zeta*r[j+length])
                r[j+length]=(r[j]-t)%Q
                r[j]=(r[j]+t)%Q
            start+=2*length
        length//=2
    return r
def invntt(r):
    r=[x%Q for x in r]; k=127; length=2
    while length<=128:
        start=0
        while start<256:
            zeta=ZETAS[k]; k-=1
            for j in range(start,start+length):
                t=r[j]
                r[j]=(t+r[j+length])%Q
                r[j+length]=(r[j+length]-t)%Q
                r[j+length]=mont(zeta*r[j+length])%Q
            start+=2*length
        length*=2
    RES=1441
    return [mont(RES*x)%Q for x in r]
def basemul(a0,a1,b0,b1,zeta):
    r0=(fqmul(fqmul(a1,b1),zeta)+fqmul(a0,b0))
    r1=(fqmul(a0,b1)+fqmul(a1,b0))
    return r0%Q,r1%Q
def poly_basemul(a,b):
    r=[0]*256
    for i in range(64):
        r[4*i],r[4*i+1]=basemul(a[4*i],a[4*i+1],b[4*i],b[4*i+1],ZETAS[64+i])
        r[4*i+2],r[4*i+3]=basemul(a[4*i+2],a[4*i+3],b[4*i+2],b[4*i+3],-ZETAS[64+i]%Q)
    return r
def poly_add(a,b): return [(x+y)%Q for x,y in zip(a,b)]
def poly_sub(a,b): return [(x-y)%Q for x,y in zip(a,b)]
def shake128(data,outlen):
    return hashlib.shake_128(data).digest(outlen)
def sample_ntt(seed,outlen=2000):
    buf=shake128(seed,outlen)
    coeffs=[];i=0
    while len(coeffs)<256 and i+3<=len(buf):
        b0,b1,b2=buf[i],buf[i+1],buf[i+2]; i+=3
        d1=b0|((b1&0xF)<<8); d2=(b1>>4)|(b2<<4)
        if d1<Q: coeffs.append(d1)
        if d2<Q and len(coeffs)<256: coeffs.append(d2)
    assert len(coeffs)==256, ('short',len(coeffs))
    return coeffs
def gen_matrix(rho, transposed=False):
    A=[[None]*K for _ in range(K)]
    for i in range(K):
        for j in range(K):
            if transposed: seed=rho+bytes([i,j])
            else: seed=rho+bytes([j,i])
            A[i][j]=sample_ntt(seed)
    return A
def cbd2(bs):
    # eta=2, 64 bytes -> 256 coeffs
    assert len(bs)==64
    bits=[]
    for b in bs:
        for k in range(8): bits.append((b>>k)&1)
    coeffs=[]
    for i in range(256):
        a=sum(bits[4*i+k] for k in range(2))
        b=sum(bits[4*i+2+k] for k in range(2))
        coeffs.append((a-b)%Q)
    return coeffs
def prf(seed,n,eta_bytes=64):
    return shake128(seed+bytes([n]),eta_bytes)
def compress(x,d):
    return (((x<<d)+Q//2)//Q)%(1<<d)
def decompress(x,d):
    return ((x*Q)+(1<<(d-1)))>>d
def pack12(vals):
    out=bytearray()
    for i in range(0,len(vals),2):
        a=vals[i]%4096; b=vals[i+1]%4096
        out+=bytes([a&0xFF,((a>>8)&0xF)|((b&0xF)<<4),(b>>4)&0xFF])
    return bytes(out)
def pack10(vals):
    out=bytearray()
    for i in range(0,len(vals),4):
        v=[x%1024 for x in vals[i:i+4]]
        out+=bytes([v[0]&0xFF, ((v[0]>>8)&0x3)|((v[1]&0x3F)<<2), ((v[1]>>6)&0xF)|((v[2]&0xF)<<4), ((v[2]>>4)&0xFF), (((v[3]&0xF)<<4))|((v[3]>>8)&0xF)])
    # careful: standard packing: r[0]=t0>>0, r[1]=(t0>>8)|(t1<<2), ...
    return bytes(out)
def pack10_std(vals):
    out=bytearray()
    for i in range(0,len(vals),4):
        t=[x%1024 for x in vals[i:i+4]]
        out+=bytes([t[0]&0xFF,(t[0]>>8)|((t[1]&0x3F)<<2),(t[1]>>6)|((t[2]&0xF)<<4),(t[2]>>4),((t[3]&0xF)<<4)|(t[3]>>8)])
    return bytes(out)
def unpack10_std(b):
    vals=[]
    for i in range(0,len(b),5):
        c=b[i:i+5]
        t0=c[0]|((c[1]&0x3)<<8)
        t1=(c[1]>>2)|((c[2]&0xF)<<6)
        t2=(c[2]>>4)|((c[3]&0xF)<<4)
        t3=(c[3]>>4)|((c[4]&0xF)<<4)
        vals+= [t0,t1,t2,t3]
    return vals
def unpack12_std(b):
    vals=[]
    for i in range(0,len(b),3):
        c=b[i:i+3]
        vals.append(c[0]|((c[1]&0xF)<<8))
        vals.append((c[1]>>4)|(c[2]<<4))
    return vals
def pack4_std(vals):
    out=bytearray()
    for i in range(0,len(vals),2):
        out+=bytes([(vals[i]%16)|((vals[i+1]%16)<<4)])
    return bytes(out)
def unpack4_std(b):
    vals=[]
    for x in b:
        vals.append(x&0xF); vals.append(x>>4)
    return vals
