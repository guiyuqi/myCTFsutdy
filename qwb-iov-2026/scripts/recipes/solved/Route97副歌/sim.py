import struct, hashlib, math

WAV='work/extracted/radio/radio_channel.wav'
EXE='work/extracted/radio/route97_rhythm.exe'
TOKEN=b'AJ9U_N1ghtR0ute_97FM_S1gnal'

def mix32(c):
    c&=0xffffffff
    a=((c>>16)^c)&0xffffffff
    c=(a*0x7fe911ab)&0xffffffff
    a=((c>>15)^c)&0xffffffff
    a=(a*0x846b2e6b)&0xffffffff
    return ((a>>16)^a)&0xffffffff

def rol32(v,n):
    v&=0xffffffff
    n&=31
    return ((v<<n)|(v>>(32-n)))&0xffffffff
def rol8(v,n):
    v&=0xff; n&=7
    return ((v<<n)|(v>>(8-n)))&0xff

def xtea_dec_block(v0,v1,key):
    s=0xc6ef3720
    for _ in range(32):
        v1=(v1 - ((((v0<<4)&0xffffffff) ^ (v0>>5)) + v0 ^ (s + key[(s>>11)&3])))&0xffffffff
        s=(s+0x61c88647)&0xffffffff
        v0=(v0 - ((((v1<<4)&0xffffffff) ^ (v1>>5)) + v1 ^ (s + key[s&3])))&0xffffffff
    return v0,v1

def xtea_cbc_dec(data,keybytes,iv):
    key=list(struct.unpack('<4I',keybytes))
    prev=iv
    out=b''
    for i in range(0,len(data),8):
        c=data[i:i+8]
        ct=struct.unpack('<2I',c)
        p=xtea_dec_block(ct[0],ct[1],key)
        pb=struct.pack('<2I',*p)
        out+=bytes(a^b for a,b in zip(pb,prev))
        prev=c
    return out

def chunks(path):
    d=open(path,'rb').read()
    assert d[0:4]==b'RIFF' and d[8:12]==b'WAVE'
    off=12; ch={}
    while off+8<=len(d):
        name=d[off:off+4]; size=struct.unpack('>I',d[off+4:off+8])[0]
        body=d[off+8:off+8+size]
        if name in (b'data',b'fmt '):
            size=struct.unpack('<I',d[off+4:off+8])[0]
            body=d[off+8:off+8+size]
        ch[name]=(body,off,size)
        off+=8+((size+1)&~1)
    return d,ch

d,ch=chunks(WAV)
print({k:(len(v[0]),hex(v[1])) for k,v in ch.items()})
abox=ch[b'abox'][0]; ach1=ch[b'ach1'][0]; ach2=ch[b'ach2'][0]; ach3=ch[b'ach3'][0]; flgx=ch[b'flgx'][0]
print('lens',len(abox),len(ach1),len(ach2),len(ach3),len(flgx))
md5tok=hashlib.md5(TOKEN).digest()
sha_tok=hashlib.sha256(TOKEN).digest()
print('md5tok',md5tok.hex())
g0=bytes(b^0xA7 for b in ach1)
g1=xtea_cbc_dec(ach2[8:],b'AJ9U-R97AJ9U-R97',ach2[0:8])
g2=xtea_cbc_dec(ach3[8:],md5tok,ach3[0:8])
print('g0',g0.hex(),len(g0))
print('g1',g1.hex(),len(g1))
print('g2',g2.hex(),len(g2))
# DFT
dat=ch[b'data'][0]
samples=dat[0x5140:0x5140+4096]
dft=[]
for k in range(16):
    f=50+8*k
    re=0.0; im=0.0
    for i in range(4096):
        s=(samples[i]-128) if samples[i]<128 else (samples[i]-256+128) # placeholder
        s=samples[i]-128
        ph=2*math.pi*f*i/4096.0
        re+=s*math.cos(ph)
        im-=s*math.sin(ph)
    mag=math.sqrt(re*re+im*im)*(2**-8)
    dft.append(int(round(mag))&0xff)
print('dft',dft)
print('dft^md5', bytes(a^b for a,b in zip(dft,md5tok)).hex())
